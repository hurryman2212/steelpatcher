from __future__ import annotations

import hashlib, json, struct, subprocess, tempfile, zlib

from pathlib import Path
from typing import Any

from steelpatcher.elf import read_defined_symbols
from steelpatcher.firmware import FirmwareInformation, append_crc32_residue
from steelpatcher.firmware import decode_thumb_b16, decode_thumb_bl, encode_thumb_bw
from steelpatcher.firmware import parse_hex_bytes, replace_bytes, validate_firmware
from steelpatcher.matcher import find_matches, parse_pattern
from steelpatcher.matcher import resolve_pattern
from steelpatcher.profile import ModelProfile, integer, load_patch_manifest

_STEELPATCH_MAGIC = bytes.fromhex("89535046570D0A1A0A7D1991DE015ABC")
_STEELPATCH_FOOTER = struct.Struct("<16sIIQQ32s32s24s")


def _wrap_binary(payload: bytes, metadata: dict[str, Any]) -> bytes:
    metadata_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    payload_digest = hashlib.sha256(payload).digest()
    metadata_digest = hashlib.sha256(metadata_bytes).digest()
    footer = _STEELPATCH_FOOTER.pack(
        _STEELPATCH_MAGIC,
        1,
        _STEELPATCH_FOOTER.size,
        len(payload),
        len(metadata_bytes),
        payload_digest,
        metadata_digest,
        bytes(24),
    )
    return payload + metadata_bytes + footer


def _build_artifacts(
    profile: ModelProfile,
    manifest: dict[str, Any],
    layouts: dict[str, dict[str, dict[str, Any]]],
    definitions: dict[str, int],
    build_directory: Path,
) -> tuple[dict[str, dict[str, int]], dict[str, bytes]]:
    toolchain = profile.project_root / "cmake" / "arm-none-eabi-gcc.cmake"
    configuration = [
        "cmake",
        "-S",
        str(profile.patch_directory),
        "-B",
        str(build_directory),
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DSTEELPATCH_DEFINITIONS="
        + ";".join(f"{name}={value}" for name, value in definitions.items()),
    ]
    for name, specification in manifest["artifacts"].items():
        link = specification["link"]
        try:
            region = layouts[name][link]
        except KeyError as error:
            raise ValueError(
                f"artifact {name} cannot link from missing {link!r} placement"
            ) from error
        if "resolved_address" in region:
            origin = region["resolved_address"]
        elif "address" in region:
            origin = integer(region["address"])
        else:
            raise ValueError(f"artifact {name} link placement is not addressable")
        length = integer(region["size"])
        if specification["packaging"] == "crc32-residue":
            if length <= 4:
                raise ValueError(f"artifact {name} link placement is too small")
            length -= 4
        prefix = "STEELPATCH_" + name.upper().replace("-", "_")
        configuration.extend(
            [f"-D{prefix}_ORIGIN={origin}", f"-D{prefix}_LENGTH={length}"]
        )
    subprocess.run(
        configuration,
        check=True,
    )
    subprocess.run(["cmake", "--build", str(build_directory), "--parallel"], check=True)
    paths = {
        name: (build_directory / f"{name}.elf", build_directory / f"{name}.bin")
        for name in manifest["artifacts"]
    }
    if not all(path.is_file() for pair in paths.values() for path in pair):
        raise ValueError("patch module build completed without expected artifacts")
    return (
        {name: read_defined_symbols(pair[0]) for name, pair in paths.items()},
        {name: pair[1].read_bytes() for name, pair in paths.items()},
    )


def _resolve_address(
    image: bytes,
    mcu_image_start: int,
    name: str,
    specification: dict[str, Any],
    resolved_bindings: dict[str, int] | None = None,
) -> int:
    pattern = parse_pattern(specification["pattern"])
    matches = find_matches(image, pattern)
    expected_count = integer(specification.get("count", 1))
    if expected_count < 1:
        raise ValueError(f"pattern for {name} has an invalid match count")
    if len(matches) != expected_count:
        raise ValueError(
            f"pattern for {name} expected {expected_count} match(es), "
            f"found {len(matches)}"
        )
    selector = specification.get("select_call")
    if selector is None:
        if len(matches) != 1:
            raise ValueError(f"pattern for {name} is ambiguous without a call selector")
        address = mcu_image_start + matches[0]
    else:
        binding = selector["target"]
        if resolved_bindings is None or binding not in resolved_bindings:
            raise ValueError(f"interface {name} requires unresolved binding {binding}")
        expected_target = resolved_bindings[binding] & ~1
        selected = []
        for match in matches:
            candidate = mcu_image_start + match
            call_address = candidate + integer(selector["offset"])
            call_offset = call_address - mcu_image_start
            if call_offset < 0 or call_offset + 4 > len(image):
                continue
            try:
                target = decode_thumb_bl(
                    call_address, image[call_offset : call_offset + 4]
                )
            except ValueError:
                continue
            if target == expected_target:
                selected.append(candidate)
        if len(selected) != 1:
            raise ValueError(
                f"interface {name} expected one call to {selector['target']}, "
                f"found {len(selected)}"
            )
        address = selected[0]

    return address


def _resolve_code_region(
    image: bytes, mcu_image_start: int, specification: dict[str, Any]
) -> int:
    size = integer(specification["size"])
    empty = bytes.fromhex(specification["empty"])
    if not empty or size % len(empty):
        raise ValueError("code-region empty pattern is inconsistent with its size")
    expected = empty * (size // len(empty))
    locate = specification["locate"]
    anchor = locate["anchor"]
    candidate = (
        mcu_image_start + resolve_pattern(image, anchor) + integer(anchor["offset"])
    )
    start_address = integer(locate["search"]["start"])
    end_address = integer(locate["search"]["end"])
    candidate_offset = candidate - mcu_image_start
    if (
        candidate % 4
        or candidate < start_address
        or candidate + size > end_address
        or candidate_offset < 0
        or candidate_offset + size > len(image)
        or image[candidate_offset : candidate_offset + size] != expected
    ):
        raise ValueError("code-area anchor did not resolve to an aligned, empty region")
    return candidate


def _region_value(region: dict[str, Any], field: str) -> int:
    if field == "end":
        start_field = "address" if "address" in region else "offset"
        return integer(region[start_field]) + integer(region["size"])
    if field not in {"address", "offset", "size"} or field not in region:
        raise ValueError(f"memory region does not define field {field!r}")
    return integer(region[field])


def _resolve_build_definitions(profile: ModelProfile) -> dict[str, int]:
    definitions = {}
    for name, specification in profile.target["build_definitions"].items():
        if isinstance(specification, (int, str)):
            definitions[name] = integer(specification)
            continue
        if not isinstance(specification, dict):
            raise ValueError(f"build definition {name} is invalid")
        region = profile.memory_region(specification["memory"], specification["region"])
        definitions[name] = _region_value(region, specification["field"]) + integer(
            specification.get("addend", 0)
        )
    return definitions


def _validate_memory_map(profile: ModelProfile) -> None:
    firmware = profile.data["firmware"]
    image_start = integer(firmware["mcu_image_start"])
    image_end = image_start + integer(firmware["image_size"])
    ranges: dict[str, list[tuple[int, int, str]]] = {
        "firmware": [],
        "external": [],
        "ram": [],
    }
    for name, region in profile.data["memory"]["flash"].items():
        space = region.get("space")
        if space == "firmware":
            start = _region_value(region, "address")
            if start < image_start or start + integer(region["size"]) > image_end:
                raise ValueError(f"flash region {name} is outside the firmware image")
        elif space == "external":
            start = _region_value(region, "offset")
        else:
            raise ValueError(f"flash region {name} has unsupported space {space!r}")
        size = integer(region["size"])
        if size <= 0:
            raise ValueError(f"flash region {name} has an invalid size")
        ranges[space].append((start, start + size, name))
    for name, region in profile.data["memory"]["ram"].items():
        start = _region_value(region, "address")
        size = integer(region["size"])
        if size <= 0:
            raise ValueError(f"RAM region {name} has an invalid size")
        ranges["ram"].append((start, start + size, name))
    for space, regions in ranges.items():
        regions.sort()
        for previous, current in zip(regions, regions[1:]):
            if previous[1] > current[0]:
                raise ValueError(
                    f"{space} regions {previous[2]} and {current[2]} overlap"
                )


def _resolve_artifact_layouts(
    image: bytes, mcu_image_start: int, profile: ModelProfile
) -> dict[str, dict[str, dict[str, Any]]]:
    _validate_memory_map(profile)
    layouts = {}
    used_storage = set()
    used_runtime = set()
    for name, placement in profile.target["artifacts"].items():
        if not isinstance(placement, dict) or "storage" not in placement:
            raise ValueError(f"artifact {name} has no storage placement")
        storage_name = placement["storage"]
        if storage_name in used_storage:
            raise ValueError(f"flash region {storage_name} is assigned more than once")
        used_storage.add(storage_name)
        storage = dict(profile.memory_region("flash", storage_name))
        if storage["space"] == "firmware":
            storage["resolved_address"] = _resolve_code_region(
                image, mcu_image_start, storage
            )
            if "deployment" in placement:
                raise ValueError(f"firmware artifact {name} has unused deployment data")
        elif not isinstance(placement.get("deployment"), dict):
            raise ValueError(
                f"separate artifact {name} has no deployment specification"
            )
        layout = {"storage": storage}
        runtime_name = placement.get("runtime")
        if runtime_name is not None:
            if runtime_name in used_runtime:
                raise ValueError(
                    f"RAM region {runtime_name} is assigned more than once"
                )
            used_runtime.add(runtime_name)
            layout["runtime"] = dict(profile.memory_region("ram", runtime_name))
        layouts[name] = layout
    resolved_firmware_ranges = sorted(
        (
            layout["storage"]["resolved_address"],
            layout["storage"]["resolved_address"] + integer(layout["storage"]["size"]),
            name,
        )
        for name, layout in layouts.items()
        if layout["storage"]["space"] == "firmware"
    )
    for previous, current in zip(
        resolved_firmware_ranges, resolved_firmware_ranges[1:]
    ):
        if previous[1] > current[0]:
            raise ValueError(
                f"resolved firmware regions {previous[2]} and {current[2]} overlap"
            )
    for name, resource in profile.target["resources"].items():
        if not isinstance(resource, dict):
            raise ValueError(f"resource {name} must be an object")
        storage_name = resource.get("storage")
        if storage_name is not None:
            profile.memory_region("flash", storage_name)
            if storage_name in used_storage:
                raise ValueError(
                    f"flash region {storage_name} is assigned more than once"
                )
            used_storage.add(storage_name)
        runtime_name = resource.get("runtime")
        if runtime_name is not None:
            profile.memory_region("ram", runtime_name)
            if runtime_name in used_runtime:
                raise ValueError(
                    f"RAM region {runtime_name} is assigned more than once"
                )
            used_runtime.add(runtime_name)
    return layouts


def _exact_prefix(specification: dict[str, Any], size: int = 4) -> bytes:
    pattern = parse_pattern(specification["pattern"])
    if pattern.size < size or pattern.masks[:size] != bytes([0xFF]) * size:
        raise ValueError("replacement pattern does not have an exact prefix")
    return pattern.values[:size]


def _resolve_bindings(
    image: bytes,
    mcu_image_start: int,
    profile: ModelProfile,
    hooks: dict[str, int],
    patch_symbols: dict[str, dict[str, int]],
    resolved: dict[str, int] | None = None,
) -> dict[str, int]:
    resolved = dict(resolved or {})
    for name, specification in profile.target["bindings"].items():
        if name in resolved:
            continue
        kind = specification["kind"]
        if kind == "signature":
            value = _resolve_address(
                image,
                mcu_image_start,
                name,
                specification,
            )
        elif kind == "hook_next":
            value = hooks[specification["hook"]] + integer(
                specification.get("addend", 4)
            )
        elif kind == "branch_target":
            instruction_address = hooks[specification["hook"]] + integer(
                specification["offset"]
            )
            instruction_offset = instruction_address - mcu_image_start
            if instruction_offset < 0 or instruction_offset + 2 > len(image):
                raise ValueError(f"binding {name} branch is outside the firmware")
            value = decode_thumb_b16(
                instruction_address,
                image[instruction_offset : instruction_offset + 2],
            )
        elif kind == "patch_symbol":
            artifact = specification["artifact"]
            symbol = specification["symbol"]
            try:
                value = patch_symbols[artifact][symbol]
            except KeyError as error:
                raise ValueError(
                    f"binding {name} refers to missing patch symbol "
                    f"{artifact}.{symbol}"
                ) from error
        else:
            raise ValueError(f"binding {name} has unsupported kind {kind!r}")
        expected_text = specification.get("expected")
        if expected_text is not None:
            expected = parse_hex_bytes(expected_text)
            target_offset = (value & ~1) - mcu_image_start
            if (
                target_offset < 0
                or target_offset + len(expected) > len(image)
                or image[target_offset : target_offset + len(expected)] != expected
            ):
                raise ValueError(
                    f"binding {name} target does not have its expected code shape"
                )
        if specification.get("thumb", False):
            value |= 1
        resolved[name] = value
    return resolved


def _resolve_pattern_bindings(
    image: bytes,
    mcu_image_start: int,
    profile: ModelProfile,
) -> dict[str, int]:
    resolved = {}
    specifications = {
        name: specification
        for name, specification in profile.target["bindings"].items()
        if specification["kind"] == "signature"
    }
    pending = dict(specifications)
    while pending:
        progress = False
        for name, specification in list(pending.items()):
            selector = specification.get("select_call")
            if selector is not None and selector.get("target") not in resolved:
                continue
            value = _resolve_address(
                image, mcu_image_start, name, specification, resolved
            )
            if specification.get("thumb", False):
                value |= 1
            resolved[name] = value
            del pending[name]
            progress = True
        if not progress:
            dependencies = ", ".join(sorted(pending))
            raise ValueError(
                f"signature bindings have unresolved dependencies: {dependencies}"
            )
    return resolved


def _verify_checks(
    image: bytes,
    information: FirmwareInformation,
    mcu_image_start: int,
    profile: ModelProfile,
) -> dict[str, int]:
    specification = profile.target["checks"]
    expected_stack_pointer = integer(profile.data["firmware"]["initial_sp"])
    if information.initial_stack_pointer != expected_stack_pointer:
        raise ValueError(
            "firmware RAM layout is incompatible: initial stack pointer "
            f"0x{information.initial_stack_pointer:08X} differs from "
            f"0x{expected_stack_pointer:08X}"
        )
    resolved = {}
    for name, pattern in specification["patterns"].items():
        resolved[name] = mcu_image_start + resolve_pattern(image, pattern)
    return resolved


def _apply_bindings(
    raw_images: dict[str, bytes],
    bindings: dict[str, int],
    manifest: dict[str, Any],
) -> dict[str, bytes]:
    rebound = dict(raw_images)
    for binding, specification in manifest["bindings"].items():
        if binding not in bindings:
            raise ValueError(f"binding refers to unresolved value {binding}")
        placeholder = struct.pack("<I", integer(specification["placeholder"]))
        replacement = struct.pack("<I", bindings[binding])
        for artifact, expected_count in specification["targets"].items():
            if artifact not in rebound:
                raise ValueError(f"binding refers to missing artifact {artifact}")
            count = rebound[artifact].count(placeholder)
            if count != integer(expected_count):
                raise ValueError(
                    f"{artifact} binding {binding} expected {expected_count} "
                    f"placeholder(s), found {count}"
                )
            rebound[artifact] = rebound[artifact].replace(placeholder, replacement)
    return rebound


def _package_artifact(
    name: str,
    raw: bytes,
    symbols: dict[str, int],
    specification: dict[str, Any],
    layout: dict[str, dict[str, Any]],
    definitions: dict[str, int],
) -> bytes:
    link = layout[specification["link"]]
    origin = integer(link.get("resolved_address", link.get("address")))
    required_symbol = specification["required_symbol"]
    if not raw or not origin <= symbols.get(required_symbol, 0) < origin + len(raw):
        raise ValueError(f"artifact {name} required symbol is outside its image")
    for offset_text, check in specification.get("word_checks", {}).items():
        offset = integer(offset_text)
        if not isinstance(check, dict) or offset < 0 or offset + 4 > len(raw):
            raise ValueError(f"artifact {name} has an invalid word check")
        sources = set(check) & {"value", "definition", "symbol"}
        if len(sources) != 1:
            raise ValueError(f"artifact {name} word check must have one source")
        source = next(iter(sources))
        if source == "value":
            expected = integer(check["value"])
        elif source == "definition":
            try:
                expected = definitions[check["definition"]]
            except KeyError as error:
                raise ValueError(
                    f"artifact {name} uses an unknown build definition"
                ) from error
        else:
            try:
                expected = symbols[check["symbol"]]
            except KeyError as error:
                raise ValueError(f"artifact {name} uses an unknown symbol") from error
            if check.get("thumb", False):
                expected |= 1
            if not origin <= (expected & ~1) < origin + len(raw):
                raise ValueError(
                    f"artifact {name} word check symbol is outside its image"
                )
        if not 0 <= expected <= 0xFFFFFFFF:
            raise ValueError(f"artifact {name} word check value is out of range")
        if struct.unpack_from("<I", raw, offset)[0] != expected:
            raise ValueError(f"artifact {name} word check failed at {offset_text}")

    packaging = specification["packaging"]
    if packaging == "raw":
        if len(raw) > integer(layout["storage"]["size"]):
            raise ValueError(f"artifact {name} does not fit its storage region")
        return raw
    if packaging != "crc32-residue":
        raise ValueError(f"artifact {name} has unsupported packaging {packaging!r}")
    storage_size = integer(layout["storage"]["size"])
    load_size = integer(link["size"])
    if load_size < 4 or storage_size < load_size or len(raw) > load_size - 4:
        raise ValueError(f"artifact {name} does not fit its load and storage regions")
    padded = raw + bytes([0xFF]) * (load_size - 4 - len(raw))
    image = append_crc32_residue(padded)
    return image + bytes([0xFF]) * (storage_size - len(image))


def _resolve_preflight(
    profile: ModelProfile,
    specification: dict[str, Any],
    artifacts: dict[str, bytes],
    layouts: dict[str, dict[str, dict[str, Any]]],
) -> tuple[dict[str, Any], set[str]]:
    if not isinstance(specification, dict) or not isinstance(
        specification.get("states"), list
    ):
        raise ValueError("external deployment preflight is invalid")
    object_id = integer(specification.get("object_id", -1))
    if not 0 <= object_id <= 0xFFFF:
        raise ValueError("external deployment preflight object ID is invalid")
    states = []
    covered_regions = set()
    state_names = set()
    for state in specification["states"]:
        if not isinstance(state, dict) or not isinstance(state.get("name"), str):
            raise ValueError("external preflight state has no name")
        name = state["name"]
        regions = state.get("regions")
        if (
            not name
            or name in state_names
            or not isinstance(regions, dict)
            or not regions
        ):
            raise ValueError("external preflight state is invalid")
        state_names.add(name)
        resolved_regions = []
        for region_name, condition in regions.items():
            region = profile.memory_region("flash", region_name)
            if region.get("space") != "external" or not isinstance(condition, dict):
                raise ValueError(
                    f"preflight region {region_name!r} is not external Flash"
                )
            matchers = set(condition) & {"fill", "artifact", "sha256"}
            if len(matchers) != 1 or set(condition) - matchers:
                raise ValueError(
                    f"preflight region {region_name!r} needs exactly one matcher"
                )
            resolved = {
                "offset": f"0x{integer(region['offset']):08X}",
                "size": integer(region["size"]),
            }
            matcher = next(iter(matchers))
            if matcher == "fill":
                fills = condition["fill"]
                if not isinstance(fills, list) or not fills:
                    raise ValueError(
                        f"preflight region {region_name!r} has no allowed fill"
                    )
                parsed_fills = [integer(fill) for fill in fills]
                if len(set(parsed_fills)) != len(parsed_fills) or any(
                    not 0 <= fill <= 0xFF for fill in parsed_fills
                ):
                    raise ValueError(
                        f"preflight region {region_name!r} has an invalid fill"
                    )
                resolved["fill"] = [f"0x{fill:02X}" for fill in parsed_fills]
            elif matcher == "artifact":
                artifact = condition["artifact"]
                if artifact not in artifacts:
                    raise ValueError(
                        f"preflight region {region_name!r} uses an unknown artifact"
                    )
                if layouts[artifact]["storage"] != region:
                    raise ValueError(
                        f"preflight artifact {artifact!r} is not stored in "
                        f"region {region_name!r}"
                    )
                if len(artifacts[artifact]) != integer(region["size"]):
                    raise ValueError(
                        f"preflight artifact {artifact!r} does not fill its region"
                    )
                resolved["sha256"] = [hashlib.sha256(artifacts[artifact]).hexdigest()]
            else:
                hashes = condition["sha256"]
                if (
                    not isinstance(hashes, list)
                    or not hashes
                    or len(set(hashes)) != len(hashes)
                    or any(
                        not isinstance(value, str)
                        or len(value) != 64
                        or any(
                            character not in "0123456789abcdef" for character in value
                        )
                        for value in hashes
                    )
                ):
                    raise ValueError(
                        f"preflight region {region_name!r} has an invalid SHA-256"
                    )
                resolved["sha256"] = hashes
            resolved_regions.append(resolved)
            covered_regions.add(region_name)
        states.append({"name": name, "regions": resolved_regions})
    if not states:
        raise ValueError("external deployment preflight has no states")
    return {
        "object_id": f"0x{object_id:04X}",
        "states": states,
    }, covered_regions


def patch_firmware(
    firmware_path: Path,
    profile: ModelProfile,
    output_path: Path | None = None,
    force: bool = False,
    no_hash_check: bool = False,
) -> dict[str, Path]:
    manifest = load_patch_manifest(profile)
    firmware_configuration = profile.data["firmware"]
    mcu_image_start = integer(firmware_configuration["mcu_image_start"])
    image_size = integer(firmware_configuration["image_size"])
    expected_residue = integer(firmware_configuration["crc32_residue"])
    original = firmware_path.read_bytes()
    information = validate_firmware(
        original, mcu_image_start, image_size, expected_residue
    )
    checks = _verify_checks(original, information, mcu_image_start, profile)
    known_version = next(
        (
            version
            for version, specification in firmware_configuration["versions"].items()
            if specification["sha256"].lower() == information.sha256
        ),
        None,
    )
    if known_version is None and not no_hash_check:
        raise ValueError(
            "firmware hash is not approved by this model profile; use "
            "--no-hash-check to rely on structural matching"
        )
    resolved_bindings = _resolve_pattern_bindings(original, mcu_image_start, profile)
    resolved_hooks: dict[str, int] = {}
    for name, specification in profile.target["hooks"].items():
        resolved_hooks[name] = _resolve_address(
            original,
            mcu_image_start,
            name,
            specification,
            resolved_bindings,
        )

    bss_specification = profile.target["bss_end"]
    bss_address = _resolve_address(
        original,
        mcu_image_start,
        "bss_end",
        bss_specification,
    )

    layouts = _resolve_artifact_layouts(original, mcu_image_start, profile)
    definitions = _resolve_build_definitions(profile)
    patch_name = profile.patch_directory.name
    with tempfile.TemporaryDirectory(prefix=f"{patch_name}-") as temporary_directory:
        patch_symbols, raw_images = _build_artifacts(
            profile, manifest, layouts, definitions, Path(temporary_directory)
        )
    resolved_bindings = _resolve_bindings(
        original,
        mcu_image_start,
        profile,
        resolved_hooks,
        patch_symbols,
        resolved_bindings,
    )
    raw_images = _apply_bindings(raw_images, resolved_bindings, manifest)
    artifacts = {
        name: _package_artifact(
            name,
            raw_images[name],
            patch_symbols[name],
            specification,
            layouts[name],
            definitions,
        )
        for name, specification in manifest["artifacts"].items()
    }

    image = bytearray(original)
    code_regions = {}
    for name, artifact in artifacts.items():
        region = layouts[name]["storage"]
        if region["space"] != "firmware":
            continue
        address = region["resolved_address"]
        code_regions[name] = address
        size = integer(region["size"])
        offset = address - mcu_image_start
        if len(artifact) > size:
            raise ValueError(f"{name} image does not fit its reviewed code area")
        empty = bytes.fromhex(region["empty"])
        expected_fill = empty * (size // len(empty))
        if bytes(image[offset : offset + size]) != expected_fill:
            raise ValueError(f"{name} code area is not in its expected state")
        image[offset : offset + len(artifact)] = artifact

    for name, specification in profile.target["hooks"].items():
        address = resolved_hooks[name]
        artifact = specification["artifact"]
        target = specification["target"]
        if target not in patch_symbols.get(artifact, {}):
            raise ValueError(f"artifact {artifact} is missing symbol {target}")
        replace_bytes(
            image,
            address - mcu_image_start,
            _exact_prefix(specification),
            encode_thumb_bw(address, patch_symbols[artifact][target] & ~1),
        )

    resource = profile.target["resources"][bss_specification["resource"]]
    state = profile.memory_region("ram", resource["runtime"])
    state_end = _region_value(state, "end")
    replace_bytes(
        image,
        bss_address - mcu_image_start,
        _exact_prefix(bss_specification),
        struct.pack("<I", state_end),
    )
    image[-4:] = struct.pack("<I", (~zlib.crc32(image[:-4])) & 0xFFFFFFFF)
    patched_information = validate_firmware(
        bytes(image), mcu_image_start, image_size, expected_residue
    )

    if output_path is None:
        main_output = Path(f"{firmware_path.stem}.patched.bin")
    else:
        main_output = output_path
    separate_outputs = {
        name: main_output.with_name(f"{main_output.stem}.{name}.bin")
        for name in artifacts
        if layouts[name]["storage"]["space"] != "firmware"
    }
    report_stem = main_output.stem.removesuffix(".patched")
    report_output = main_output.with_name(f"{report_stem}.patch.json")
    outputs = {"firmware": main_output, **separate_outputs, "json": report_output}
    if not force and any(path.exists() for path in outputs.values()):
        raise FileExistsError(
            "an output file already exists; use --force to replace it"
        )
    post_update = []
    preflight_regions = set()
    for name, path in separate_outputs.items():
        deployment = dict(profile.target["artifacts"][name]["deployment"])
        preflight_specification = deployment.pop("preflight", None)
        entry = {
            "artifact": name,
            "file": path.name,
            "sha256": hashlib.sha256(artifacts[name]).hexdigest(),
            **deployment,
        }
        if preflight_specification is not None:
            entry["preflight"], covered = _resolve_preflight(
                profile, preflight_specification, artifacts, layouts
            )
            preflight_regions.update(covered)
        post_update.append(entry)
    claimed_external_regions = {
        placement["storage"]
        for placement in (
            *profile.target["artifacts"].values(),
            *profile.target["resources"].values(),
        )
        if "storage" in placement
        and profile.memory_region("flash", placement["storage"])["space"] == "external"
    }
    missing_preflight = claimed_external_regions - preflight_regions
    if missing_preflight:
        raise ValueError(
            "external Flash regions lack destructive-write preflight: "
            + ", ".join(sorted(missing_preflight))
        )

    payloads = {"firmware": bytes(image)}
    payloads.update({name: artifacts[name] for name in separate_outputs})
    bundle_description = {
        "schema_version": 1,
        "model": profile.data["model"],
        "patches": [patch_name],
        "source_sha256": information.sha256,
        "firmware": {
            "file": main_output.name,
            "sha256": patched_information.sha256,
        },
        "post_update": post_update,
    }
    bundle_id = hashlib.sha256(
        json.dumps(bundle_description, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    paths = {"firmware": main_output, **separate_outputs}
    for name, payload in payloads.items():
        metadata = {
            "schema_version": 1,
            "format": "steelpatcher-bin",
            "artifact": name,
            "bundle_id": bundle_id,
            "model": profile.data["model"],
            "patches": [patch_name],
            "source_sha256": information.sha256,
            "payload_size": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        paths[name].write_bytes(_wrap_binary(payload, metadata))

    report = {
        "schema_version": 1,
        "bundle_id": bundle_id,
        "model": profile.data["model"],
        "patches": [patch_name],
        "source": firmware_path.name,
        "source_sha256": information.sha256,
        "known_source_version": known_version,
        "hash_check_bypassed": known_version is None and no_hash_check,
        "compatibility": {
            "decision": "compatible",
            "checks": {name: f"0x{address:08X}" for name, address in checks.items()},
        },
        "firmware": main_output.name,
        "firmware_sha256": patched_information.sha256,
        "post_update": post_update,
        "code_regions": {
            name: f"0x{address:08X}" for name, address in code_regions.items()
        },
        "hooks": {name: f"0x{address:08X}" for name, address in resolved_hooks.items()},
        "bindings": {
            name: f"0x{address:08X}" for name, address in resolved_bindings.items()
        },
        "bss_end_location": f"0x{bss_address:08X}",
    }
    report_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return outputs
