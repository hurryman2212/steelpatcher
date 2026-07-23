from __future__ import annotations

import copy, fnmatch, hashlib, json, re, struct

from pathlib import Path
from typing import Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AsarArchive:
    def __init__(self, data: bytes) -> None:
        if len(data) < 16:
            raise ValueError("truncated ASAR header")
        word_size, header_size, pickle_size, json_size = struct.unpack_from(
            "<IIII", data
        )
        if word_size != 4 or pickle_size + 4 != header_size or pickle_size % 4 != 0:
            raise ValueError("unsupported ASAR header layout")
        if (
            pickle_size < 4
            or json_size > pickle_size - 4
            or pickle_size - 4 - json_size > 3
            or 8 + header_size > len(data)
        ):
            raise ValueError("invalid ASAR header sizes")
        self.header = json.loads(data[16 : 16 + json_size].decode("utf-8"))
        self.payload = data[8 + header_size :]

    def _metadata(self, archive_path: str) -> dict[str, Any]:
        metadata = self.header
        for component in Path(archive_path).parts:
            metadata = metadata["files"][component]
        if "size" not in metadata or metadata.get("unpacked", False):
            raise ValueError(f"{archive_path} is not a packed ASAR file")
        return metadata

    def content(self, archive_path: str) -> bytes:
        metadata = self._metadata(archive_path)
        start = int(metadata["offset"])
        size = int(metadata["size"])
        if (
            start < 0
            or size < 0
            or start > len(self.payload)
            or size > len(self.payload) - start
        ):
            raise ValueError(f"{archive_path} has an invalid ASAR range")
        content = self.payload[start : start + size]
        return content

    def paths(self) -> list[str]:
        paths = []
        pending = [("", self.header["files"])]
        while pending:
            prefix, children = pending.pop()
            for name, metadata in children.items():
                path = f"{prefix}/{name}" if prefix else name
                if "files" in metadata:
                    pending.append((path, metadata["files"]))
                elif "size" in metadata and not metadata.get("unpacked", False):
                    paths.append(path)
        return paths

    def replace(self, replacements: dict[str, bytes]) -> bytes:
        header = copy.deepcopy(self.header)
        payload = self.payload
        targets = []
        for archive_path, replacement in replacements.items():
            metadata = header
            for component in Path(archive_path).parts:
                metadata = metadata["files"][component]
            targets.append((metadata, replacement))
        for metadata, replacement in sorted(
            targets, key=lambda item: int(item[0]["offset"]), reverse=True
        ):
            offset = int(metadata["offset"])
            old_size = int(metadata["size"])
            delta = len(replacement) - old_size
            metadata["size"] = len(replacement)
            _adjust_offsets(header["files"], offset, delta)
            payload = payload[:offset] + replacement + payload[offset + old_size :]
        return _serialize(header, payload)


def _adjust_offsets(
    children: dict[str, dict[str, Any]], target_offset: int, delta: int
) -> None:
    for metadata in children.values():
        if "files" in metadata:
            _adjust_offsets(metadata["files"], target_offset, delta)
        elif "size" in metadata and not metadata.get("unpacked", False):
            offset = int(metadata["offset"])
            if offset > target_offset:
                metadata["offset"] = str(offset + delta)


def _serialize(header: dict[str, Any], payload: bytes) -> bytes:
    encoded = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    pickle_size = (4 + len(encoded) + 3) & ~3
    header_size = 4 + pickle_size
    padding = bytes(pickle_size - 4 - len(encoded))
    return (
        struct.pack("<IIII", 4, header_size, pickle_size, len(encoded))
        + encoded
        + padding
        + payload
    )


def _webpack_module_id(source: str, anchor: str) -> str:
    positions = [match.start() for match in re.finditer(re.escape(anchor), source)]
    if len(positions) != 1:
        raise ValueError(
            f"Webpack module anchor expected one match, found {len(positions)}"
        )
    factories = list(
        re.finditer(
            r"(?:^|[},])([0-9]+):\("
            r"[A-Za-z_$][A-Za-z0-9_$]*,"
            r"[A-Za-z_$][A-Za-z0-9_$]*,"
            r"[A-Za-z_$][A-Za-z0-9_$]*\)=>\{",
            source[: positions[0]],
        )
    )
    if not factories:
        raise ValueError("Webpack module anchor is not inside a module factory")
    return factories[-1].group(1)


def _bindings(source: str, specification: dict[str, Any]) -> dict[str, str]:
    resolved = {}
    for name, binding in specification.get("bindings", {}).items():
        if binding["type"] != "webpack_module_id":
            raise ValueError(f"unsupported ASAR binding type: {binding['type']}")
        resolved[name] = _webpack_module_id(source, binding["anchor"])
    return resolved


def _expand(value: str, bindings: dict[str, str]) -> str:
    for name, resolved in bindings.items():
        value = value.replace(f"{{{{{name}}}}}", resolved)
    if re.search(r"\{\{[A-Za-z_][A-Za-z0-9_]*\}\}", value):
        raise ValueError("ASAR replacement contains an unresolved binding")
    return value


def _transform_source(source: str, specification: dict[str, Any], reverse: bool) -> str:
    bindings = _bindings(source, specification)
    replacements = specification["replacements"]
    if reverse:
        replacements = reversed(replacements)
    for replacement in replacements:
        before = _expand(
            replacement["replace"] if reverse else replacement["find"], bindings
        )
        after = _expand(
            replacement["find"] if reverse else replacement["replace"], bindings
        )
        count = source.count(before)
        if count != 1:
            raise ValueError(f"ASAR replacement expected one match, found {count}")
        source = source.replace(before, after, 1)
    return source


def _source_state(source: str, specification: dict[str, Any]) -> str:
    states = []
    for reverse, state in ((False, "original"), (True, "patched")):
        try:
            _transform_source(source, specification, reverse)
        except ValueError:
            continue
        states.append(state)
    if len(states) != 1:
        raise ValueError("ASAR source has an unsupported or ambiguous patch state")
    return states[0]


def _target_state(
    archive: AsarArchive,
    selector: str,
    specification: dict[str, Any],
    structural: bool,
) -> tuple[str, str]:
    matches = []
    for archive_path in archive.paths():
        if not fnmatch.fnmatchcase(archive_path, selector):
            continue
        content = archive.content(archive_path)
        if structural:
            try:
                state = _source_state(content.decode("utf-8"), specification)
            except (UnicodeDecodeError, ValueError):
                continue
        else:
            digest = sha256(content)
            if digest == specification["original_sha256"]:
                state = "original"
            elif digest == specification["patched_sha256"]:
                state = "patched"
            else:
                continue
        matches.append((archive_path, state))
    if len(matches) != 1:
        raise ValueError(
            f"ASAR selector {selector!r} expected one patch target, "
            f"found {len(matches)}"
        )
    return matches[0]


def asar_state(
    data: bytes, specification: dict[str, Any], structural: bool = False
) -> str:
    archive = AsarArchive(data)
    state = None
    targets = set()
    for selector, file_specification in specification["files"].items():
        archive_path, current = _target_state(
            archive, selector, file_specification, structural
        )
        if archive_path in targets:
            raise ValueError(f"ASAR selectors resolve to the same file: {archive_path}")
        targets.add(archive_path)
        if state is not None and current != state:
            raise ValueError(
                "ASAR patch targets have mixed original and patched states"
            )
        state = current
    if state is None:
        raise ValueError("ASAR operation has no files")
    return state


def _transform_asar(
    data: bytes,
    specification: dict[str, Any],
    reverse: bool,
    structural: bool,
) -> bytes:
    source_state = "patched" if reverse else "original"
    target_state = "original" if reverse else "patched"
    if asar_state(data, specification, structural) != source_state:
        raise ValueError(f"ASAR is not in its approved {source_state} state")
    archive = AsarArchive(data)
    replacements = {}
    for selector, file_specification in specification["files"].items():
        archive_path, current = _target_state(
            archive, selector, file_specification, structural
        )
        if current != source_state:
            raise ValueError(f"ASAR target is not in its approved {source_state} state")
        original = archive.content(archive_path)
        source = original.decode("utf-8")
        source = _transform_source(source, file_specification, reverse)
        transformed = source.encode("utf-8")
        if not structural:
            expected = file_specification[f"{target_state}_sha256"]
            if sha256(transformed) != expected:
                raise ValueError(
                    f"{archive_path} {target_state} SHA-256 differs from manifest"
                )
        replacements[archive_path] = transformed
    transformed = archive.replace(replacements)
    if asar_state(transformed, specification, structural) != target_state:
        raise ValueError(f"{target_state} ASAR failed internal verification")
    return transformed


def patch_asar(
    data: bytes, specification: dict[str, Any], structural: bool = False
) -> bytes:
    return _transform_asar(data, specification, False, structural)


def restore_asar(
    data: bytes, specification: dict[str, Any], structural: bool = False
) -> bytes:
    return _transform_asar(data, specification, True, structural)
