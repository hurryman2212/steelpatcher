from __future__ import annotations

import copy, hashlib, json, os, sqlite3, stat, tempfile

from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ggpatcher import descriptor
from ggpatcher.asar import asar_state, patch_asar, restore_asar


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_manifest(patch_directory: Path) -> dict[str, Any]:
    path = patch_directory.resolve() / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported GG patch manifest schema version")
    common_files = data.get("files")
    if not isinstance(common_files, list) or not common_files:
        raise ValueError("GG patch manifest has no files")
    if not isinstance(data.get("engine"), str):
        raise ValueError("GG patch manifest has no Engine path")
    if not isinstance(data.get("versions"), dict) or not data["versions"]:
        raise ValueError("GG patch manifest has no versions")
    for version, specification in data["versions"].items():
        if not isinstance(version, str) or not isinstance(specification, dict):
            raise ValueError("GG patch manifest has an invalid version")
        digest = specification.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"GG version {version} has an invalid SHA-256")

    files = copy.deepcopy(common_files)
    file_paths = set()

    def add_file(specification: Any) -> None:
        if not isinstance(specification, dict):
            raise ValueError("GG patch manifest has an invalid file")
        target = specification.get("path")
        operation = specification.get("operation")
        if not isinstance(target, str) or not target or not isinstance(operation, dict):
            raise ValueError("GG patch manifest has an invalid file")
        if target in file_paths:
            raise ValueError(f"GG patch manifest targets a file twice: {target}")
        file_paths.add(target)

    for specification in files:
        add_file(specification)

    devices = data.get("devices", [])
    if not isinstance(devices, list):
        raise ValueError("GG patch manifest devices must be a list")
    database = data.get("database")
    if devices:
        if not isinstance(database, dict) or not isinstance(database.get("path"), str):
            raise ValueError("device GG patch manifest has no Engine database path")
    elif database is not None:
        raise ValueError("GG patch manifest database has no devices")

    product_ids = set()
    common_asar = {
        specification["path"]: specification["operation"]
        for specification in files
        if specification["operation"].get("type") == "asar"
    }
    for device in devices:
        if not isinstance(device, dict):
            raise ValueError("GG patch manifest has an invalid device")
        product_id = device.get("product_id")
        macro_size = device.get("macro_size")
        has_onboard_macros = device.get("has_onboard_macros")
        if (
            not isinstance(product_id, int)
            or isinstance(product_id, bool)
            or not 0 <= product_id <= 0xFFFFFFFF
            or not isinstance(macro_size, int)
            or isinstance(macro_size, bool)
            or macro_size <= 0
            or not isinstance(has_onboard_macros, bool)
        ):
            raise ValueError("GG patch manifest has invalid device capabilities")
        if product_id in product_ids:
            raise ValueError(f"GG patch manifest repeats product ID {product_id}")
        product_ids.add(product_id)

        device_files = device.get("files", [])
        if not isinstance(device_files, list):
            raise ValueError(f"GG device {product_id} has invalid file patches")
        for specification in copy.deepcopy(device_files):
            add_file(specification)
            files.append(specification)

        contributions = device.get("asar_replacements", {})
        if not isinstance(contributions, dict):
            raise ValueError(f"GG device {product_id} has invalid ASAR replacements")
        for target, archive_files in contributions.items():
            operation = common_asar.get(target)
            if operation is None or not isinstance(archive_files, dict):
                raise ValueError(
                    f"GG device {product_id} references an unknown common ASAR"
                )
            operation_files = operation.get("files")
            if not isinstance(operation_files, dict):
                raise ValueError(f"common ASAR operation is invalid: {target}")
            for selector, replacements in archive_files.items():
                archive_specification = operation_files.get(selector)
                if (
                    not isinstance(archive_specification, dict)
                    or not isinstance(replacements, list)
                    or not replacements
                ):
                    raise ValueError(
                        f"GG device {product_id} references an unknown ASAR file"
                    )
                destination = archive_specification.setdefault("replacements", [])
                if not isinstance(destination, list):
                    raise ValueError(f"common ASAR operation is invalid: {target}")
                for replacement in copy.deepcopy(replacements):
                    if not isinstance(replacement, dict):
                        raise ValueError(
                            f"GG device {product_id} has an invalid ASAR replacement"
                        )
                    duplicate = next(
                        (
                            candidate
                            for candidate in destination
                            if isinstance(candidate, dict)
                            and candidate.get("find") == replacement.get("find")
                        ),
                        None,
                    )
                    if duplicate is None:
                        destination.append(replacement)
                    elif duplicate != replacement:
                        raise ValueError(
                            f"GG device {product_id} conflicts in ASAR file {selector}"
                        )

    for specification in files:
        operation = specification["operation"]
        if operation.get("type") != "asar":
            continue
        archive_files = operation.get("files")
        if not isinstance(archive_files, dict) or not archive_files:
            raise ValueError("ASAR operation has no files")
        for selector, archive_specification in archive_files.items():
            replacements = archive_specification.get("replacements")
            bindings = archive_specification.get("bindings", {})
            if (
                not isinstance(selector, str)
                or not selector
                or not isinstance(replacements, list)
                or not replacements
                or not isinstance(bindings, dict)
            ):
                raise ValueError("ASAR operation has invalid replacements")
            tokens = []
            for name, binding in bindings.items():
                if (
                    not isinstance(name, str)
                    or not name.isidentifier()
                    or not isinstance(binding, dict)
                    or binding.get("type") != "webpack_module_id"
                    or not isinstance(binding.get("anchor"), str)
                    or not binding["anchor"]
                ):
                    raise ValueError("ASAR operation has an invalid binding")
                tokens.append(f"{{{{{name}}}}}")
            finds = []
            values = []
            for replacement in replacements:
                if (
                    not isinstance(replacement, dict)
                    or not isinstance(replacement.get("find"), str)
                    or not replacement["find"]
                    or not isinstance(replacement.get("replace"), str)
                    or replacement["find"] == replacement["replace"]
                ):
                    raise ValueError("ASAR operation has an invalid replacement")
                finds.append(replacement["find"])
                values.extend((replacement["find"], replacement["replace"]))
            if len(finds) != len(set(finds)):
                raise ValueError(f"ASAR file {selector} repeats a replacement")
            for token in tokens:
                if sum(value.count(token) for value in values) != 1:
                    raise ValueError(
                        f"ASAR binding {token} must be used exactly once in {selector}"
                    )

    data["files"] = files
    return data


def _target(root: Path, relative: str) -> Path:
    root = root.resolve()
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError(f"manifest path escapes its root: {relative}") from error
    return target


def _load_engine(gg_root: Path, manifest: dict[str, Any], no_hash_check: bool) -> bytes:
    engine = _target(gg_root, manifest["engine"]).read_bytes()
    if no_hash_check:
        return engine
    version_data = json.loads(_target(gg_root, "version.json").read_text("utf-8"))
    if not isinstance(version_data, dict) or not isinstance(
        version_data.get("version"), str
    ):
        raise ValueError("GG version.json does not contain a version string")
    installed_version = version_data["version"]
    digest = _sha256(engine)
    specification = manifest["versions"].get(installed_version)
    if not isinstance(specification, dict):
        raise ValueError(
            "installed GG version is not supported by this patch manifest; use "
            "--no-hash-check to rely on patch-specific checks"
        )
    if specification["sha256"] != digest:
        raise ValueError(
            "SteelSeriesEngine.exe SHA-256 does not match its supported GG version; "
            "use --no-hash-check to rely on patch-specific checks"
        )
    return engine


def _descriptor_state(
    plaintext: bytes,
    patch: bytes,
    operation: dict[str, Any],
    structural: bool,
) -> str:
    if structural:
        return descriptor.scm_patch_state(plaintext, patch)
    digest = _sha256(plaintext)
    if digest == operation["original_scm_sha256"]:
        return "original"
    if digest == operation["patched_scm_sha256"]:
        return "patched"
    raise ValueError("descriptor is neither the approved original nor SCM patch")


def _atomic_write(path: Path, data: bytes) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _macro_settings(settings: dict[str, Any], size: int) -> dict[str, Any]:
    macros = settings.get("macros")
    if macros is None:
        settings["macros"] = {"event_data": [0] * size, "no_live_deploy": 1}
        return settings
    if not isinstance(macros, dict):
        raise ValueError("existing macro settings are not an object")
    event_data = macros.get("event_data")
    if not isinstance(event_data, list) or len(event_data) != size:
        raise ValueError(f"existing macro event_data is not {size} bytes")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255
        for value in event_data
    ):
        raise ValueError("existing macro event_data contains a non-byte value")
    macros["no_live_deploy"] = 1
    return settings


def _database_rows(
    connection: sqlite3.Connection, specification: dict[str, Any]
) -> tuple[tuple[int, int, str], list[tuple[int, str]]]:
    product_id = int(specification["product_id"])
    devices = connection.execute(
        "SELECT id, has_onboard_macros, settings FROM devices " "WHERE product_id = ?",
        (product_id,),
    ).fetchall()
    if len(devices) != 1:
        raise ValueError(
            "target product ID does not identify exactly one Engine database row"
        )
    device = devices[0]
    configurations = connection.execute(
        "SELECT id, settings FROM configurations WHERE device_id = ?", (device[0],)
    ).fetchall()
    return device, configurations


def _database_device_configured(
    connection: sqlite3.Connection, specification: dict[str, Any]
) -> bool:
    device, configurations = _database_rows(connection, specification)
    size = int(specification["macro_size"])
    if device[1] != int(specification["has_onboard_macros"]):
        return False
    settings_values = [device[2], *(row[1] for row in configurations)]
    for value in settings_values:
        settings = json.loads(value)
        macros = settings.get("macros")
        if not isinstance(macros, dict):
            return False
        event_data = macros.get("event_data")
        if not isinstance(event_data, list) or len(event_data) != size:
            return False
        if any(
            not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 255
            for byte in event_data
        ):
            return False
        no_live_deploy = macros.get("no_live_deploy")
        if (
            not isinstance(no_live_deploy, int)
            or isinstance(no_live_deploy, bool)
            or no_live_deploy != 1
        ):
            return False
    return True


def _database_device_unconfigured(
    connection: sqlite3.Connection, specification: dict[str, Any]
) -> bool:
    device, configurations = _database_rows(connection, specification)
    if device[1] != 0:
        return False
    settings_values = [device[2], *(row[1] for row in configurations)]
    return all("macros" not in json.loads(value) for value in settings_values)


def _database_connection_configured(
    connection: sqlite3.Connection, specifications: list[dict[str, Any]]
) -> bool:
    return all(
        _database_device_configured(connection, specification)
        for specification in specifications
    )


def _database_connection_unconfigured(
    connection: sqlite3.Connection, specifications: list[dict[str, Any]]
) -> bool:
    return all(
        _database_device_unconfigured(connection, specification)
        for specification in specifications
    )


def _database_configured(path: Path, specifications: list[dict[str, Any]]) -> bool:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        return _database_connection_configured(connection, specifications)


def _database_unconfigured(path: Path, specifications: list[dict[str, Any]]) -> bool:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        return _database_connection_unconfigured(connection, specifications)


def _snapshot_database(path: Path) -> bytes:
    with (
        closing(sqlite3.connect(path, timeout=0)) as source,
        closing(sqlite3.connect(":memory:")) as snapshot,
    ):
        source.backup(snapshot)
        return snapshot.serialize()


def _patch_database(path: Path, specifications: list[dict[str, Any]]) -> bytes:
    with (
        closing(sqlite3.connect(path, timeout=0)) as source,
        closing(sqlite3.connect(":memory:")) as working,
    ):
        source.backup(working)
        with working:
            for specification in specifications:
                device, configurations = _database_rows(working, specification)
                size = int(specification["macro_size"])
                device_settings = _macro_settings(json.loads(device[2]), size)
                working.execute(
                    "UPDATE devices SET has_onboard_macros = ?, settings = ? "
                    "WHERE id = ? AND product_id = ?",
                    (
                        int(specification["has_onboard_macros"]),
                        json.dumps(device_settings, separators=(",", ":")),
                        device[0],
                        int(specification["product_id"]),
                    ),
                )
                for configuration_id, value in configurations:
                    settings = _macro_settings(json.loads(value), size)
                    working.execute(
                        "UPDATE configurations SET settings = ? WHERE id = ?",
                        (
                            json.dumps(settings, separators=(",", ":")),
                            configuration_id,
                        ),
                    )
        if not _database_connection_configured(working, specifications):
            raise ValueError("patched Engine database failed verification")
        return working.serialize()


def _restore_database(path: Path, specifications: list[dict[str, Any]]) -> bytes:
    with (
        closing(sqlite3.connect(path, timeout=0)) as source,
        closing(sqlite3.connect(":memory:")) as working,
    ):
        source.backup(working)
        with working:
            for specification in specifications:
                device, configurations = _database_rows(working, specification)
                device_settings = json.loads(device[2])
                del device_settings["macros"]
                working.execute(
                    "UPDATE devices SET has_onboard_macros = 0, settings = ? "
                    "WHERE id = ? AND product_id = ?",
                    (
                        json.dumps(device_settings, separators=(",", ":")),
                        device[0],
                        int(specification["product_id"]),
                    ),
                )
                for configuration_id, value in configurations:
                    settings = json.loads(value)
                    del settings["macros"]
                    working.execute(
                        "UPDATE configurations SET settings = ? WHERE id = ?",
                        (
                            json.dumps(settings, separators=(",", ":")),
                            configuration_id,
                        ),
                    )
        if not _database_connection_unconfigured(working, specifications):
            raise ValueError("restored Engine database failed verification")
        return working.serialize()


def _install_database(path: Path, data: bytes) -> None:
    _atomic_write(path, data)


@dataclass(frozen=True)
class Change:
    target: Path
    before: bytes
    after: bytes
    kind: str = "file"


def _prepare_files(
    gg_root: Path,
    patch_directory: Path,
    manifest: dict[str, Any],
    no_hash_check: bool,
) -> list[Change]:
    engine = _load_engine(gg_root, manifest, no_hash_check)
    descriptor_password = None
    if any(
        specification["operation"]["type"] == "descriptor_patch"
        for specification in manifest["files"]
    ):
        descriptor_password = descriptor.extract_descriptor_password(engine)
    changes = []
    for specification in manifest["files"]:
        target = _target(gg_root, specification["path"])
        original = target.read_bytes()
        operation = specification["operation"]
        if operation["type"] == "descriptor_patch":
            if descriptor_password is None:
                raise ValueError("descriptor password was not loaded")
            plaintext = descriptor.decrypt_descriptor(original, descriptor_password)
            patch = _target(patch_directory, operation["source"]).read_bytes()
            if (
                _descriptor_state(plaintext, patch, operation, no_hash_check)
                == "patched"
            ):
                continue
            patched_plaintext = descriptor.apply_scm_patch(plaintext, patch)
            if (
                _descriptor_state(patched_plaintext, patch, operation, no_hash_check)
                != "patched"
            ):
                raise ValueError(f"{target} failed patched SCM verification")
            patched = descriptor.encrypt_descriptor(
                patched_plaintext, descriptor_password
            )
        elif operation["type"] == "asar":
            if asar_state(original, operation, no_hash_check) == "patched":
                continue
            patched = patch_asar(original, operation, no_hash_check)
        elif operation["type"] == "replace":
            digest = _sha256(original)
            if digest == specification["patched_sha256"]:
                continue
            if digest != specification["original_sha256"]:
                raise ValueError(f"{target} is neither the approved original nor patch")
            source = _target(patch_directory, operation["source"])
            patched = source.read_bytes()
            if _sha256(patched) != specification["patched_sha256"]:
                raise ValueError(f"{target} patched SHA-256 differs from manifest")
        else:
            raise ValueError(f"unsupported GG file operation: {operation['type']}")
        changes.append(Change(target, original, patched))
    return changes


def _prepare_restore_files(
    gg_root: Path,
    patch_directory: Path,
    manifest: dict[str, Any],
    no_hash_check: bool,
) -> list[Change]:
    engine = _load_engine(gg_root, manifest, no_hash_check)
    descriptor_password = None
    if any(
        specification["operation"]["type"] == "descriptor_patch"
        for specification in manifest["files"]
    ):
        descriptor_password = descriptor.extract_descriptor_password(engine)
    changes = []
    for specification in manifest["files"]:
        target = _target(gg_root, specification["path"])
        current = target.read_bytes()
        operation = specification["operation"]
        if operation["type"] == "descriptor_patch":
            if descriptor_password is None:
                raise ValueError("descriptor password was not loaded")
            plaintext = descriptor.decrypt_descriptor(current, descriptor_password)
            patch = _target(patch_directory, operation["source"]).read_bytes()
            if (
                _descriptor_state(plaintext, patch, operation, no_hash_check)
                == "original"
            ):
                continue
            restored_plaintext = descriptor.restore_scm_patch(plaintext, patch)
            if (
                _descriptor_state(restored_plaintext, patch, operation, no_hash_check)
                != "original"
            ):
                raise ValueError(f"{target} failed restored SCM verification")
            restored = descriptor.encrypt_descriptor(
                restored_plaintext, descriptor_password
            )
        elif operation["type"] == "asar":
            if asar_state(current, operation, no_hash_check) == "original":
                continue
            restored = restore_asar(current, operation, no_hash_check)
        elif operation["type"] == "replace":
            digest = _sha256(current)
            if digest == specification["original_sha256"]:
                continue
            if digest != specification["patched_sha256"]:
                raise ValueError(f"{target} is neither the approved original nor patch")
            source = operation.get("original_source")
            if not isinstance(source, str):
                raise ValueError("replace operation cannot be restored without source")
            restored = _target(patch_directory, source).read_bytes()
            if _sha256(restored) != specification["original_sha256"]:
                raise ValueError(f"{target} original SHA-256 differs from manifest")
        else:
            raise ValueError(f"unsupported GG file operation: {operation['type']}")
        changes.append(Change(target, current, restored))
    return changes


def _install_changes(changes: list[Change], verify: Callable[[], None]) -> None:
    written = []
    try:
        for change in changes:
            if change.kind == "sqlite":
                _install_database(change.target, change.after)
            else:
                _atomic_write(change.target, change.after)
            written.append(change)
        verify()
    except Exception as error:
        rollback_errors = []
        for change in reversed(written):
            try:
                if change.kind == "sqlite":
                    _install_database(change.target, change.before)
                else:
                    _atomic_write(change.target, change.before)
            except Exception as rollback_error:
                rollback_errors.append(f"{change.target}: {rollback_error}")
        if rollback_errors:
            raise RuntimeError(
                "GG change failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from error
        raise


def _patch_gg(
    gg_root: Path,
    data_root: Path,
    patch_directory: Path,
    no_hash_check: bool,
) -> bool:
    gg_root = gg_root.resolve()
    data_root = data_root.resolve()
    patch_directory = patch_directory.resolve()
    manifest = _load_manifest(patch_directory)
    changes = _prepare_files(gg_root, patch_directory, manifest, no_hash_check)
    database_specification = manifest.get("database")
    if database_specification is not None:
        database = _target(data_root, database_specification["path"])
        devices = manifest["devices"]
        if not _database_configured(database, devices):
            if not _database_unconfigured(database, devices):
                raise ValueError("Engine database is neither original nor patched")
            original = _snapshot_database(database)
            changes.append(
                Change(
                    database,
                    original,
                    _patch_database(database, devices),
                    "sqlite",
                )
            )
    if not changes:
        return False
    _install_changes(
        changes,
        lambda: _verify_gg_state(
            gg_root, data_root, patch_directory, True, no_hash_check
        ),
    )
    return True


def _verify_gg_state(
    gg_root: Path,
    data_root: Path,
    patch_directory: Path,
    patched: bool,
    no_hash_check: bool,
) -> None:
    manifest = _load_manifest(patch_directory)
    engine = _load_engine(gg_root, manifest, no_hash_check)
    state = "patched" if patched else "original"
    descriptor_password = None
    for specification in manifest["files"]:
        target = _target(gg_root, specification["path"])
        operation = specification["operation"]
        if operation["type"] == "descriptor_patch":
            if descriptor_password is None:
                descriptor_password = descriptor.extract_descriptor_password(engine)
            plaintext = descriptor.decrypt_descriptor(
                target.read_bytes(), descriptor_password
            )
            patch = _target(patch_directory, operation["source"]).read_bytes()
            valid = (
                _descriptor_state(plaintext, patch, operation, no_hash_check) == state
            )
        elif operation["type"] == "asar":
            valid = asar_state(target.read_bytes(), operation, no_hash_check) == state
        else:
            valid = _sha256(target.read_bytes()) == specification[f"{state}_sha256"]
        if not valid:
            raise ValueError(f"GG {state} verification failed: {target}")
    database_specification = manifest.get("database")
    if database_specification is not None:
        database = _target(data_root, database_specification["path"])
        devices = manifest["devices"]
        configured = _database_configured(database, devices)
        valid = configured if patched else _database_unconfigured(database, devices)
        if not valid:
            raise ValueError(f"Engine database {state} verification failed")


def _restore_gg(
    gg_root: Path,
    data_root: Path,
    patch_directory: Path,
    no_hash_check: bool,
) -> bool:
    gg_root = gg_root.resolve()
    data_root = data_root.resolve()
    patch_directory = patch_directory.resolve()
    manifest = _load_manifest(patch_directory)
    changes = _prepare_restore_files(gg_root, patch_directory, manifest, no_hash_check)
    database_specification = manifest.get("database")
    if database_specification is not None:
        database = _target(data_root, database_specification["path"])
        devices = manifest["devices"]
        if _database_configured(database, devices):
            current = _snapshot_database(database)
            changes.append(
                Change(
                    database,
                    current,
                    _restore_database(database, devices),
                    "sqlite",
                )
            )
        elif not _database_unconfigured(database, devices):
            raise ValueError("Engine database is neither original nor patched")
    if not changes:
        return False
    _install_changes(
        changes,
        lambda: _verify_gg_state(
            gg_root, data_root, patch_directory, False, no_hash_check
        ),
    )
    return True


def patch_gg(
    gg_root: Path,
    data_root: Path,
    patch_directories: list[Path],
    no_hash_check: bool = False,
) -> bool:
    changed = []
    try:
        for patch_directory in patch_directories:
            if _patch_gg(gg_root, data_root, patch_directory, no_hash_check):
                changed.append(patch_directory)
        verify_gg(gg_root, data_root, patch_directories, no_hash_check)
    except Exception as error:
        rollback_errors = []
        for patch_directory in reversed(changed):
            try:
                _restore_gg(gg_root, data_root, patch_directory, no_hash_check)
            except Exception as rollback_error:
                rollback_errors.append(str(rollback_error))
        if rollback_errors:
            raise ValueError(
                f"GG patch failed and rollback also failed: {'; '.join(rollback_errors)}"
            ) from error
        raise
    return bool(changed)


def verify_gg(
    gg_root: Path,
    data_root: Path,
    patch_directories: list[Path],
    no_hash_check: bool = False,
    *,
    patched: bool = True,
) -> None:
    for patch_directory in patch_directories:
        _verify_gg_state(gg_root, data_root, patch_directory, patched, no_hash_check)


def restore_gg(
    gg_root: Path,
    data_root: Path,
    patch_directories: list[Path],
    no_hash_check: bool = False,
) -> bool:
    changed = []
    try:
        for patch_directory in reversed(patch_directories):
            if _restore_gg(gg_root, data_root, patch_directory, no_hash_check):
                changed.append(patch_directory)
        for patch_directory in patch_directories:
            _verify_gg_state(gg_root, data_root, patch_directory, False, no_hash_check)
    except Exception as error:
        rollback_errors = []
        for patch_directory in reversed(changed):
            try:
                _patch_gg(gg_root, data_root, patch_directory, no_hash_check)
            except Exception as rollback_error:
                rollback_errors.append(str(rollback_error))
        if rollback_errors:
            raise ValueError(
                f"GG restore failed and rollback also failed: {'; '.join(rollback_errors)}"
            ) from error
        raise
    return bool(changed)
