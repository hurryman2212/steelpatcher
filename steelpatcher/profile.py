from __future__ import annotations

import json, re

from dataclasses import dataclass
from pathlib import Path
from typing import Any


def integer(value: int | str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected an integer or integer string, got {value!r}")


def _load_device_profile(path: Path) -> tuple[Path, dict[str, Any]]:
    resolved = path.resolve()
    data = json.loads(resolved.read_text(encoding="utf-8"))
    required = {"schema_version", "model", "firmware", "memory"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"model profile is missing fields: {sorted(missing)}")
    if data["schema_version"] != 1:
        raise ValueError("unsupported model profile schema version")
    if data["firmware"]["architecture"] != "arm-thumb":
        raise ValueError("the minimal implementation supports ARM Thumb only")
    memory = data["memory"]
    if not isinstance(memory, dict) or not all(
        isinstance(memory.get(kind), dict) and memory[kind] for kind in ("flash", "ram")
    ):
        raise ValueError("model profile memory must define flash and RAM regions")
    return resolved, data


def select_patch_directories(
    profile_path: Path, selected_patch: str | None, select_all: bool = False
) -> list[Path]:
    resolved, _ = _load_device_profile(profile_path)
    patch_root = resolved.parent.parent / "patches"
    if not patch_root.is_dir():
        raise ValueError(f"patch directory does not exist: {patch_root}")
    candidates = sorted(
        directory
        for directory in patch_root.iterdir()
        if directory.is_dir()
        and (directory / "manifest.json").is_file()
        and (directory / "targets" / resolved.name).is_file()
    )
    if selected_patch is not None:
        candidates = [
            directory for directory in candidates if directory.name == selected_patch
        ]
        if not candidates:
            raise ValueError(
                f"patch does not support this device profile: {selected_patch}"
            )
    elif not select_all:
        if len(candidates) != 1:
            raise ValueError(
                "device profile does not select exactly one patch; use --select"
            )
        candidates = candidates[:1]
    if not candidates:
        raise ValueError("no patch supports this device profile")
    return candidates


@dataclass(frozen=True)
class ModelProfile:
    path: Path
    data: dict[str, Any]
    patch_directory: Path
    target: dict[str, Any]

    @property
    def project_root(self) -> Path:
        return self.path.parent.parent

    def memory_region(self, memory: str, name: str) -> dict[str, Any]:
        try:
            region = self.data["memory"][memory][name]
        except KeyError as error:
            raise ValueError(f"unknown {memory} region {name!r}") from error
        if not isinstance(region, dict):
            raise ValueError(f"{memory} region {name!r} must be an object")
        return region


def load_profile(path: Path, selected_patch: str | None = None) -> ModelProfile:
    resolved, data = _load_device_profile(path)
    patch_directory = select_patch_directories(resolved, selected_patch)[0]
    target_path = patch_directory / "targets" / resolved.name
    target = json.loads(target_path.read_text(encoding="utf-8"))
    target_required = {
        "schema_version",
        "architecture",
        "artifacts",
        "resources",
        "build_definitions",
        "bindings",
        "checks",
        "hooks",
        "bss_end",
    }
    target_missing = target_required - target.keys()
    if target_missing:
        raise ValueError(f"patch target is missing fields: {sorted(target_missing)}")
    if target["schema_version"] != 1:
        raise ValueError("unsupported patch target schema version")
    if target["architecture"] != data["firmware"]["architecture"]:
        raise ValueError("patch target architecture differs from model profile")
    if not isinstance(target["artifacts"], dict) or not target["artifacts"]:
        raise ValueError("patch target must place at least one artifact")
    return ModelProfile(resolved, data, patch_directory, target)


def load_patch_manifest(profile: ModelProfile) -> dict[str, Any]:
    path = profile.patch_directory / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported patch module schema version")
    if data.get("architecture") != profile.data["firmware"]["architecture"]:
        raise ValueError("patch module architecture differs from model profile")
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("patch module artifacts must be a non-empty object")
    if set(artifacts) != set(profile.target["artifacts"]):
        raise ValueError("patch target must place every manifest artifact exactly once")
    for name, specification in artifacts.items():
        if (
            name in {"firmware", "report"}
            or re.fullmatch(r"[a-z][a-z0-9_]*", name) is None
        ):
            raise ValueError(f"patch artifact has an unsafe name: {name!r}")
        if (
            not isinstance(specification, dict)
            or not {
                "link",
                "packaging",
                "required_symbol",
            }
            <= specification.keys()
        ):
            raise ValueError(f"patch artifact {name} is incomplete")
        if specification["link"] not in {"storage", "runtime"}:
            raise ValueError(f"patch artifact {name} has an invalid link placement")
        if specification["packaging"] not in {"raw", "crc32-residue"}:
            raise ValueError(f"patch artifact {name} has unsupported packaging")
    return data
