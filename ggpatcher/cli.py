from __future__ import annotations

import argparse, json, sqlite3, sys

from importlib.metadata import version
from pathlib import Path

from ggpatcher.patcher import patch_gg, restore_gg, verify_gg
from steelpatcher.profile import select_patch_directories

try:
    from _steelpatcher_build_version import VERSION
except ModuleNotFoundError:
    VERSION = version("steelpatcher")

_DEFAULT_PROGRAM_DIR = Path(r"C:\Program Files\SteelSeries\GG")
_DEFAULT_PROGRAM_DATA_DIR = Path(r"C:\ProgramData\SteelSeries\GG")


def _add_common_arguments(
    parser: argparse.ArgumentParser, optional_target: bool = False
) -> None:
    parser.add_argument(
        "target",
        nargs="?" if optional_target else None,
        type=Path,
        help=(
            "model JSON or standalone GG patch; omit to verify original state"
            if optional_target
            else "model JSON or standalone GG patch directory"
        ),
    )
    parser.add_argument(
        "--select",
        metavar="PATCH",
        help="select single patch",
    )
    parser.add_argument(
        "--program-dir",
        type=Path,
        default=_DEFAULT_PROGRAM_DIR,
        help="GG program directory",
    )
    parser.add_argument(
        "--program-data-dir",
        type=Path,
        default=_DEFAULT_PROGRAM_DATA_DIR,
        help="GG ProgramData directory",
    )
    parser.add_argument(
        "--no-hash-check",
        action="store_true",
        help="allow an unknown GG version or Engine hash",
    )


def _gg_patch_directories(target: Path, selected_patch: str | None) -> list[Path]:
    standalone = target.resolve()
    if standalone.is_dir():
        if selected_patch is not None:
            raise ValueError("--select cannot be used with a standalone GG patch")
        if not (standalone / "manifest.json").is_file():
            raise ValueError("standalone GG patch has no manifest.json")
        return [standalone]

    profile_path = standalone
    directories = []
    for patch_directory in select_patch_directories(profile_path, selected_patch, True):
        directory = patch_directory / "gg"
        if (directory / "manifest.json").is_file():
            directories.append(directory)
        elif selected_patch is not None:
            raise ValueError(f"selected patch has no GG manifest: {selected_patch}")
    if not directories:
        raise ValueError("model profile has no GG patches")
    return directories


def _original_gg_patch_directories(selected_patch: str | None) -> list[Path]:
    executable = Path(sys.executable).resolve()
    module = Path(__file__).resolve()
    candidates = [
        (Path.cwd() / "patches").resolve(),
        *((parent / "patches").resolve() for parent in module.parents),
        *((parent / "patches").resolve() for parent in executable.parents),
    ]
    roots = [
        root
        for index, root in enumerate(candidates)
        if root not in candidates[:index] and root.is_dir()
    ]
    if not roots:
        raise ValueError(
            "cannot find patches directory; run from the project root or specify target"
        )
    root = roots[0]
    directories = []
    for path in sorted(root.rglob("manifest.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("engine"), str):
            continue
        directory = path.parent
        name = directory.parent.name if directory.name == "gg" else directory.name
        if selected_patch is None or selected_patch == name:
            directories.append(directory)
    if not directories:
        suffix = (
            f" matching --select {selected_patch!r}"
            if selected_patch is not None
            else ""
        )
        raise ValueError(f"patches directory has no GG manifests{suffix}")
    return directories


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ggpatcher")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    patch = subcommands.add_parser("patch", help="patch a closed GG installation")
    _add_common_arguments(patch)

    verify = subcommands.add_parser(
        "verify", help="verify patched target or original GG"
    )
    _add_common_arguments(verify, True)

    restore = subcommands.add_parser("restore", help="remove selected GG patches")
    _add_common_arguments(restore)
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    try:
        original = arguments.command == "verify" and arguments.target is None
        patch_directories = (
            _original_gg_patch_directories(arguments.select)
            if original
            else _gg_patch_directories(arguments.target, arguments.select)
        )
        if arguments.command == "patch":
            changed = patch_gg(
                arguments.program_dir,
                arguments.program_data_dir,
                patch_directories,
                arguments.no_hash_check,
            )
            if not changed:
                print("GG patch set is already installed.")
            else:
                print("GG patch set installed and verified.")
        elif arguments.command == "verify":
            verify_gg(
                arguments.program_dir,
                arguments.program_data_dir,
                patch_directories,
                arguments.no_hash_check,
                patched=not original,
            )
            state = "original state" if original else "patch set"
            print(f"GG {state} verification passed.")
        elif arguments.command == "restore":
            changed = restore_gg(
                arguments.program_dir,
                arguments.program_data_dir,
                patch_directories,
                arguments.no_hash_check,
            )
            if changed:
                print("GG patch set removed and verified.")
            else:
                print("GG patch set is not installed.")
    except (
        KeyError,
        OSError,
        ValueError,
        sqlite3.Error,
    ) as error:
        print(f"ggpatcher: {error}", file=sys.stderr)
        raise SystemExit(1) from error
