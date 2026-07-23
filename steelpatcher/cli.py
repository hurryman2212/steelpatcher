from __future__ import annotations

import argparse, subprocess, sys

from importlib.metadata import version
from pathlib import Path

from steelpatcher.patcher import patch_firmware
from steelpatcher.profile import load_profile

try:
    from _steelpatcher_build_version import VERSION
except ModuleNotFoundError:
    VERSION = version("steelpatcher")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="steelpatcher")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    patch = subcommands.add_parser("patch", help="patch one firmware image")
    patch.add_argument("firmware", type=Path)
    patch.add_argument("model_json", type=Path)
    patch.add_argument(
        "--select",
        metavar="PATCH",
        help="select single patch",
    )
    patch.add_argument(
        "--output",
        type=Path,
        help="set the patched firmware path",
    )
    patch.add_argument(
        "--force",
        action="store_true",
        help="replace existing output files",
    )
    patch.add_argument(
        "--no-hash-check",
        action="store_true",
        help="allow an unknown firmware hash",
    )
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "patch":
            outputs = patch_firmware(
                arguments.firmware,
                load_profile(arguments.model_json, arguments.select),
                arguments.output,
                arguments.force,
                arguments.no_hash_check,
            )
            print("compatibility: passed")
            for name, path in outputs.items():
                print(f"{name}: {path}")
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"steelpatcher: {error}", file=sys.stderr)
        raise SystemExit(1) from error
