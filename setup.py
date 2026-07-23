import os, shutil, subprocess

from pathlib import Path
from setuptools import setup

root = Path(__file__).resolve().parent
if os.name == "nt":
    command = [
        shutil.which("pwsh") or "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(root / "generate_version.ps1"),
    ]
else:
    command = [str(root / "generate-version.sh")]

setup(version=subprocess.check_output(command, text=True).strip())
