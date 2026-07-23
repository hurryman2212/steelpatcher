# steelpatcher

> [!CAUTION]
> This software can brick your device. You are solely responsible for any resulting damage.

This project contains tools for adding features to the firmware of SteelSeries
products and exposing them through SteelSeries GG. The repository currently
includes only one device feature patch: it adds hardware macro support to the
Rival 3 Wireless Gen 2 mouse, allowing recorded macros to be stored in and
executed from onboard memory. I hope this effort eventually expands to every
mouse without hardware macro support but still uses an onboard MCU and Flash.

## How This Is Possible

The currently supported device checks firmware integrity with CRC32, but no
cryptographic firmware signature check was found. A modified image can therefore
be accepted after its CRC is recomputed.

GG also contains the information needed to modify its device descriptions.
`SteelSeriesEngine.exe` contains the password used for the symmetric OpenPGP
encryption of `.edevice` files, which describe device capabilities, settings,
and HID commands. `ggpatcher` extracts that password, decrypts the target
descriptor, applies the patch, and encrypts it again. This encryption applies to
the `.edevice` descriptors; `app.asar` and the Engine database are patched
separately.

## How To Build

Building requires CMake 3.25 or newer, Python 3.11 or newer, and a C++20
compiler. First install the native dependencies. On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install --yes \
  build-essential cmake git \
  libssl-dev libudev-dev libusb-1.0-0-dev pkg-config \
  python3 python3-pip python3-venv
python3 --version
```

Other Linux distributions need the equivalent OpenSSL, libudev, libusb, and
pkg-config packages and the required build tools. On Windows, install Git,
CMake, Python, and the MSVC C++ toolchain from an administrator PowerShell:

```powershell
winget install --exact --id Git.Git
winget install --exact --id Kitware.CMake
winget install --exact --id Python.Python.3.13 --scope user
winget install --exact --id Microsoft.VisualStudio.2022.BuildTools `
  --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
py -3 --version
```

Open a new PowerShell, then install
[vcpkg](https://github.com/microsoft/vcpkg), set its location, and install the
static OpenSSL package:

```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
& "$env:VCPKG_ROOT\vcpkg.exe" install openssl:x64-windows-static
```

Install the Python build dependencies once from the repository root:

```sh
# Linux
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[build]"

# Windows
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[build]"
```

Configure and build all three CLI programs on Linux:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DPython3_EXECUTABLE="$PWD/.venv/bin/python"
cmake --build build --parallel
```

On Windows, pass the vcpkg toolchain so CMake statically links OpenSSL:

```powershell
$python = (Resolve-Path .venv\Scripts\python.exe).Path
cmake -S . -B build -A x64 `
  "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  "-DPython3_EXECUTABLE=$python" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release --parallel
```

The executables are written to `build/bin` as `steelpatcher`, `steelupdater`,
and `ggpatcher`, with an `.exe` suffix on Windows.

Applying firmware patches also requires the Arm GNU Toolchain. Install
`binutils-arm-none-eabi` and `gcc-arm-none-eabi` on Debian or Ubuntu. On
Windows, install it from an administrator PowerShell:

```powershell
winget install --exact `
  --id Arm.GnuArmEmbeddedToolchain `
  --source winget `
  --accept-source-agreements `
  --accept-package-agreements `
  --disable-interactivity
```

Open a new shell and confirm that `arm-none-eabi-gcc`,
`arm-none-eabi-objcopy`, and `arm-none-eabi-size` are on `PATH`.

`steelpatcher` and `ggpatcher` read model and patch data from the repository at
runtime. Use the `profiles/` and `patches/` trees from the same release as the
executables.

# How To Use

- `steelpatcher` creates patched firmware images from a model profile.
- `steelupdater` derives update targets and commands from GG device descriptors.
- `ggpatcher` applies, verifies, or removes the matching GG integration.

Run `<program> -h` and `<program> <command> -h` for complete command syntax and
options.

The following example installs the recorded onboard macro patch for the Rival 3
Wireless Gen 2. It assumes `build/bin` is on `PATH` and uses the standard Windows
GG installation paths. Close GG before updating the device or patching GG.

```sh
steelpatcher patch "C:\Program Files\SteelSeries\GG\apps\engine\firmware\272111730\firmware-rival-3-wireless-v2-mouse-v1.5.0.bin" profiles/rival3_wireless_gen2.json --select recorded_macro
steelupdater dev-list
steelupdater update 1038:1872:0 --json firmware-rival-3-wireless-v2-mouse-v1.5.0.patch.json
ggpatcher patch profiles/rival3_wireless_gen2.json --select recorded_macro
```

Keep the generated `.patch.json`, `.patched.bin`, and additional image files
together. Every generated binary carries a verified host-only trailer that
`steelupdater` removes before flashing. Passing one directly instead of through
`--json` is rejected. An unmarked stock firmware is accepted directly only when
its SHA-256 matches exactly one stock component in the GG installation selected
by `--program-dir`; that match determines the device firmware recipe.

## Running GG on Wine

GG 115 requires the Wine 11.13 source patches in `patches/gg_wine`. Apply both
patches before building Wine:

```sh
git -C /path/to/wine checkout wine-11.13
git -C /path/to/wine apply "$PWD/patches/gg_wine/wine-11.13-crypt32.patch"
git -C /path/to/wine apply "$PWD/patches/gg_wine/wine-11.13-hid-short-input.patch"
```

Install GG normally in the Wine prefix so its `ProgramData` databases are
created, close GG, and apply the host patch:

```sh
ggpatcher patch patches/gg_wine \
  --program-dir "$WINEPREFIX/drive_c/Program Files/SteelSeries/GG" \
  --program-data-dir "$WINEPREFIX/drive_c/ProgramData/SteelSeries/GG"
```

Install the included udev rule once, reload the rules, and reconnect the
wireless dongle so Wine can access its HID command interfaces:

```sh
sudo install -m 0644 \
  patches/gg_wine/target/99-steelpatcher-rival3-wireless-gen2.rules \
  /etc/udev/rules.d/
sudo udevadm control --reload-rules
```
