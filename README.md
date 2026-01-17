# eCTF Insecure Example

This repository holds the insecure example design for an eCTF Hardware Security Module.
The rules for the 2026 eCTF can be found here: https://rules.ectf.mitre.org/. Your team
should **NOT fork this repo**. Instead clone it and push to a new __private__ repo.

## Layout

- `firmware/` - Source code to build the firmware
    - `Makefile` - This makefile is invoked by the eCTF tools when creating an HSM.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `secrets_to_c_header.py` - Python file to convert from global secrets to firmware-parsable header file
    - `inc/` - Directory with c header files
    - `src/` - Directory with c source files
    - `wolfssl/` - Location to place wolfssl library for included Crypto Example
    - `firmware.ld` - Defines memory layout of built firmware
- `ectf26_design/` - Pip-installable module for generating secrets
    - `src/` - Secrets gen source code
        - `gen_secrets.py` - Generates shared secrets
    - `pyproject.toml` - File that tells pip how to install this module
- `Makefile` - Helper script to simplify repetitive build steps

# 2026 MITRE eCTF – HSM Firmware (WIP)

This repository contains my team’s work for the **MITRE eCTF 2026** design phase: firmware for an embedded **Hardware Security Module (HSM)** and the accompanying **secrets generation package**.

> ⚠️ **Competition note:** during the design phase, keep your working repository **private** and **do not commit secrets or build artifacts**.

---

## What’s in this repo

* `firmware/` — C firmware source + build environment (Docker-based toolchain)
* `ectf26_design/` — pip-installable Python package used to generate `global.secrets`
* `Makefile` — helper targets for common workflows

---

## Prerequisites

* Docker Desktop (Linux containers)
* Python 3 + `uv`
* Git
* eCTF tools available via `uvx` (used for flash + host commands)
* MSP-LITO-L2228 dev board + USB serial connection

---

## Quick start (Windows + PowerShell)

### 1) Clone

```powershell
git clone git@github.com:Adrian609/2026-mitre-ectf.git
cd 2026-mitre-ectf
git checkout release
```

### 2) Create a venv + install the design package

```powershell
uv venv
.\.venv\Scripts\Activate.ps1
uv pip install -e .\ectf26_design\
```

### 3) Generate `global.secrets`

Pick the group IDs your team will use (examples below):

```powershell
uv run secrets .\global.secrets 1 2 3 0x1111
```

✅ This creates a `global.secrets` file in the repo root.

### 4) Build the firmware toolchain image

```powershell
docker build -t build-hsm .\firmware
```

### 5) Build firmware (`hsm.bin`)

```powershell
mkdir build -Force | Out-Null

docker run --rm `
  -v "${PWD}\firmware:/hsm" `
  -v "${PWD}\global.secrets:/secrets/global.secrets:ro" `
  -v "${PWD}\build:/out" `
  -e HSM_PIN="abc123" `
  -e PERMISSIONS="0001=RWC:0002=RWC:0003=RWC:1111=RWC" `
  build-hsm
```

Outputs:

* `build\hsm.bin` — flashable firmware image
* `build\hsm.elf` — ELF for debugging/symbols

### 6) Flash the board + start

Replace `COM12` with your serial port:

```powershell
uvx ectf hw COM12 erase
uvx ectf hw COM12 flash .\build\hsm.bin -n hsm
uvx ectf hw COM12 start
```

### 7) Sanity check (host tools)

```powershell
uvx ectf tools COM12 list abc 123
```

---

## Quick start (Linux/macOS)

```bash
git clone git@github.com:Adrian609/2026-mitre-ectf.git
cd 2026-mitre-ectf
git checkout release

uv venv
source .venv/bin/activate
uv pip install -e ./ectf26_design/

uv run secrets ./global.secrets 1 0x1111

docker build -t build-hsm ./firmware
mkdir -p build

docker run --rm \
  -v "$(pwd)/firmware:/hsm" \
  -v "$(pwd)/global.secrets:/secrets/global.secrets:ro" \
  -v "$(pwd)/build:/out" \
  -e HSM_PIN='abc123' \
  -e PERMISSIONS='0001=RWC:1111=RWC' \
  build-hsm
```

---

## Windows gotchas (common fixes)

### Git Bash path mangling with Docker mounts

If you build/run Docker from Git Bash, set:

```bash
MSYS_NO_PATHCONV=1
```

Or run Docker commands from PowerShell.

### CRLF line endings break container scripts

If you see `/out\r`-style errors, convert `*.sh` to LF:

```bash
find firmware -type f -name "*.sh" -print0 | xargs -0 sed -i 's/\r$//'
```

---

## Secrets + artifacts policy (important)

Do **not** commit:

* `global.secrets`
* `build/`
* `*.bin`, `*.elf`
* local venvs (`.venv/`)

If you accidentally committed secrets, rotate them and rewrite history before continuing.

---

## Development notes (WIP)

This repo started from the official **insecure example** and is being hardened to satisfy eCTF 2026 security requirements (authentication, authorization, integrity, and safe transfer between HSMs). Expect rapid changes.

---

## License / Credits

* See `LICENSE.txt`.
* Original scaffolding derived from the MITRE eCTF 2026 insecure example repository; modified for our team’s design.
