# 2026 DU MITRE eCTF HSM Firmware

This repository contains the University of Denver team firmware and build tooling for the
2026 MITRE eCTF Hardware Security Module (HSM) environment.

The official competition rules are at:
https://rules.ectf.mitre.org/

## Security Notice

This codebase started from the insecure reference design and has been actively modified.
Do not assume cryptographic or access-control behavior is correct unless validated by test.

## Repository Layout

- `firmware/`
  - Embedded firmware source, linker scripts, Docker build image, and build entrypoint.
  - `src/` contains implementation files including `security.c`.
  - `inc/` contains shared headers.
  - `build.sh` is the container entrypoint invoked during `.hsm` image creation.
- `ectf26_design/`
  - Python package used to generate deployment secrets (`global.secrets`).
- `docs/`
  - Project documentation, including manual security test plans.
- `Makefile` (repo root)
  - Host-side helper targets for Docker build, secrets generation, and `.hsm` packaging.

## Prerequisites

Install the following on the host machine:

- Docker Desktop / Docker Engine (daemon running)
- `make`
- `uv` / `uvx` (for the `global.secrets` make target)
- Python 3 (optional fallback for direct secrets generation)

## Quick Start

1. Build firmware container image:

```bash
make docker
```

2. Generate global secrets for one or more group IDs:

```bash
make global.secrets GROUPS="0x1001 0x2002"
```

3. Build an HSM bundle directory (example target name: `hsm_a.hsm`):

```bash
make hsm_a.hsm PIN=111111 PERMS='1001=RWC:2002=R--:3003=--C'
```

4. Artifacts are placed in the output directory you named (`hsm_a.hsm/`), including:

- `hsm.elf`
- `hsm.bin`

## Permission String Format

`PERMS` is a colon-separated list of `<group>=<flags>` entries:

- Group ID: 16-bit hex without `0x` in normal usage (example: `1001`)
- Flags: 3 chars in `RWC` order using `-` for missing permission

Examples:

- `1001=RWC`
- `2002=R--`
- `3003=-W-`
- `4004=--C`

Combined:

```text
1001=RWC:2002=R--:3003=-W-:4004=--C
```

## Useful Make Targets

- `make docker`
- `make docker-nc` (no Docker cache)
- `make global.secrets GROUPS="..."`
- `make <name>.hsm PIN=<pin> PERMS='<perm string>'`
- `make clean`

## Manual Testing

Security-focused manual validation plan for `security.c` is tracked at:

- [`docs/security_c_manual_test_plan.md`](docs/security_c_manual_test_plan.md)

## Development Notes

- `firmware/src/security.c` is tightly coupled to:
  - `firmware/src/syscalls.c`
  - `firmware/src/commands.c`
  - `firmware/inc/security.h`
  - `firmware/inc/commands.h`
- Keep command struct sizes and packet lengths stable when modifying transfer paths.
- Re-run transfer and tamper scenarios after any crypto, nonce, or header-format changes.

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

## Troubleshooting

- `make: command not found`
  - Install `make` (or use WSL/Git Bash with build tools).
- Docker build fails with daemon/pipe errors
  - Start Docker Desktop and verify `docker version` works.
- `global.secrets` target fails due to `uvx`
  - Install `uv`, or generate secrets directly with:
    - `python ectf26_design/src/gen_secrets.py -f global.secrets 0x1001`

---

## License / Credits

* See `LICENSE.txt`.
* Original scaffolding derived from the MITRE eCTF 2026 insecure example repository; modified for our team’s design.
