>This repository is intended for the MITRE eCTF 2026 competition environment and depends on the eCTF tooling and board setup.

# eCTF 2026 University of Denver Design

This repository contains the University of Denver submission for the **MITRE eCTF 2026** Hardware Security Module (HSM) design challenge.
- eCTF 2026 rules: https://rules.ectf.mitre.org/
- Original insecure reference design: https://github.com/ectfmitre/2026-ectf-insecure-example/


## Layout

- `firmware/` - Source code to build the firmware
    - `Makefile` - This makefile is invoked by the eCTF tools when creating an HSM.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `secrets_to_c_header.py` - Python file to convert from global secrets to firmware-parsable header file
    - `inc/` - Directory with c header files
    - `src/` - Directory with c source files
    - `firmware.ld` - Original reference file for memory layout (not used)
    - `firmware_mod.ld` - Modified linker script defining the firmware memory layout
- `ectf26_design/` - Pip-installable module for generating secrets
    - `src/` - Secrets gen source code
        - `gen_secrets.py` - Generates shared secrets
    - `pyproject.toml` - File that tells pip how to install this module
- `insecure.out` - Bootloader to load built firmware
- `Makefile` - Helper script to simplify repetitive build steps
- `Design_Document.pdf` - Document explaining the design

## Design Summary

The implementation provides secure local file storage, access-controlled file operations, and protected file transfer between neighboring HSMs. The design uses an MPU-enforced split between unprivileged command handling and privileged security services, with sensitive material and protected storage accessible only through a constrained syscall interface. 

Files are encrypted at rest with AES-GCM under per-file keys derived from a device-local secret, while inter-device metadata and transfer control are protected using a deployment-shared secret, HMAC-SHA256, and nonce-derived session keys. The firmware also includes explicit software countermeasures against glitch and fault-injection attacks: critical authorization paths use hardened comparison barriers, capability consumption, and permission validation expressed through data operations rather than simple branch-based checks. 

Together, these mechanisms aim to provide confidentiality, integrity, and policy enforcement on a resource-constrained embedded platform. See `Design_Document.pdf` for more details.

## Build Notes

Standard setup, flashing, and host-tool usage follow the official MITRE eCTF 2026 workflow:
https://rules.ectf.mitre.org/2026/getting_started/boot_reference.html
