# Security.c Manual Testing Plan

Last updated: March 3, 2026

## 1. Scope

This plan covers manual security and functional validation of:

- `firmware/src/security.c`
- Command entry points that exercise security paths:
  - `LIST`
  - `READ`
  - `WRITE`
  - `INTERROGATE`
  - `RECEIVE`
  - `LISTEN`

Focus areas:

- PIN validation and one-time capability handling
- Permission checks (`R/W/C`)
- Local file encrypt/decrypt flow
- Transfer encryption/decryption and integrity checks
- Negative/tamper handling
- Stability under malformed packets and stress

## 2. Known Blockers (Current Codebase)

1. `secure_read_file_meta()` is declared and called, but missing implementation in `security.c`.
2. `secure_read_file_meta_for_transfer()` is incomplete and currently returns failure (`TODO` path).

Mark impacted tests as `Blocked` until fixed.

## 3. Environment and Equipment

- Two programmed HSMs (`HSM-A`, `HSM-B`)
- Host machine with UART access to:
  - Control UART for each HSM
  - Transfer UART between HSMs
- Optional MITM UART proxy/injector for transfer tamper tests
- Optional debugger/flash tool (for direct metadata tamper tests)
- Full UART log capture enabled

## 4. Build and Provisioning

Example setup:

```bash
make docker
make global.secrets GROUPS="1001 2002 3003 4004 5005"
make hsm_a.hsm PIN=111111 PERMS='1001=RWC:2002=R--:3003=-W-:4004=--C'
make hsm_b.hsm PIN=222222 PERMS='1001=RWC:2002=--C:3003=R--:5005=RWC'
```

Ensure both devices boot and emit `Ready` on control UART.

## 5. Protocol Notes (For Manual Injection)

- Packet format: `%` magic + `cmd` + `len` (uint16 little-endian) + payload
- ACKs are required on non-debug traffic per `host_messaging.c`
- Command payload structures are packed (`#pragma pack(push, 1)`) in `commands.h`

## 6. Test Data Set

Use these files repeatedly across tests:

- `F_SMALL` = 16 bytes
- `F_1023` = 1023 bytes
- `F_1025` = 1025 bytes
- `F_ZERO` = 0 bytes
- `F_MAX` = 8192 bytes

Example names:

- `a.txt`
- `p1023.bin`
- `p1025.bin`
- `zero.bin`
- `max.bin`

## 7. Manual Test Cases

Status values to record: `Pass`, `Fail`, `Blocked`.

| ID | Area | Procedure | Expected Result |
|---|---|---|---|
| SEC-001 | Build/boot | Flash both devices and reboot each 3 times. | Boots cleanly; emits `Ready`; no init crash. |
| SEC-002 | Crypto init robustness | Reboot each device 10 times and watch debug/error output. | No crypto-init failure messages; stable boot every cycle. |
| SEC-003 | Invalid command | Send unsupported opcode over control UART. | Error returned; device remains responsive. |
| SEC-010 | Valid PIN path | Run `WRITE`, `READ`, `RECEIVE`, `INTERROGATE` with correct PINs. | Command-specific success path reached. |
| SEC-011 | Invalid PIN path | Repeat each command with wrong PIN. | `Invalid PIN`; no operation occurs. |
| SEC-012 | LISTEN pin bypass behavior | Invoke `LISTEN` and send one remote request. | LISTEN works without PIN payload and handles one request. |
| SEC-013 | Read permission deny | Create file in group without `R`, then `READ`. | `Permission failure`. |
| SEC-014 | Write permission deny | Attempt `WRITE` into group without `W`. | `Permission failure`. |
| SEC-015 | Receive permission deny | Transfer file whose group receiver lacks `C` for. | Receive rejected with permission error. |
| SEC-020 | Local crypto happy path | `WRITE` then `READ` same slot (`F_SMALL`). | Name and bytes match exactly. |
| SEC-021 | Zero-length local file | `WRITE`/`READ` `F_ZERO`. | Success; empty contents returned. |
| SEC-022 | Max local size | `WRITE`/`READ` `F_MAX`. | Success; exact 8192-byte match. |
| SEC-023 | Boundary 1023 | `WRITE`/`READ` `F_1023`. | Success and exact match. |
| SEC-024 | Boundary 1025 | `WRITE`/`READ` `F_1025`. | Success and exact match. |
| SEC-025 | Slot bounds | Try slot `8` and `255` on read/write. | Error; no file change in valid slots. |
| SEC-026 | Local tag tamper | Flip one byte of stored `aes_gcm_tag`, then `READ`. | Integrity/decrypt error; no plaintext output. |
| SEC-027 | Local IV tamper | Flip one byte of stored `aes_gcm_iv`, then `READ`. | Integrity/decrypt error. |
| SEC-028 | Local persistence | Reboot after writes; re-read all slots used. | Data unchanged and readable. |
| SEC-030 | Interrogate baseline | B in `LISTEN`; A issues `INTERROGATE`. | Blocked/fails until `secure_read_file_meta_for_transfer` is implemented. |
| SEC-031 | Interrogate permission filter | After blocker fix, compare returned list vs local `C` perms. | Only `C`-permitted entries remain. |
| SEC-032 | Interrogate tag tamper | MITM flips response `tag` byte. | Request rejected by initiator. |
| SEC-033 | Interrogate nonce tamper | MITM changes metadata response nonce. | Request rejected by initiator. |
| SEC-034 | Interrogate list size tamper | MITM manipulates decrypted `n_files` to oversized value. | Rejected; no overflow/crash. |
| SEC-040 | Receive happy path | B `LISTEN`; A `RECEIVE` from valid source slot/group. | Transfer succeeds; A local read matches B source content. |
| SEC-041 | Request signature tamper | MITM flips one byte in `permissions_sig` in transfer request. | Responder rejects request. |
| SEC-042 | Response tag tamper | MITM flips one byte in `receive_response_enc.tag`. | Initiator rejects response. |
| SEC-043 | Response IV tamper | MITM flips one byte in `receive_response_enc.iv`. | Initiator rejects response. |
| SEC-044 | Ciphertext tamper | MITM flips encrypted file payload byte. | Integrity failure; no accepted write. |
| SEC-045 | Replay protection | Replay old valid transfer response against fresh request nonce. | Replay rejected. |
| SEC-046 | Header group tamper | MITM alters plaintext group in transfer payload to permitted group. | Must reject; if accepted, log critical defect. |
| SEC-047 | Length tamper | MITM inflates transfer `contents_len` beyond allowed range. | Must reject without crash/hang/reset. |
| SEC-048 | Responder policy check | Remove responder local `W` permission and retry transfer of existing file. | Should reject by policy; if allowed, log security defect. |
| SEC-049 | Destination slot invalid | Receive into invalid destination slot. | Receive fails cleanly; no unintended writes. |
| SEC-060 | ACK fault handling | Drop ACKs during large control/transfer packets. | Graceful error; no persistent deadlock. |
| SEC-061 | Length mismatch handling | Send malformed packet length/truncated payload. | Error path triggered; device remains usable. |
| SEC-062 | Fuzz control channel | Send 500 random packets, then valid commands. | No crash/hang; valid commands still work. |
| SEC-063 | Local stress loop | 100 cycles of random `WRITE` then `READ` verify hash. | Zero mismatches; no reset. |
| SEC-064 | Transfer stress loop | 50 receive transfers with post-read hash verification. | Zero mismatches; no reset. |
| SEC-065 | Power-loss during write | Cut power mid-`WRITE`, reboot, inspect target + neighboring slots. | No cross-slot corruption; safe failure behavior. |
| SEC-066 | Power-loss during receive | Cut power mid-transfer, reboot both, retry. | System recovers; normal operations resume. |

## 8. Evidence to Collect Per Test

For every test run, capture:

1. Test ID and timestamp
2. Firmware image/hash and permission configuration on both devices
3. Exact command payload values used
4. Raw UART request/response logs
5. Final status (`Pass`, `Fail`, `Blocked`)
6. Defect ticket ID for failures

## 9. Pass/Fail Criteria

- `Pass`: observed behavior matches expected result exactly.
- `Fail`: wrong response, unauthorized success, data mismatch, crash/reset, or hang.
- `Blocked`: cannot execute due to known code blockers or missing tooling.

## 10. Exit Criteria

Test campaign is complete when:

1. All non-blocked positive-path tests pass.
2. All non-blocked tamper tests reject malformed or malicious data safely.
3. Stress tests show no corruption, crashes, or hangs.
4. Any critical failure (tamper accepted, unauthorized access, crash on malformed input) is fixed and retested.

## 11. Suggested Execution Order

1. Baseline setup and boot tests (`SEC-001` to `SEC-003`)
2. PIN/capability/permission tests (`SEC-010` to `SEC-015`)
3. Local crypto/read-write tests (`SEC-020` to `SEC-028`)
4. Transfer/interrogate tests (`SEC-030` to `SEC-049`)
5. Robustness and stress tests (`SEC-060` to `SEC-066`)


```
Test Data Dump

┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 README.md 
Write successful
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 README.md
Write successful

real    0.75s
user    0.33s
sys     0.05s
cpu     51%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ dd if=/dev/random of=randomfile.bin bs=1 n=8192 
dd: unrecognized operand 'n=8192'
Try 'dd --help' for more information.
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ dd if=/dev/random of=randomfile.bin bs=1 count=8192 
8192+0 records in
8192+0 records out
8192 bytes (8.2 kB, 8.0 KiB) copied, 0.0322007 s, 254 kB/s
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ ls    
build  ectf26_design  global.secrets  LICENSE.txt  randomfile.bin  renode
docs   firmware       insecure.out    Makefile     README.md
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 randomfile.bin 
Write successful

real    2.00s
user    0.36s
sys     0.04s
cpu     19%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ dd if=/dev/random of=randomfile.bin bs=1 count=8193                  
8193+0 records in
8193+0 records out
8193 bytes (8.2 kB, 8.0 KiB) copied, 0.0332416 s, 246 kB/s
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 randomfile.bin
HSM failed with error: Message(opcode=<Opcode.ERROR: 69>, body=b'Illegal name or content length')

real    1.18s
user    0.33s
sys     0.07s
cpu     33%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc124 0 0x1111 randomfile.bin
HSM failed with error: Message(opcode=<Opcode.ERROR: 69>, body=b'Invalid PIN')

real    5.14s
user    0.35s
sys     0.04s
cpu     7%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 README.md     
Write successful

real    0.79s
user    0.34s
sys     0.05s
cpu     49%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read                           
Usage: ectf tools PORT read [OPTIONS] PIN SLOT READ_FILE_PATH
Try 'ectf tools PORT read --help' for help.
╭─ Error ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Missing argument 'PIN'.                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

real    0.42s
user    0.38s
sys     0.05s
cpu     101%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read abc123 0 dump/
╭──────────────────────────────────────── Traceback (most recent call last) ─────────────────────────────────────────╮
│ /home/du-student/.cache/uv/archive-v0/RoC6Q-NM_FOehK1VPvFMA/lib/python3.12/site-packages/ectf/tools/cli.py:101 in  │
│ read                                                                                                               │
│                                                                                                                    │
│    98 │                                                                                                            │
│    99 │   # Write the results to a file                                                                            │
│   100 │   full_path = read_file_path / name.decode("utf-8")                                                        │
│ ❱ 101 │   with Path.open(full_path, "wb" if force else "xb") as f:                                                 │
│   102 │   │   f.write(contents)                                                                                    │
│   103 │                                                                                                            │
│   104 │   success(f"Read successful. Wrote file to {full_path.absolute()!s}")                                      │
│                                                                                                                    │
│ /home/du-student/.local/share/uv/python/cpython-3.12.11-linux-x86_64-gnu/lib/python3.12/pathlib.py:1013 in open    │
│                                                                                                                    │
│   1010 │   │   """                                                                                                 │
│   1011 │   │   if "b" not in mode:                                                                                 │
│   1012 │   │   │   encoding = io.text_encoding(encoding)                                                           │
│ ❱ 1013 │   │   return io.open(self, mode, buffering, encoding, errors, newline)                                    │
│   1014 │                                                                                                           │
│   1015 │   def read_bytes(self):                                                                                   │
│   1016 │   │   """                                                                                                 │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
FileNotFoundError: [Errno 2] No such file or directory: 'dump/README.md'

real    0.77s
user    0.48s
sys     0.04s
cpu     68%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ mkdir dump           
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read abc123 0 dump/
Read successful. Wrote file to /home/du-student/Documents/2026-du-mitre-ectf/dump/README.md

real    0.84s
user    0.53s
sys     0.08s
cpu     72%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ diff dump/README.md README.md 
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ dd if=/dev/random of=randomfile.bin bs=1 count=8192                  
8192+0 records in
8192+0 records out
8192 bytes (8.2 kB, 8.0 KiB) copied, 0.0332666 s, 246 kB/s
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 1 0x1111 randomfile.bin
Write successful

real    2.00s
user    0.34s
sys     0.05s
cpu     19%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 list abc123                         
Found file: Slot 0, Group 1111, README.md
Found file: Slot 1, Group 1111, randomfile.bin
List successful

real    0.49s
user    0.34s
sys     0.05s
cpu     81%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read abc123 1 dump/                 
Read successful. Wrote file to /home/du-student/Documents/2026-du-mitre-ectf/dump/randomfile.bin

real    1.85s
user    0.36s
sys     0.07s
cpu     23%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ diff dump/randomfile.bin randomfile.bin             
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ dd if=/dev/random of=randomfile.bin bs=1 count=8192                  
8192+0 records in
8192+0 records out
8192 bytes (8.2 kB, 8.0 KiB) copied, 0.0396318 s, 207 kB/s
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 1 0x1111 randomfile.bin
Write successful

real    2.01s
user    0.35s
sys     0.04s
cpu     19%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 write abc123 1 0x1111 randomfile.bin
Write successful

real    2.03s
user    0.34s
sys     0.06s
cpu     19%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read abc123 1 dump/      
╭──────────────────────────────────────── Traceback (most recent call last) ─────────────────────────────────────────╮
│ /home/du-student/.cache/uv/archive-v0/RoC6Q-NM_FOehK1VPvFMA/lib/python3.12/site-packages/ectf/tools/cli.py:101 in  │
│ read                                                                                                               │
│                                                                                                                    │
│    98 │                                                                                                            │
│    99 │   # Write the results to a file                                                                            │
│   100 │   full_path = read_file_path / name.decode("utf-8")                                                        │
│ ❱ 101 │   with Path.open(full_path, "wb" if force else "xb") as f:                                                 │
│   102 │   │   f.write(contents)                                                                                    │
│   103 │                                                                                                            │
│   104 │   success(f"Read successful. Wrote file to {full_path.absolute()!s}")                                      │
│                                                                                                                    │
│ /home/du-student/.local/share/uv/python/cpython-3.12.11-linux-x86_64-gnu/lib/python3.12/pathlib.py:1013 in open    │
│                                                                                                                    │
│   1010 │   │   """                                                                                                 │
│   1011 │   │   if "b" not in mode:                                                                                 │
│   1012 │   │   │   encoding = io.text_encoding(encoding)                                                           │
│ ❱ 1013 │   │   return io.open(self, mode, buffering, encoding, errors, newline)                                    │
│   1014 │                                                                                                           │
│   1015 │   def read_bytes(self):                                                                                   │
│   1016 │   │   """                                                                                                 │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
FileExistsError: [Errno 17] File exists: 'dump/randomfile.bin'

real    1.98s
user    0.49s
sys     0.06s
cpu     27%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ rm dump/*            
zsh: sure you want to delete all 2 files in /home/du-student/Documents/2026-du-mitre-ectf/dump [yn]? y
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read abc123 1 dump/
Read successful. Wrote file to /home/du-student/Documents/2026-du-mitre-ectf/dump/randomfile.bin

real    1.83s
user    0.36s
sys     0.06s
cpu     22%
                                                                                                                      
┌──(du-student㉿DU-kali)-[~/Documents/2026-du-mitre-ectf]
└─$ time uvx ectf tools /dev/ttyACM2 read abc123 0 dump/
Read successful. Wrote file to /home/du-student/Documents/2026-du-mitre-ectf/dump/README.md

real    0.64s
user    0.35s
sys     0.05s
cpu     62%
```