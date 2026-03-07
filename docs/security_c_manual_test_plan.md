# Security.c Manual Testing Plan (Rev B)

Last updated: March 7, 2026

## 1. Scope

This plan covers manual security and functional validation of:

- `firmware/src/security.c`
- Command paths that invoke security-critical code:
  - `LIST`
  - `READ`
  - `WRITE`
  - `INTERROGATE`
  - `RECEIVE`
  - `LISTEN`

Primary goals:

- Validate PIN and capability enforcement
- Validate `R/W/C` permission enforcement
- Validate local-at-rest encryption/decryption/integrity
- Validate transfer encryption/decryption/integrity
- Validate malformed/tampered packet handling
- Validate stability under repeated and faulted operation

## 2. Current Implementation Status

As of this revision:

- `secure_read_file_meta()` is implemented
- `secure_read_file_meta_for_transfer()` is implemented
- `INTERROGATE` path is testable end-to-end
- No known blockers in `security.c` for executing this plan

## 3. Environment and Equipment

- Two programmed HSMs: `HSM-A`, `HSM-B`
- Host with access to each control UART
- Transfer UART connected between A and B
- Optional MITM/proxy to modify transfer packets
- Optional debugger/flash tool for metadata tamper tests
- UART logging enabled on both control and transfer interfaces

## 4. Build and Provisioning

Example build/provision sequence:

```bash
make docker
make global.secrets GROUPS="1001 2002 3003 4004 5005"
make hsm_a.hsm PIN=111111 PERMS='1001=RWC:2002=R--:3003=-W-:4004=--C'
make hsm_b.hsm PIN=222222 PERMS='1001=RWC:2002=--C:3003=R--:5005=RWC'
```

Verify each device reaches `Ready` on control UART after boot.

## 5. Protocol Notes (Manual Injection)

- Packet format: `%` magic + `cmd` + `len` (little-endian `uint16`) + payload
- ACK exchange is required for non-debug traffic
- Command payload structs are packed in `commands.h`
- Expected error outputs are generated through `commands.c` mapping

## 6. Test Data Set

Use these files repeatedly:

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

Record each case as `Pass` or `Fail`.

| ID | Area | Procedure | Expected Result |
|---|---|---|---|
| SEC-001 | Boot baseline | Boot each HSM 3 times. | Clean boot, `Ready` seen every cycle. |
| SEC-002 | Crypto-init stability | Power cycle each HSM 10 times and monitor logs. | No init crash/hang; command handling remains functional. |
| SEC-003 | Invalid opcode handling | Send unknown command opcode on control UART. | Error returned; loop continues; subsequent valid command works. |
| SEC-010 | Valid PIN acceptance | Execute `WRITE`, `READ`, `INTERROGATE`, `RECEIVE` with correct PIN. | Commands proceed to normal auth/permission checks. |
| SEC-011 | Invalid PIN rejection | Repeat each command with wrong PIN. | `Invalid PIN` error; no persistent data changes. |
| SEC-012 | LISTEN capability path | Start `LISTEN`; send one remote request from peer. | Request processed; no PIN payload needed for `LISTEN`. |
| SEC-013 | `R` permission deny | Attempt `READ` on group lacking `R`. | `Permission failure`. |
| SEC-014 | `W` permission deny | Attempt `WRITE` on group lacking `W`. | `Permission failure`. |
| SEC-015 | `C` permission deny | Attempt `RECEIVE` for group lacking local `C`. | Receive rejected with permission error. |
| SEC-020 | Local crypto happy path | `WRITE` then `READ` (`F_SMALL`) same slot/group. | Exact name/content match. |
| SEC-021 | Local zero length | `WRITE`/`READ` `F_ZERO`. | Success with empty content. |
| SEC-022 | Local max length | `WRITE`/`READ` `F_MAX`. | Success with exact 8192-byte match. |
| SEC-023 | Boundary 1023 | `WRITE`/`READ` `F_1023`. | Success and exact match. |
| SEC-024 | Boundary 1025 | `WRITE`/`READ` `F_1025`. | Success and exact match. |
| SEC-025 | Slot bounds | Use slot `8` and `255` for `READ`/`WRITE`. | Clean reject, no corruption of valid slots. |
| SEC-026 | Local tag tamper | Flip stored `aes_gcm_tag` byte, then `READ`. | Integrity/decrypt failure; no plaintext output. |
| SEC-027 | Local IV tamper | Flip stored `aes_gcm_iv` byte, then `READ`. | Integrity/decrypt failure. |
| SEC-028 | Local persistence | Reboot after writes, then read back all written slots. | Data unchanged across reboot. |
| SEC-030 | Interrogate happy path | B in `LISTEN`; A runs `INTERROGATE`. | Encrypted metadata exchange succeeds; result list returned. |
| SEC-031 | Interrogate permission filtering | Compare A final list against A local `C` permissions. | Only `C`-permitted metadata entries remain. |
| SEC-032 | Interrogate tag tamper | MITM flips response `tag` byte. | Initiator rejects response. |
| SEC-033 | Interrogate nonce tamper | MITM alters response nonce field. | Initiator rejects response. |
| SEC-034 | Interrogate `data_len` too small | MITM sets `data_len < sizeof(uint32_t)`. | Initiator rejects response. |
| SEC-035 | Interrogate `data_len` too large | MITM sets `data_len > sizeof(list_response_t)`. | Initiator rejects response. |
| SEC-036 | Interrogate `data_len` mismatch | MITM keeps ciphertext valid but alters plaintext `n_files` vs `data_len` consistency. | Initiator rejects response. |
| SEC-037 | Interrogate oversized `n_files` | MITM crafts decrypted `n_files > MAX_FILE_COUNT`. | Initiator rejects response without crash. |
| SEC-040 | Receive happy path | B `LISTEN`; A `RECEIVE` from valid slot/group. | Transfer succeeds; A `READ` output equals B source file. |
| SEC-041 | Receive request signature tamper | MITM flips one byte in `permissions_sig`. | Responder rejects request. |
| SEC-042 | Receive request permissions tamper | MITM modifies permissions table without recomputing signature. | Responder rejects request. |
| SEC-043 | Receive response tag tamper | MITM flips one byte in response `tag`. | Initiator rejects response. |
| SEC-044 | Receive response IV tamper | MITM flips one byte in response `iv`. | Initiator rejects response. |
| SEC-045 | Receive ciphertext tamper | MITM flips encrypted payload byte. | Initiator rejects response; no stored plaintext accepted. |
| SEC-046 | Replay old transfer response | Replay prior valid response against new request nonce. | Replay rejected. |
| SEC-047 | Receive `data_len` too small | MITM sets response `data_len < UUID + file header`. | Initiator rejects immediately. |
| SEC-048 | Receive `data_len` too large | MITM sets response `data_len > sizeof(receive_response_t)` or > storage size. | Initiator rejects immediately. |
| SEC-049 | Receive `data_len` mismatch | Keep packet decryptable but alter embedded `contents_len` mismatch vs `data_len`. | Initiator rejects response. |
| SEC-050 | Responder local `W` policy | Remove responder local `W` permission on file group and retry transfer. | Responder rejects transfer by policy. |
| SEC-051 | Destination slot invalid | Execute `RECEIVE` with invalid destination slot. | Receive fails cleanly. |
| SEC-060 | ACK fault handling | Drop ACK(s) during long control/transfer packets. | Error path triggered; no permanent deadlock. |
| SEC-061 | Length mismatch handling | Send malformed header length/truncated payload. | Error path triggered; system remains responsive. |
| SEC-062 | Fuzz control channel | Send 500 random packets, then valid command sequence. | No crash/hang; valid commands still execute. |
| SEC-063 | Local stress loop | 100 cycles of random `WRITE` then `READ` hash verify. | Zero mismatches, no reset. |
| SEC-064 | Transfer stress loop | 50 full `RECEIVE` cycles with post-transfer hash verify. | Zero mismatches, no reset. |
| SEC-065 | Power-loss during local write | Interrupt power during `WRITE`, reboot, inspect slots. | Safe failure, no cross-slot corruption. |
| SEC-066 | Power-loss during transfer | Interrupt power mid-`RECEIVE`, reboot both, retry transfer. | Recovery without persistent lockup. |

### 7.1 Single-HSM CLI Step Sequence (Data-Dump Repro)

Use this exact sequence for a reproducible single-device sanity pass on `/dev/ttyACM2`.

Preconditions:

- In repo root: `~/Documents/2026-du-mitre-ectf`
- Device connected at `/dev/ttyACM2`
- Valid PIN: `abc123`
- Invalid PIN for negative case: `abc124`

1. Write baseline text file to slot 0 (covers `SEC-010`, `SEC-020`):
```bash
uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 README.md
```
Expected: `Write successful`.

2. Repeat with timing:
```bash
time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 README.md
```
Expected: `Write successful` (observed `real` about `0.75s`).

3. Generate max-size random file (`8192` bytes, `SEC-022`):
```bash
dd if=/dev/random of=randomfile.bin bs=1 count=8192
```
Expected: `8192 bytes` written.

4. Write `8192`-byte file to slot 0:
```bash
time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 randomfile.bin
```
Expected: `Write successful` (observed `real` about `2.00s`).

5. Generate oversized file (`8193` bytes) for length rejection:
```bash
dd if=/dev/random of=randomfile.bin bs=1 count=8193
```
Expected: `8193 bytes` written.

6. Attempt oversized write (length reject path):
```bash
time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 randomfile.bin
```
Expected: `HSM failed ... Illegal name or content length`.

7. Attempt write with invalid PIN (`SEC-011`):
```bash
time uvx ectf tools /dev/ttyACM2 write abc124 0 0x1111 randomfile.bin
```
Expected: `HSM failed ... Invalid PIN`.

8. Restore slot 0 with README baseline:
```bash
time uvx ectf tools /dev/ttyACM2 write abc123 0 0x1111 README.md
```
Expected: `Write successful`.

9. Trigger CLI read argument validation:
```bash
time uvx ectf tools /dev/ttyACM2 read
```
Expected: usage error indicating missing argument `PIN`.

10. Attempt read to non-existent output directory:
```bash
time uvx ectf tools /dev/ttyACM2 read abc123 0 dump/
```
Expected: `FileNotFoundError` for `dump/README.md`.

11. Create output directory and retry read:
```bash
mkdir dump
time uvx ectf tools /dev/ttyACM2 read abc123 0 dump/
```
Expected: `Read successful. Wrote file to .../dump/README.md`.

12. Verify round-trip integrity for README (`SEC-020`):
```bash
diff dump/README.md README.md
```
Expected: no output.

13. Generate new `8192`-byte random file and write to slot 1:
```bash
dd if=/dev/random of=randomfile.bin bs=1 count=8192
time uvx ectf tools /dev/ttyACM2 write abc123 1 0x1111 randomfile.bin
```
Expected: write succeeds.

14. List entries (`SEC-010` list path):
```bash
time uvx ectf tools /dev/ttyACM2 list abc123
```
Expected includes:
- `Found file: Slot 0, Group 1111, README.md`
- `Found file: Slot 1, Group 1111, randomfile.bin`
- `List successful`

15. Read back slot 1 and verify (`SEC-022`):
```bash
time uvx ectf tools /dev/ttyACM2 read abc123 1 dump/
diff dump/randomfile.bin randomfile.bin
```
Expected: read succeeds; `diff` has no output.

16. Re-write slot 1 twice (stability check):
```bash
dd if=/dev/random of=randomfile.bin bs=1 count=8192
time uvx ectf tools /dev/ttyACM2 write abc123 1 0x1111 randomfile.bin
time uvx ectf tools /dev/ttyACM2 write abc123 1 0x1111 randomfile.bin
```
Expected: both writes succeed.

17. Read slot 1 again without cleaning output:
```bash
time uvx ectf tools /dev/ttyACM2 read abc123 1 dump/
```
Expected: `FileExistsError` for `dump/randomfile.bin`.

18. Clear `dump/` and re-read slot 1:
```bash
rm dump/*
time uvx ectf tools /dev/ttyACM2 read abc123 1 dump/
```
Expected: read succeeds and writes `dump/randomfile.bin`.

19. Final read of slot 0:
```bash
time uvx ectf tools /dev/ttyACM2 read abc123 0 dump/
```
Expected: read succeeds and writes `dump/README.md`.

## 8. Evidence to Collect Per Test

For each test:

1. Test ID and timestamp
2. Firmware build identity (hash/tag)
3. HSM permission config for both devices
4. Exact command and payload details
5. UART logs for request/response
6. Result (`Pass`/`Fail`) and defect ID on failure

## 9. Pass/Fail Criteria

- `Pass`: observed behavior exactly matches expected result
- `Fail`: authorization bypass, tamper accepted, corruption, crash/reset/hang, or mismatch

## 10. Exit Criteria

Campaign completes when:

1. All positive-path cases pass
2. All tamper/malformed-input cases are rejected safely
3. Stress/fault cases show no persistent instability
4. Any critical failure is fixed and fully retested

## 11. Recommended Execution Order

1. Baseline and PIN/capability tests (`SEC-001` to `SEC-015`)
2. Local storage crypto tests (`SEC-020` to `SEC-028`)
3. Interrogate metadata tests (`SEC-030` to `SEC-037`)
4. Receive transfer tests (`SEC-040` to `SEC-051`)
5. Robustness/stress/fault tests (`SEC-060` to `SEC-066`)
