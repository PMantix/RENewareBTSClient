# First control commands: pause and resume on 62-1-1 (2026-11-13)

## Setup
- Channel 62-1-1 (device 62 = 192.168.0.2, BTS83 5 V / 50 mA, unit 1, channel 1),
  **no cell connected** (user), open-terminal voltage 0.445 V.
- User started a single Rest step on 62-1-1 from the BTS GUI (test 140, files
  `20261113_211527_250062_1_1_140*`) and watched the GUI throughout.
- Tool `tools/control_test.py`: allowlist `config/test_channels.json` (62-1-1 only),
  live-state precondition, separate short session for the command, verification on the
  live feed. Logs: `captures/2026-11-13/control_*`.

## What was run
| Time | Action | Bytes sent | Reply |
|---|---|---|---|
| 21:13:58 | pause 62-1-1 while idle | nothing (refused: channel idle) | - |
| 21:15:51 | pause (legacy Stop 0x000A) | `FF×8 3E 01 1A 00 FE 0A 00 19 01 00 00 00 00 00 00 00 7B 5A` | `FF×8 3E 01 1B 00 FE 00 0A 80 19 01 00 00 00 00 00 00 00 FC 5A` (0x800A, result 0, devType 25, mask 0x1) in 6 ms |
| 21:16:51 | resume (Continue 0x000D) | `FF×8 3E 01 1A 00 FE 0D 00 19 01 00 00 00 00 00 00 00 7E 5A` | `FF×8 3E 01 1C 00 FE 00 0D 80 19 01 00 00 00 00 00 00 00 00 00 5A` (0x800D, result 0, mask 0x1, one extra 0 byte) in 11 ms |

Also, before the run, `control_test.py pause 35-4-1` was refused by the allowlist without
connecting.

## Results
- Pause: live WorkType 16 (running) -> 32 (stopped) within 2 s, step 1 kept. The **GUI
  showed 62-1-1 paused** (user).
- Resume: WorkType 32 -> 16 within 2 s, step 1. User confirmed the GUI before resuming.
- The server's event log (`_log.ndc`) recorded `0x8 Start` (GUI start) and `0x2 Stop`
  (our pause), same as a GUI pause. The resume event was not yet flushed at the time of
  writing.
- All other channels unchanged: the 15 real-cell channels kept running; 62-4-6 stayed
  stopped.
- Not done by us: the GUI's resume also writes the XWJ GUID for the test to MySQL
  (`MySql.UpdateXwjGuidInfo`, `Network/Network/Client.cs:8750-8790`). No visible effect.

## New facts
- Observed: legacy Stop 0x000A and Continue 0x000D work for BTS83 (devType 25) with header
  devID/unitID, body `devType u8, channel mask u64` (bit = ChlID-1). Responses
  0x800A/0x800D echo devType and mask; 0x800D has one extra trailing byte.
- Observed: "pause" on these devices = Stop, resumable by Continue; WorkType 32 in RT.
- Observed: the server log codes a client Stop as `0x2 Stop`.

## Problems
None.

## Next
- Close the test on 62-1-1 from the GUI when done (or leave it to end the rest step).
- Jump/goto (0x00EC ProtocJump83) and clear-flag next, same procedure.
- Start: port the step encoder (`Step.EncodeBts80` / `StepItem.EncodeF`) and the
  CmdStart83 transaction; verify offline against a GUI capture before any live start.
