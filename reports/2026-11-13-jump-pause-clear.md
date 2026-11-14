# Jump, pause and clear-flag on 62-1-1 (2026-11-13)

## Setup
62-1-1 (device 62, BTS83 5 V / 50 mA, unit 1, channel 1), **no cell**. User started a
2 x Rest schedule from the GUI (test 141, files `20261113_213045_250062_1_1_141*`) and
confirmed the GUI after each command. Tool `tools/control_test.py` (allowlist
`config/test_channels.json`, live-state precondition, live verification). Logs in
`captures/2026-11-13/control_*`.

Before this, three jump attempts were refused by the state guard without sending
(21:26, 21:28, 21:29): 62-1-1 was idle. The user had cleared the previous test in the
GUI at 21:25 and first started the new schedule on 35-1-1 by mistake (not allowlisted, untouched).

## What was run
| Time | Command | Sent | Reply | Live result |
|---|---|---|---|---|
| 21:31:03 | jump to step 2 (PacketProto 0x00EC ProtocJump83) | `FF×8 3E 01 1F 00 FE EC 00 0A 00 00 00 08 19 10 3E 18 01 20 01 28 02 25 5A` | `0x80EC` result 0, proto `{DevType 25, DevID 62, UnitID 1, Result 0, Channel 1}` | step 1 (17 s) -> step 2 (0.6 s); GUI showed step 2 |
| 21:33:02 | pause (0x000A) | `FF×8 3E 01 1A 00 FE 0A 00 19 01 00.. 7B 5A` | `0x800A` result 0 | running -> stopped at step 2, 118 s; GUI showed paused |
| 21:34:03 | clear flag (0x0097) | `FF×8 3E 01 1A 00 FE 97 00 19 01 00.. 08 5A` | `0x8097` result 0, mask 0x1 | stopped -> idle |

Server event log (`_log.ndc`, device clock +1 h): `0x8 Start` (GUI), `0x4 Jump` at step 1,
`0x2 Stop` at step 2, `0xE4 User clear channel`, each followed by `0x285`.

## Results
All three commands accepted and effective on the first try. 15 real-cell channels
unaffected throughout; 62-4-6 still stopped.

## New facts (Observed)
- Jump for BTS83: PacketProto cmdEx 0x00EC, header devID/unitID, body `u32 len` +
  proto2 ProtocJump83 {1 DevType, 2 DevID, 3 UnitID, 4 Channel mask (int64), 5 StepID}.
  StepID = schedule step number as shown in the GUI. Response 0x80EC = ProtocJump83Resp
  {DevType, DevID, UnitID, Result, Channel}. Logged by the server as `0x4 Jump`.
- Clear flag for BTS83: legacy 0x0097, body devType u8 + channel mask u64, allowed from
  stopped/protect/pause; leaves the channel idle (RT WorkType 0); logged as `0xE4`.

## Next
Start: port the step encoder and the CmdStart83 transaction, verify offline against a
capture of the GUI starting the same schedule, then a live start on 62-1-1.
