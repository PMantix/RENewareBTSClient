# Device info + realtime subscription (2026-11-13)

## Setup
Same as `2026-11-13-first-login-probe.md`. User watching the GUI. Tool
`tools/probe_devices.py` (allowlist: login, heartbeat, get-device-list, get-device-info,
select-device). Capture `captures/2026-11-13/probe_devices.log` (DB credentials redacted).

## What was run
21:00:54-21:01:55 local, one session to 127.0.0.1:8001: login; heartbeat; device list;
Plus GetDeviceInfo 0x0201 for DevID 35 (t=3.0 s) and 62 (t=4.6 s); Plus SelectDev 0x021F
for DevID 35 only (t=7.1 s); heartbeats every 10 s; graceful close at 60 s.
Packets: GetDeviceInfo 35 `FF×8 23 00 15 00 FE 01 02 19 02 00 00 54 5A`,
SelectDev 35 `FF×8 23 00 15 00 FE 1F 02 19 02 00 00 72 5A`.

## Results
- **Device to IP:** DevID 35 = **192.168.1.35**, DevID 62 = **192.168.0.2**
  (`TRespGetDeviceInfo.IP`). Each reply carries a `DevInfo83` of ~1.8 kB (channel map,
  not yet decoded); single frame, no chunking.
- **GetDeviceInfo also triggers a one-shot realtime snapshot** of every unit of that
  device (0x80D4, one frame per unit 1-5, 8 channels each).
- **SelectDev(35) starts a stream:** 0x80D4 for units 1-5 of device 35 every **2.0 s**
  (27 frames per unit in ~54 s). Device 62 (not selected) sent nothing further.
  SelectDev reply 0x821F result 0, empty proto.
- Other pushes after select: 0x80E4 every 5 s from dev 35 unit 0xFE (48 B, proto:
  DevType 25, DevID 35, ...), one 0x80BF (43 B). Not decoded yet.
- **RTData83 units (checked against btsmon at the same time):**
  `Volt` = V x 1e4 (37131 -> 3.7131 V), `Curr` = mA (13.57), `CCap`/`DCCap` = mAs
  (159390 -> 44.3 mAh), `TestTime` = step time in ms (11754700 -> 3.27 h on step 10).
  `StepID` = step number, `StepType` uses the NDC step-type codes (7 = CCCV_Chg,
  6 = End, 1 = CC_Chg). `PrtCode` = log/protection code (62-4-7: 390 = 0x186
  "CC, exceeding voltage limit", matches `_log.ndc`).
- **WorkType values seen:** 16 on all running channels, 32 on 62-4-6 (user-stopped),
  0 on idle/finished/protected-then-cleared channels.
- Idle channels report `Volt` noise from open terminals (e.g. +-0.01..4 V) or values like
  4.16 V on channels holding a cell; only meaningful with WorkType/step context.
- After: 15 running channels unchanged, GUI sessions and both middle machines
  unchanged. The server again logged `SessionDisconnect ... error 10038` on our close,
  even with a graceful half-close: this is the server's normal log line for a client
  leaving, not something we cause.

## New facts
All Observed, also in `docs/findings.md` F-CS-9.

## Problems
None.

## Next
- Decode `DevInfo83` (channel map, ranges) from the saved bytes (offline).
- Make a `btsmon` live source from the 0x80D4 stream (2 s data instead of ~3 min NDC lag).
- First control command (pause/continue) on a user-named free channel with no cell / a
  dummy load, with the user watching.
