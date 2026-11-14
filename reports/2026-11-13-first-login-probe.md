# First live connection to BtsServer: login + device list (2026-11-13)

## Setup
- Lab PC (also RE PC), BTS Client 8.0.1.493 GUI running and connected, BTS Server
  8.0.1.437, two BTS83 middle machines (192.168.1.35, 192.168.0.2), 15 channels running
  real cells. User watching the GUI throughout.
- Tool: `tools/probe_login.py` (hard allowlist: login, Plus heartbeat, Plus get-device-list
  only). Capture: `captures/2026-11-13/probe_login.log` (DB credentials redacted).

## What was run
20:56:08-20:56:38 local, one TCP session to 127.0.0.1:8001:
1. t=0 s login `FF×8 00 00 12 00 00 03 01 02 18 5A`
2. t=2 s heartbeat (counter 0), t=3 s get-device-list (`ClientVersion="8.0.1.493"`),
   t=12/22 s heartbeat (counter 1, 2)
3. t=30 s close.
Before/after: `btsmon.monitor` JSON snapshots and `Get-NetTCPConnection` on port 8001.

## Results
- Login answered immediately: `FF×8 00 00 10 00 80 00 90 5A` (cmd 0x80, result 0). No
  user/password needed.
- Unsolicited server-version push right after login: layout D, cmd 0xFE... byte 12 = `0xFE`,
  **result byte 0xFF**, cmdEx 0x0081, frame length 658. `version=0x0802`,
  `svrVer="8.0.1.437 (2025.01.23)"` (note the space before the parenthesis), svrGuid,
  sysVer "Microsoft Windows 10", computer name; DB user/password fields present
  (redacted here).
- Heartbeat responses `0x8211` (byte 12 = `0xFF`, result 0) carry: counter (field 1, omitted
  when 0), disk letter/total/free MB for two roots (fields 6-11: 'C', 463332, ~93275),
  one field-14 entry per device `{1: devType 25, 2: devID, 3: epoch seconds (PC clock),
  4: ?, 5: ?}`, and system stats in fields 15-18. Full meaning per `.proto` TRespClientHeart.
- Device list `0x821B`: `Devs = [{DevType 25, DevID 35, OnLineStatus 1, Version 283},
  {DevType 25, DevID 62, OnLineStatus 1, Version 283}]`, no abnormal devices.
- No unsolicited realtime data (expected: we never selected a device).
- Server network log: accept socket 588 at 20:56:08, close at 20:56:38, then
  `CCompletionPort::SessionDisconnect(): shutdown(...) == SOCKET_ERROR, error(10038)`.
- After: 15 channels still running, no state change on any channel; the GUI's two
  sessions (127.0.0.1:50166/50168) and both middle machines unchanged. User saw nothing
  in the GUI.

## New facts
- Observed: framing, checksum and login exactly as documented (F-CS-3); the server
  accepts a third client alongside the GUI without affecting it (confirms Q4).
- Observed: no credentials needed beyond the connect packet (answers P3).
- Observed: server version string format `8.0.1.437 (2025.01.23)`, version u16 0x0802
  (answers P2; note the space — check the client's date parser handles it).
- Observed: Plus responses use byte 12 = 0xFF (answers half of P1).
- Observed: both devices are devType 25, DevIDs 35 and 62, online, version 283.

## Problems
- Server logs error 10038 on close of our session. Benign (same message appeared 4×
  earlier today with the GUI's own probes), but next time half-close gracefully
  (`shutdown(SHUT_WR)`, drain, then close).

## Questions for the RE side
- Which middle-machine IP is DevID 35 vs 62: answered by Plus GetDeviceInfo 0x0201
  (`TRespGetDeviceInfo.IP`), read-only, next session.
