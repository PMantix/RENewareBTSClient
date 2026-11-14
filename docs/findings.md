# Findings ledger

Tags: **Observed** = seen on this PC / on the wire / on hardware. **Inferred** = static RE.
Citations are relative to `vendor/decompiled/` unless a full path is given.

## Installation and architecture (2026-11-13)

- F-SYS-1 Observed: BTS Client 8.0.1.493 (`BTS.exe`, .NET Framework 4.5.2, x64) and
  BTS Server 8.0.1.437 (service `BtsServer`, `BtsServerNT.exe`, native C++, `.pdb` shipped)
  plus bundled MySQL (service `MySQL`, port 3306, datadir `BTSServer80\Data\`).
- F-SYS-2 Observed: `BtsServerNT` listens on TCP 8001 (all interfaces) and UDP 8002.
  Two cyclers are connected *into* the server: 192.168.1.35 -> 192.168.1.250:8001 and
  192.168.0.2 -> 192.168.0.250:8001. `BTS.exe` holds two connections to 127.0.0.1:8001.
  Both processes hold several MySQL connections.
- F-SYS-3 Observed: almost all client assemblies are .NET (MSIL) and decompile cleanly
  with ILSpy 7.2 (ilspycmd on .NET 6 runtime). Server `BtsServer.dll`, `Btsapi.dll`,
  `Network.dll` are native.
- F-SYS-4 Observed: client user config in `C:\Users\user\Documents\NEWARE\BTSClient\`
  (`BTS.ini`, `BTSAuto.ini`, `SysConfigParam.iconf` ...). `SysConfigParam.iconf` has
  `PortTCP=0`, `PortUDP=0`.
- F-SYS-6 Observed (user + NdcFile names, 2026-11-13): hardware is BT-4008 and CT-4008
  cyclers behind two middle machines (192.168.1.35, 192.168.0.2). All recent data files
  carry dev_uid 250035 or 250062, i.e. **devType 25 = BTS83**, devIDs 35 and 62
  (dev_uid = devType*10000 + devID, `Common/common/DevType.cs`). DevID 35 = 192.168.1.35, DevID 62 = 192.168.0.2 (F-CS-9).
  Consequence: we use the **legacy-proto path (BTS82-84)**: RT data 0x80D4 with RTData83
  (float volt/curr), GetDeviceInfo via Plus 0x0201 (DevInfo83), Jump 0x00EC
  (ProtocJump83), Start via CmdStart83 (0x00D1 step chunks of <=3500 B with
  `Step.EncodeBts80`/`StepItem.EncodeF`, then 0x00EB ProtocStart83). See
  `docs/protocol-clientserver.md` §3-4.
- F-SYS-5 Observed: the GUI refers to channels like `CHANNEL-127.0.0.1-25-35-4-8-671`
  (`BTSAuto.ini` DaCookie). Inferred: server IP, devType 25, devID 35, unit 4, channel 8,
  test id 671. NDC file names use the same `<devuid>_<unit>_<chl>_<testid>` order.

## Data at rest (passive monitoring candidates)

- F-DATA-1 Observed: BtsServer writes live test data to
  `C:\Program Files (x86)\NEWARE\BTSServer80\NdcFile\<yyyymmdd>\<yyyymmdd>_<hhmmss>_<dev>_<unit>_<chl>_<testid>.ndc`
  plus `_step.ndc` and `_runInfo.ndc`, updated during the run (files for tests started
  2026-11-11 had mtime 2026-11-13 10:20). ~21k files, 3.7 GB total.
- F-DATA-2 Inferred: the client reads these with native `NdcReader.dll` (classes
  `CNdcFileV11..V13+`) and C# wrappers `Common/Common.Ndc/NdcFile.cs`,
  `Common/Common.Nda/NdaFile.cs`. The `.ndc` format is the same as inside `.ndax`
  exports, which the open-source Python package `NewareNDA` parses. Lead for a
  zero-command monitor: read `.ndc` files with shared read access.
- F-DATA-3 Inferred: MySQL (`MySqlHelper.cs:171`, user/password from BTS config) holds test
  metadata, e.g. `h_test` (incl. `ndc_path`), `test_note`, `bts902_testinfo_h_*`,
  step tables. Live point data is not obviously in MySQL.

- F-DATA-4 Observed (2026-11-13): live NDC files are **version 11**. Per test:
  `<stem>.ndc` (filetype 1, V/I per point: `<ff` V*1e4 and mA, pages of 4096 B with 132 B
  page header), `_runInfo.ndc` (18: step time, capacity mAs, energy, dt, epoch timestamp,
  step, index; sparse, ~every 7th point), `_step.ndc` (7: cycle, step no, step type),
  plus `_log.ndc` (9) and `_es.ndc` (16), not yet decoded. NewareNDA's v11 layouts decode
  them correctly (plausible V/I, step sequence, timestamps). Implemented in `btsmon/ndc.py`.
- F-DATA-5 Observed: reading with `btsmon/safe_read.py` (CreateFileW, share
  read+write+delete, read-only) holds each handle 0.2-8 ms for 8-160 kB files. A full scan of
  30 days (32 channels, ~100 files) takes ~2.4 s.
- F-DATA-6 Observed: middle-machine clocks (devices 35 and 62) are ~1 h ahead of the PC
  (EST): NDC timestamps vs file mtime differ by +3400..+3650 s, the rest being the
  server's write lag. Probably DST not applied on the devices. Use relative times and
  file mtimes; don't trust device timestamps as wall-clock time.
- F-DATA-7 Observed: server flushes NDC files every few minutes (data age 3 min at scan),
  data interval 10 s on the running tests. NDC files do not say whether an ended test
  finished, was stopped or hit a protection (maybe in `_log.ndc`); a channel whose file
  stopped growing is only "not live".

- F-DATA-8 Observed (2026-11-13): `_log.ndc` (filetype 9, v11) = event log. 4096 B pages,
  132 B page header, 45 records of 88 B (3960 B). Record: `0` u8 0xAA, `1` u32 seq
  (gaps occur), `9` u8 step no, `11` u8 step type, `17` u32 step time ms, `25` f32 V*1e4,
  `29` f32 mA, `33` u16 log code, `69` u16 year + u8 month/day/hour/min/sec (device clock),
  `80` u32 data index. Other bytes not decoded. Log codes map to `LogCode.csv` in the client
  install (UTF-16; columns code, name, ..., event text (en) col 6, lamp col 7:
  -1 record, 0 tip, 1 warning, 2-4 error).
  Checked on four ended tests, matching their history: 62-4-2 `0x1B6` cut-off V jump ->
  `0x1B2` time jump -> `0x1 Finish` on the End step -> `0x285` status changed;
  62-4-6 `0x238` into CV -> `0x2 Stop`; 62-4-7 `0x186` "CC, exceeding voltage limit"
  (lamp 2) at 4.3603 V -> later `0xE4` user clear channel; 35-5-3 Finish.
  End state rule (`btsmon/logcodes.py`): last event ignoring 0x285/0xE4: Finish ->
  finished, Stop -> stopped, lamp >= 1 -> protect (+ reason), else unknown.
- F-DATA-9 Observed: 35-4-x tests record at 1 s intervals, 62-x-x at 10 s.

## XML API (see docs/api-xml-protocol.md)

- F-API-1 Inferred: `BTSAPI.dll` implements an XML-over-TCP API (default port 502,
  `#\r\n` terminator), plus named-pipe and WCF transports, hosted inside `BTS.exe`.
  `BTSAPI/BTS.PipeAPI/TCPApiManager.cs:21,27`.
- F-API-2 Inferred: the API only starts when the registration code enables
  `StartMode.API` (52). `BTSLib/BTS/MainFrame.cs:5799`. Observed: no registration code is
  stored on this PC (no `SOFTWARE\NEWARE` key in HKLM/HKCU, no `%TEMP%\NEWARE\BtsRegedit`);
  ports 502/9527/9528 not listening. **Getting a code from Neware is the legitimate route;
  do not bypass.**
- F-API-3 Inferred: the API is a thin wrapper over `Network.Client` methods
  (`SendStop`, `LookForChl`, ...) in `Network.dll`. `BTSAPI/BTS.PipeAPI/CommonInterface.cs`.
  So anything the API can do, the 8001 client protocol can do.
- F-API-4 Inferred: API `start` takes a step-file path on the BTS PC, loaded with
  `XmlStep.LoadStepFile`. `CommonInterface.cs:878`.

## Client <-> server protocol (see docs/protocol-clientserver.md)

- F-CS-1 Inferred: binary framed packets; receive path `Network/Network/OnLineEx.cs:165`.
  Command byte, with 0xFE/0xFF -> 16-bit extended cmd, 0x7F -> "plus" extended cmd;
  length field int16 at offset 10, valid range 15..4095. Some payloads are protobuf
  (`Proto.dll`, Google.ProtocolBuffers 2.x).
- F-CS-2 Inferred: main protocol client is `Network/Network/Client.cs` (~20k lines). The GUI
  creates one `Client` per server node (`BTSLib/BTS/MainFrame.cs:14807`).
- F-CS-3 Inferred: frame = `FF x8`, devID u8 @8, unitID u8 @9, total length u16 LE @10,
  cmd u8 @12, body, checksum u8 (8-bit sum of bytes 8..n-3), trailer `0x5A`
  (`NetworkBase/Network/Packet.cs`). Extended commands: client sends cmd 0xFE with u16
  cmdEx @13; response cmdEx = request | 0x8000. Login example:
  `FF FF FF FF FF FF FF FF 00 00 12 00 00 03 01 02 18 5A` (checksum verified by hand).
- F-CS-4 Inferred: three body styles on one socket: fixed C structs (legacy), u32-length
  protobuf (BTS82-84), "Plus" header+protobuf (BTS85, and on recent 8.0 servers also
  heartbeat/device list/subscribe). 131 `.proto` schemas recovered into `vendor/protos/`
  by `tools/dump_protos.py`.
- F-CS-5 Inferred: handshake = Login (0x00) -> server pushes version (0x0081, includes
  build date that gates features, and the MySQL credentials lightly obfuscated) ->
  GetDevList (Plus 0x021B) -> SelectDev (Plus 0x021F, this is the data subscription) ->
  channel layout -> heartbeat every 10 s (Plus 0x0211). Realtime data is then pushed
  unsolicited (0x80BE / 0x80D4 / Plus 0x0202 depending on devType).
- F-CS-6 Inferred: control: Stop 0x000A / Plus 0x0208, Continue 0x000D / Plus 0x0209,
  Jump 0x0070 / 0x00EC / Plus 0x020A. "Pause" from the GUI is a Stop that Continue can
  resume. Start is a multi-packet transaction keyed by a GUID; the step XML is re-encoded
  (`ProtoStep.Encode` or `Step.EncodeBts80`), never sent as-is.
- F-CS-7 Inferred (disassembly of `BtsServer.dll` 8.0.1.437 with `tools/disasm.py` +
  PDB publics from `tools/pdb_publics.py`, 2026-11-13): client registration is keyed by
  connection ID, not IP.
  - Signatures: `CManager::OnConnect(DWORD conn, char* ip, int port)`,
    `RegisterOnlineLogin(DWORD, char*, int)`, `OnRegClient(DWORD conn, std::string& ip,
    CBuffer*, u16 ver)`, `LookForClientBgs(DWORD)`, `UnRegisterClientBgs(DWORD, int)`,
    `OnDisconnect(DWORD, int)`.
  - `OnRegClient` (RVA 0x294660): erases the pending-login entry for *this* conn
    (map `this+0x168` keyed by conn, 0x2947BF); if `(ver & 0xFE00) == 0 && ver != 1`
    (old client) it does `inet_addr(ip)` (0x2947FB, the only IP use besides a log line),
    rate-limits a log message per IP for 60 s (map `this+0x1B0`) and rejects only that
    login (`UnRegisterOnlineLogin(conn)`, 0x294B4B). Otherwise it creates
    `CClient800(conn, ip, ver)` (0x294B76) and inserts it into the client map keyed by conn
    (0x294D1E/0x294D50), then `SendSvrVerToClient`. No `DelClient`, no lookup of
    existing clients by IP.
  - Observed: a 127.0.0.1 connection is accepted and closed every 30 s all day
    (`Networt*.log`) without affecting the GUI or tests.
- F-CS-8 **Observed** (2026-11-13, `captures/2026-11-13/probe_login.log`, report
  `reports/2026-11-13-first-login-probe.md`): first live session from our own client.
  Login `FF×8 00 00 12 00 00 03 01 02 18 5A` -> `FF×8 00 00 10 00 80 00 90 5A` (result 0),
  no credentials. Server then pushes 0x0081 (byte 12 0xFE, result 0xFF, 658 B):
  version 0x0802, svrVer `8.0.1.437 (2025.01.23)`. Plus heartbeat 0x0211 -> 0x8211 and
  get-device-list 0x021B -> 0x821B work as documented; Plus responses have byte 12 = 0xFF.
  Devices: devType 25, DevIDs 35 and 62, online, version 283. GUI, middle machines and all
  15 running channels unaffected. Server logs a benign error 10038 when we close abruptly.
- F-CS-9 **Observed** (2026-11-13, `captures/2026-11-13/probe_devices.log`, report
  `reports/2026-11-13-device-info-and-subscribe.md`): DevID 35 = 192.168.1.35,
  DevID 62 = 192.168.0.2 (Plus GetDeviceInfo 0x0201 -> 0x8201 `IP`, `DevInfo83` ~1.8 kB).
  GetDeviceInfo triggers a one-shot RT snapshot of the device; Plus SelectDev 0x021F
  (empty proto) starts 0x80D4 RTData83 frames for every unit of that device every 2.0 s.
  RTData83 units: Volt = V*1e4, Curr = mA, CCap/DCCap = mAs, TestTime = step time ms,
  StepType = NDC step-type codes, PrtCode = log code. WorkType 16 = running, 32 = stopped,
  0 = idle. Other pushes: 0x80E4 every 5 s (unit 0xFE), 0x80BF. No effect on the GUI or
  the 15 running channels. BtsServer logs `SessionDisconnect error 10038` whenever any
  client leaves (benign).
- Full detail with citations: `docs/protocol-clientserver.md` (its questions are P1-P10).
