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
  (dev_uid = devType*10000 + devID, `Common/common/DevType.cs`). Which IP is which devID is
  not yet known (server logs don't say; the device-list reply will).
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
- Full detail with citations: `docs/protocol-clientserver.md` (its questions are P1-P10).
