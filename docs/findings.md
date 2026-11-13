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
- F-SYS-5 Observed: the GUI refers to channels like `CHANNEL-127.0.0.1-25-35-4-8-671`
  (`BTSAuto.ini` DaCookie); the meaning of each field is to be confirmed.

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
- F-CS-2 Inferred: main protocol client is `Network/Network/Client.cs` (~20k lines).
