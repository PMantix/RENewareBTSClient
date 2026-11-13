# Neware BTS built-in XML API (BTSAPI.dll)

All facts **Inferred** from static RE of `BTSAPI.dll` 8.0.1.19 ("BTSAPI(2025.01.23)") in
BTS Client 8.0.1.493 unless marked otherwise. Paths are relative to `vendor/decompiled/`.

## Where it runs and when it is enabled

- The API lives **inside the GUI client** (`BTS.exe`), not in BtsServer. It is a thin
  layer over the client's `Network.Client` objects (`BTSAPI/BTS.PipeAPI/CommonInterface.cs`,
  e.g. `OnStop` -> `client.SendStop(listChl, allowStopWhenPause)` at `:238`).
  So `BTS.exe` must be running for the API to work.
- Started in `MainFrame_Load` only when the registration code enables
  `SystemSet.StartMode.API` (= 52): `BTSLib/BTS/MainFrame.cs:5799`,
  enum at `Common/common/SystemSet.cs:226`. When enabled, three transports start
  together: named pipe (`PipeApiManager`), WCF (`WCFApiManager`,
  `net.tcp://localhost:9527/BTSService`, `http://localhost:9528/BTSService`), TCP
  (`TCPApiManager`).
- Registration code is read from `HKLM|HKCU\SOFTWARE\NEWARE\BTSClient8.0`
  (`RegeditCode`, `RegeditDate`) or `%TEMP%\NEWARE\BtsRegedit`
  (`BTSLib/BTS/MainFrame.cs:5867`). **Observed 2026-11-13:** none of these exist on this
  PC, so the API is off (nothing listens on 502/9527/9528).
- A separate `StartMode` 98 enables `ServerManager` ("C-lab API", `MainFrame.cs:5834`).

## TCP transport

- Port: `[NewareBtsTCP] Port=` in `<ConfigDir>\NewareBtsTCP.ini`, default **502**; created
  on first start with `PrintLog=0` (`TCPApiManager.cs:575-605`). Service-mode variant uses
  `NewareBtsAPIServer.ini`, default 9502.
- Listens on all interfaces (`ServerIp = ""`, `TCPApiManager.cs:55`).
- Framing: each message is an XML document terminated by **`#\r\n`** (`TCPApiManager.cs:27`).
  Requests decoded as UTF-8 (`:621`); responses encoded with `Encoding.Default` (ANSI code
  page; `:571`). Receive buffer is keyed per client IP.
- Envelope: `<?xml version="1.0" encoding="UTF-8" ?><bts version="1.0"><cmd>NAME</cmd>...</bts>`
  (`BTSAPI/BTS.PipeAPI/PacketBase.cs:53`). `cmd` is lower-cased before dispatch.
  Response cmd is `NAME_resp`.

## Channel addressing

Channel elements carry **attributes** (not child elements): `ip` (BtsServer IP as the client
knows it, here `127.0.0.1`), `devtype`, `devid`, `subdevid` (unit, display numbering),
`chlid` (display numbering). Inner text is a per-command flag/value.

## Commands (dispatcher: `TCPApiManager.cs:85-541`)

| cmd | Request body | Response | Notes |
|---|---|---|---|
| `connect` | `<username>`, `<password>`, `<type>` | `<result>ok</result>` | Handler always returns ok (`CommonInterface.cs:47`). |
| `getdevinfo` | none | `<client version=...>`, `<serverip count><server ip port version devCount><dev ip devid zwjVersion zwjGuid xwjCount><xwj id .../>`, `<middle count><channel ip devtype devid subdevid Channelid>true/false</channel>` | Inner true = channel allows the light command. Note the capital `Channelid` here. |
| `getchlstatus` | `<list><status ip devtype devid subdevid chlid>true</status>...` | `<list count><status ... reservepause="0/1">STATE</status>` | STATE: `working stop finish protect pause synCtrl ...` (`PacketBase.cs:97`). |
| `inquire` | `<list><inquire ip devtype devid subdevid chlid aux="N" barcode="0/1">true</inquire>` | per channel attrs: `dev cycle_id step_id step_type workstatus barcode current voltage capacity energy totaltime relativetime auxtemp auxvol open_or_close log_code`, plus aux `V{n} I{n} T{n} P{n}` | Live data. Step type codes in `PacketBase.cs:163`. |
| `start` | `<list><start ip devtype devid subdevid chlid barcode="...">C:\path\step.xml</start>...<backup backupdir remotedir filenametype customfilename .../></list>` | `start_resp` | **Inner text is a step-file path on the BTS PC**, loaded with `XmlStep.LoadStepFile` (`CommonInterface.cs:828,878`). |
| `stop` | `<list><stop ...>true</stop>` | `<stop ...>ok/false</stop>` | Only if `WorkType.AllowStop` (`CommonInterface.cs:185`). |
| `pause` / `continue` | `<list><continue ...>true</continue>` | `continue_resp` | |
| `goto` | see `PacketJump.cs` | `goto_resp` | Jump to step. |
| `reset` | see `PacketReset.cs` | `reset_resp` | Reset/modify steps of a running test. |
| `chl_ctrl`, `light`, `clearflag`, `resetalarm` | see Packet*.cs | `*_resp` | |
| `download`, `downloadlog`, `downloadsteplayer`, `inquiredf` | see Packet*.cs | | Historical data, logs, step-layer stats. |
| `parallel`, `getparallel`, `setpause`, `getpause`, `cancelpause`, `broadcaststop` | | | Reserve-pause, parallel channels. |

TODO (Phase 0): fill exact fields for goto/reset/download/inquiredf/downloadsteplayer.
