# Open questions

Each entry: status (`open`/`answered`), what is needed, what it blocks.

## Q1 (open): API registration code from Neware
The XML API is gated by `StartMode.API` (52) in the BTS registration code (F-API-2).
Ask Neware support for: (a) the BTS 8.0 API protocol document, (b) a registration code
that enables "API" for this PC's client (they may need the machine/serial code shown in the
client's registration dialog, `Step/Steps/RegeditWnd.cs`). User asked Neware for the doc
on 2026-11-13; no reply yet. Blocks transport option 2a only.

## Q2 (open): which test channels are free
User says there are plenty. Needed: an explicit list (devid/unit/channel as shown in the
GUI) for `config/test_channels.json`, and whether a dummy load/resistor or spare cell is
on them. Blocks Phase 3.

## Q3 (open): can Neware's `Network.Client` be hosted outside BTS.exe?
If `Network.dll`/`Common.dll` can be loaded from our own process (pythonnet on .NET
Framework 4.x, or a small C# host) and `Client` connected to 127.0.0.1:8001 without the GUI,
we reuse Neware's tested protocol code instead of reimplementing it. Need to check its
dependencies on GUI state, MySQL, SysConfigParam. Blocks transport option 2b.

Partial (Inferred, 2026-11-13): looks promising. `Network.Client` has a plain constructor
`Client(string strIP, object parent, ClientVersion ver = client801, bool bStart = true)`
(`Network/Network/Client.cs:7681`), no WinForms references in `Network/Network/*.cs`, and
public methods such as `SendStartStep(List<Channel>, Common.Step, SysConfigParam, ...)`
(`:17890`), `SendResetStep` (`:9057`), `SendStop` (used by the API). It needs a user login
(`_isUserLogin`; `Client.cs:7686`) and the server pushes DB credentials to it
(`MySqlHelper.SetUserInfo`, `Client.cs:7017`). Still to check: static init the GUI does
before creating a Client (`BTS.ClientVersion`, language resources, `SysConfigParam` load).

## Q5 (open): protocol details P1-P10
Listed in `docs/protocol-clientserver.md` §6. The most important are P9 (which device
types are attached; decides legacy vs Plus code path), P8 (step encoder for start), and
P3 (whether login needs credentials). Most can be answered from one passive look at the
device list, or from the PDBs.

## Q4 (answered 2026-11-13, Inferred from disassembly): does BtsServer allow a second client connection safely?

**Answer: yes at registration level.** Client sessions are keyed by the server's
per-connection ID, not by IP, so a second client from 127.0.0.1 does not replace or evict
the GUI's session. See findings F-CS-7 for the disassembly. Remaining risk is in what a
client *does* after login (control commands, channel locks), not in connecting.
Condition: our login must carry a valid client version (bits in 0xFE00 set, e.g. 0x0201);
otherwise the server rejects *our* login only.

Earlier evidence:

Evidence so far (no connection made):
- Observed: server network log (`BTSServer80\bin\Log\Networt*.log`, 3 days kept) shows
  a connection from 127.0.0.1 accepted and closed cleanly every 30 s, ~2,880 per day
  (probably the BtsServerGuard watchdog), while the GUI stays connected and the tests run.
  4 abrupt client disconnects today (`Reactor_Error`, IOCP error) caused no visible effect.
- Inferred from `BtsServer.pdb` symbols: IOCP reactor (`CManager`, `CCompletionPort`);
  every socket starts as a `COnlineLogin` with a login timeout (`CheckOnlineLoginOnTime`)
  until `BtsCmd_Connect`; clients are kept in lists and served by broadcast
  (`OnRegClient`, `DelClient`, `LookForAllClientBgs`, `SendAllClientRtData`,
  `SendAllClient_Resp`); there are inter-client channel locks (`CClient800::OnCmdChlLock`,
  `OnCmdChlLockRequest`) and per-user permissions (popedom: `POPEDOM_CAHNNEL_READ`,
  `POPEDOM_CAHNNEL_EXECUTE`). This is a multi-client design.
- Not yet proven: that client sessions are keyed by socket and not by IP (if keyed by IP,
  a second session from 127.0.0.1 could replace the GUI's session). Settling it needs a
  disassembly of `CManager::OnRegClient` / `LookForClientBgs`. Tried: capstone/pdbparse
  don't work on this PC's 32-bit Python; a self-contained 64-bit Python or Ghidra is
  needed (user decision). Alternative: make the first live test from another PC on the LAN
  (different IP), which sidesteps the IP question entirely.

## Q4-old (superseded): does BtsServer allow a second client connection safely?
BTS.exe already holds two connections to 8001. A third client (ours) must not disrupt the
GUI's session or the cyclers. Check the server's client handling in `BtsServer.dll` (PDB)
before connecting. Blocks Phase 1 via 8001 and options 2b/2c.

## Q6 (open): first live start (btsmon/start.py)
Packets are built from decompiled code (F-START-5). To confirm on the first start, ideally
with a RawCap capture of a GUI start for comparison: (a) StartChlInfo/UnitChlInfo.ChlID is
the channel mask, not the number (identical for channel 1, so 62-1-1 cannot tell them
apart); (b) reply layouts for map/barcode; (c) whether skipping the GUI's MySQL XML-info
update after start (F-START-6) changes how the GUI shows the test.
