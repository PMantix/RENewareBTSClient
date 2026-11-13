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

## Q4 (open): does BtsServer allow a second client connection safely?
BTS.exe already holds two connections to 8001. A third client (ours) must not disrupt the
GUI's session or the cyclers. Check the server's client handling in `BtsServer.dll` (PDB)
before connecting. Blocks Phase 1 via 8001 and options 2b/2c.
