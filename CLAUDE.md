# CLAUDE.md: agent instructions

## Project

Give an AI agent (Claude, via an MCP server) full control of **Neware battery cyclers**
that are normally driven by the vendor GUI **BTS Client 8.0** (`BTS.exe`): list channels,
monitor live data, start tests from step files, stop/pause/continue/jump, download data,
and run autonomous test campaigns. We own all code in this repo; Neware binaries are only
studied, never shipped.

Sister project: `../RECellTest` (same approach for a Solartron 1470E/1260). Reuse its
conventions: `docs/findings.md` ledger, `reports/`, `docs/open-questions.md`.

Read `docs/findings.md` before doing anything.

## System on this PC (lab PC = RE PC, same machine)

```
Cyclers (192.168.1.35, 192.168.0.2) --TCP 8001--> BtsServerNT.exe (service "BtsServer", native C++, PDBs shipped)
                                                     |-- MySQL :3306 (service "MySQL", bundled)
BTS.exe (.NET 4.5.2 GUI) --TCP 127.0.0.1:8001-------/   and also MySQL :3306
```
- Client install: `C:\Program Files (x86)\NEWARE\BTSClient80\`
- Server install: `C:\Program Files (x86)\NEWARE\BTSServer80\bin\`
- Client user config: `C:\Users\user\Documents\NEWARE\BTSClient\` (`Common.BTS.ConfigDir()`)

## Safety rules: real cells are running on these cyclers

Cyclers source/sink amps into real cells, often unattended for days.

1. **Do not disturb running tests.** Never stop/restart the `BtsServer` or `MySQL`
   services, never kill or restart `BTS.exe`, never reboot, never touch the cyclers'
   network, without the user explicitly asking at that moment.
2. **Ask before sending anything that is not a pure read** to BtsServer (8001), the XML
   API (502), a cycler, or MySQL. Say exactly what goes where. Reads (device list,
   channel status, live data) still need a one-time OK per new transport.
3. **Control commands only on channels the user has named as free test channels**
   (allowlist `config/test_channels.json`; only the user adds channels to it, never an agent). Code must refuse
   any control command on a channel not in the allowlist. Never on a channel that is
   currently `working`/`pause`, unless the user names it.
4. **MySQL is read-only for us.** `SELECT` only. Never `INSERT/UPDATE/DELETE/ALTER`.
5. Never modify the Neware install, registry, licence/registration, calibration,
   cycler firmware ("ZWJ/XWJ upgrade"), device IDs or server config.
   **Do not bypass or forge the BTS registration code** (it gates the XML API, see
   findings F-API-2). Obtaining a code from Neware is the legitimate route.
6. Every code path that starts a channel must be able to stop it: wrap in try/finally,
   and log every command sent with timestamp.
7. Files under `BTSServer80\NdcFile\` are being written by the server: read them only
   through `btsmon.safe_read.read_shared` (full share flags, handle closed at once), never
   with plain `open()`/`shutil`/editors, never write/rename/delete there, poll >= 30 s.
8. Connections to BtsServer (8001) go through `btsmon.protocol`, whose packet builder only
   allows the Observed-safe read-only requests (login, heartbeat, device list, device info,
   select device). Adding any other request (stop/continue/jump/start/...) to that set is a
   control change: get the user's explicit go-ahead first, test on a user-named free
   channel. The MCP server keeps one such read-only connection open while it runs.
9. Never invent protocol commands on live hardware. A command is usable when it is
   documented here as Observed (seen in a capture) or the user approves a first test on
   a free channel with no cell / a dummy load.

## Workflow

- `vendor/` (git-ignored) holds copies of the Neware binaries/configs and ILSpy output.
  Rebuild it with `tools/setup_vendor.sh`. Decompiled C# is in `vendor/decompiled/<Assembly>/`.
- Record every fact in `docs/findings.md`, tagged **Observed** (seen on the wire / on
  hardware) or **Inferred** (static RE), with a `file:line` citation into
  `vendor/decompiled/` or a capture path.
- Protocol docs: `docs/api-xml-protocol.md` (Neware's built-in XML API),
  `docs/protocol-clientserver.md` (BTS.exe <-> BtsServer binary protocol).
- Questions that need the user, Neware, or hardware go in `docs/open-questions.md`.
- After a hardware/capture session write `reports/YYYY-MM-DD-<topic>.md` (Setup, What was
  run, Results, New facts, Problems, Questions).

## Plan

| Phase | What | Status |
|---|---|---|
| 0 | Static RE: decompile client, document XML API + client/server protocol | done |
| 1 | Read-only monitoring: `btsmon.monitor` + MCP server `btsmon.mcp_server` from live NDC files, incl. finished/stopped/protect from `_log.ndc` | done |
| 1b | Live read-only feed over 8001 (`btsmon.live`, 2 s), used by the MCP server | done |
| 2 | Transport for control. Candidates: (a) Neware XML API, needs registration code from Neware; (b) host Neware's own `Network.dll` `Client` class from our process (pythonnet/C#); (c) our own Python implementation of the 8001 protocol | todo |
| 3 | Control on a free test channel: pause/resume, jump, clear flag done on 62-1-1 (F-CS-12, F-CS-13); start: step codec `btsmon/steps.py` + step-file reader `btsmon/stepfile.py` verified vs server logs (F-STEP-1..5), GUI start defaults `btsmon/gui_defaults.py` (F-STEP-4, -6); start transaction `btsmon/start.py` + `tools/start_test.py` (F-START-1..6), first live start OK on 62-1-1 (test 142); MCP start tool todo | in progress |
| 4 | MCP server with guardrails: monitoring + live feed done; pause/resume/jump/clear via allowlist + prepare/execute token (`btsmon/control.py`) done; start todo | in progress |

## Repo conventions

- Python 3.10+. This PC only has 32-bit Python 3.12 (no pandas wheels), so keep the core
  stdlib-only. Venv: `python -m venv .venv`, `.venv\Scripts\pip install -e .[test]`;
  tests: `.venv\Scripts\python -m pytest`.
- Tests run without hardware against recorded captures.
- Never commit anything from `vendor/`, Neware binaries, or decompiled source.
  Short excerpts (a few lines) quoted in docs for citation are fine.
- Commit small logical changes; the repo is private.
