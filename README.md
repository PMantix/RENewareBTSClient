# RENewareBTSClient

AI-agent control of Neware battery cyclers that are normally run from BTS Client 8.0.
We reverse-engineer how BTS talks to its server and cyclers, then build our own Python
driver and MCP server so an agent can monitor, start, stop and run tests autonomously.

- Agent instructions and safety rules: [CLAUDE.md](CLAUDE.md)
- What is known: [docs/findings.md](docs/findings.md)
- Neware's built-in XML API: [docs/api-xml-protocol.md](docs/api-xml-protocol.md)
- Client <-> server binary protocol: [docs/protocol-clientserver.md](docs/protocol-clientserver.md)
- Open questions: [docs/open-questions.md](docs/open-questions.md)

Rebuild the local (git-ignored) `vendor/` folder with `bash tools/setup_vendor.sh`.

## Monitor (read-only, available now)

```
.venv\Scripts\python -m btsmon.monitor            # latest test per channel
.venv\Scripts\python -m btsmon.monitor --live     # only channels running now
.venv\Scripts\python -m btsmon.monitor --json --watch 60
```
Reads the server's live `.ndc` files with full file sharing; sends nothing to the
server, cyclers or database. State per channel: running / finished / stopped / protect
(with the protection reason from Neware's log codes).

## MCP server

`btsmon.mcp_server` exposes the monitor to AI agents over stdio. While it runs it also
holds one read-only connection to BtsServer (`btsmon.live`: login, heartbeat, device
list/info, subscribe) so values are ~2 s old (`source: "live"`); if that feed is down it
falls back to the data files (`source: "files"`, minutes old). Set `BTSMON_LIVE=0` to
disable the connection. It is registered for
Claude Code in `.mcp.json`; start Claude Code in this folder and approve the
`neware-bts-monitor` server. Tools:

| Tool | What it returns |
|---|---|
| `list_channels(only_running)` | every channel: state, V, mA, step, capacity, data age |
| `get_channel(channel, events)` | one channel in detail: executed steps, recent log events |
| `get_channel_data(channel, last_hours, max_points)` | recent V/I points (downsampled) |
| `explain_log_code(code)` | Neware log/protection code text and severity |
| `get_system_status()` | live-feed health, server version, devices with IP and hardware current/voltage ranges |
| `list_control_channels()` | channels released for control (allowlist) with live state, and the actions |
| `prepare_channel_command(channel, action, step)` | **sends nothing**: checks allowlist + live state, returns summary, exact bytes and a 60 s one-time token |
| `execute_channel_command(token)` | **controls hardware**: re-checks, sends, verifies on the live feed |

### Controls (pause / resume / jump / clear)

Verified live on 62-1-1 (reports from 2026-11-13). Guards: the channel must be in
`config/test_channels.json` (edit by hand; the agent cannot add channels), the live feed
must show it in a state that allows the action, and execution needs a token from
`prepare_channel_command`. `execute_channel_command` is marked destructive, so Claude Code
asks for permission each time; do not add it to an allow rule. Every command is logged to
`logs/control_*.log`. Starting tests is not supported yet. CLI equivalent:
`.venv\Scripts\python tools/control_test.py pause|resume|clear 62-1-1` or `jump 62-1-1 <step>`.

Live feed on its own: `.venv\Scripts\python -m btsmon.live --seconds 20`.

Setup: `python -m venv .venv` then `.venv\Scripts\pip install -e .[test,mcp]`.
