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

## MCP server (read-only)

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

Live feed on its own: `.venv\Scripts\python -m btsmon.live --seconds 20`.

Setup: `python -m venv .venv` then `.venv\Scripts\pip install -e .[test,mcp]`.
