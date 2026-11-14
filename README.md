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
server, cyclers or database.
