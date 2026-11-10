# hash-portal MCP server

Lets Claude Desktop (or any MCP client) look up a file hash through the hash-enrich-2 backend.
It has one tool, `lookup_hash`, calls only the backend API and holds no API key.
The tool contract is in [design.md](../design.md#mcp-tool).

## Install

From the project folder (Windows, PowerShell):

```powershell
.venv\Scripts\python -m pip install -r mcp_server\requirements.txt
```

## Run

Start the backend first (see the [project README](../README.md)). Claude Desktop starts the
server itself: add this to `claude_desktop_config.json` (use full paths), then restart Claude Desktop.

```json
{"mcpServers": {"hash-portal": {
  "command": "C:\\path\\to\\hash-enrich-2\\.venv\\Scripts\\python.exe",
  "args": ["C:\\path\\to\\hash-enrich-2\\mcp_server\\server.py"],
  "env": {"PORTAL_URL": "http://127.0.0.1:8000"}}}}
```

`PORTAL_URL` is the backend's address.

## Test

```powershell
.venv\Scripts\python -m pytest tests\test_mcp_tool.py tests\test_mcp_portal_problems.py tests\test_mcp_stdio.py
```

## hash-triage Skill

`.claude/skills/hash-triage/SKILL.md` uses `lookup_hash` to triage a list of hashes and reports
the portal's verdict for each one in a single table. Claude Code loads it from the project folder.
