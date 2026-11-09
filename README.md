# hash-enrich-2

Type a file hash (MD5, SHA-1 or SHA-256) on a web page and see what VirusTotal,
MalwareBazaar and ThreatFox know about it, on one page. If one source fails (bad key,
rate limit, offline), the page still shows the other two.

The app only **looks up hashes**. It never uploads files. Lookups are not private, so do not
look up hashes of internal files.

How it works: the Streamlit page (frontend) asks the FastAPI backend, and the backend asks
the sources. Both run on your own computer only (127.0.0.1). See [design.md](design.md).

## Install (Windows, once)

You need Python 3.14 and Git. In PowerShell:

```
cd $HOME\Desktop
git clone https://github.com/gr-aleph/hash-enrich-2.git
cd hash-enrich-2
py -3.14 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env
notepad .env
```

In Notepad, replace the placeholders with your own keys and save:

- `VT_API_KEY`: from your VirusTotal account (free key: 4 lookups/minute, 500/day)
- `ABUSECH_AUTH_KEY`: from https://auth.abuse.ch/ (one key covers MalwareBazaar and ThreatFox)

Paste each key right after the `=`, with no spaces or quote marks.

`.env` is listed in `.gitignore`, so Git never commits it. Never paste a key into a code file.

## Run (two terminals)

Commands use `.venv\Scripts\python`, so you don't need to activate the venv.

**Terminal 1: backend**

```
cd $HOME\Desktop\hash-enrich-2
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2: frontend**

```
cd $HOME\Desktop\hash-enrich-2
.venv\Scripts\python -m streamlit run frontend/app.py
```

Your browser opens http://127.0.0.1:8501. Paste a hash and click **Look up**.
Stop either part with Ctrl+C.

## Check the backend by hand

In PowerShell, use `curl.exe` (plain `curl` is a different PowerShell command):

```
curl.exe http://127.0.0.1:8000/api/v1/health
curl.exe http://127.0.0.1:8000/api/v1/hash/44d88612fea8a8f36de82e1278abb02f
curl.exe http://127.0.0.1:8000/api/v1/hash/abc
```

The last one is not a valid hash, so it gets HTTP 400 and
`{"error":"Expected 32, 40 or 64 hex characters"}`.
FastAPI also shows interactive docs at http://127.0.0.1:8000/docs.

Test hashes:

| Hash | Expected |
|---|---|
| `add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de` | Mirai sample, found by all three; verdict malicious |
| `44d88612fea8a8f36de82e1278abb02f` | EICAR test file, found on VirusTotal only; verdict malicious (from VirusTotal) |
| `0000000000000000000000000000000000000000000000000000000000000000` | not found anywhere; verdict suspicious, score 50 (never "safe") |

## Verdict

Next to `sources`, every answer has a `verdict`, worked out by `backend/verdict.py` from the
source results:

```json
"verdict": {"score": 90, "label": "malicious",
            "reasons": ["MalwareBazaar has this file as a malware sample (Mirai)"],
            "failed_sources": []}
```

The score runs from 0 (safe) to 100 (malicious); the highest source wins. The label is `safe`
(0-29), `suspicious` (30-69) or `malicious` (70-100). "Safe" needs real proof: VirusTotal checked the
file with 30+ engines and none flags it, and all three sources answered. A hash nobody knows gets 50,
`suspicious`: not proof of malware, but never safe. A source that failed is named in
`failed_sources` and in the reasons. The page shows the verdict as a coloured box above the
sources. The rules are in [design.md](design.md), section "Verdict".

## Run the tests

The tests use saved replies in `tests/fixtures`, so they need no internet and no API keys
(they pass with Wi-Fi off):

```
.venv\Scripts\python -m pytest -v
```

You should see `87 passed`. If you have not installed the MCP server's packages, the 24 MCP tests are skipped and you see `63 passed, 3 skipped` (3 test files skipped). A warning about `httpx2` is expected and harmless.

## Caching

Each source's answer is kept in memory for a while, so asking about the same hash again does not
call the source again (VirusTotal's free key allows only 4 lookups a minute and 500 a day):
VirusTotal 30 minutes, MalwareBazaar 6 hours, ThreatFox 1 hour; "not found" 5 to 10 minutes; an
error is never kept. The reasons for each time are in [design.md](design.md), section "Caching".
The page shows a fixed note that a result can be that old. The cache adds no field and no header to the JSON
answer. The cache is empty again when the backend restarts.

A fixed list of 24 lookups with a fake web (no keys, no quota) caused 66 outbound requests without the
cache and 18 with it (VirusTotal 22 to 5, MalwareBazaar 22 to 5, ThreatFox 22 to 8). Details in design.md.

## MCP server (use the portal from Claude Desktop)

The MCP server lets Claude Desktop look up a hash through the portal. The portal must be running
(see "Run"). The server needs one more package:

```
.venv\Scripts\pip install -r mcp_server\requirements.txt
```

Add this to `claude_desktop_config.json` (Claude Desktop, Settings, Developer, Edit Config; keep any other
settings in the file) and change the two paths to yours (full paths, not relative):

```
{
  "mcpServers": {
    "hash-portal": {
      "command": "C:\\path\\to\\hash-enrich-2\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\hash-enrich-2\\mcp_server\\server.py"],
      "env": { "PORTAL_URL": "http://127.0.0.1:8000" }
    }
  }
}
```

On a Mac the command is `/path/to/hash-enrich-2/.venv/bin/python`. Quit Claude Desktop completely and open
it again. Then ask, for example: "Look up this hash: add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de".
The answer includes the portal's verdict (score 0 = safe to 100 = malicious, label and reasons), and
Claude is told to give the reasons and never judge a file from the score alone. If Claude says the portal
"sent no verdict", the portal is running older code: stop it and start it again.
The server holds no API key; the keys stay in the portal's `.env`. Lookups go to outside services, so never
ask about hashes of internal files. Details: [design.md](design.md), section "MCP server".

## Project files

| File | What it does |
|---|---|
| `backend/main.py` | FastAPI app: `/api/v1/health` and `/api/v1/hash/{hash}`; asks all sources at the same time |
| `backend/virustotal.py` | Calls VirusTotal and turns its reply into a result |
| `backend/malwarebazaar.py` | Same for MalwareBazaar |
| `backend/threatfox.py` | Same for ThreatFox |
| `backend/cache.py` | The in-memory cache (what is kept, and for how long) |
| `backend/verdict.py` | Works out the overall verdict (score, label, reasons) from the source results |
| `frontend/app.py` | The Streamlit page |
| `mcp_server/` | The MCP server (one tool) and its requirements |
| `tests/` | pytest tests and saved replies |
| `.streamlit/config.toml` | Keeps the page local (127.0.0.1) |
