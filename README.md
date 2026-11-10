# hash-enrich-2

Look up a file hash (MD5, SHA-1 or SHA-256) in VirusTotal, MalwareBazaar and ThreatFox
from one local web page, with an overall verdict. The app only looks up hashes and never
uploads files. Lookups reach outside services, so do not look up hashes of internal files.

## Install (Windows PowerShell, once; needs Python 3.14 and Git)

```powershell
git clone https://github.com/gr-aleph/hash-enrich-2.git
cd hash-enrich-2
py -3.14 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt -r mcp_server\requirements.txt
copy .env.example .env
notepad .env
```

In `.env`, set `VT_API_KEY` (VirusTotal) and `ABUSECH_AUTH_KEY` (abuse.ch; one key covers
MalwareBazaar and ThreatFox). `.env` is git-ignored; never put a key in a code file.

## Run

Run the backend and the page in two PowerShell windows, both in the project folder:

```powershell
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

```powershell
.venv\Scripts\python -m streamlit run frontend/app.py
```

Streamlit opens the page. Paste a hash and click **Look up**, for example the Mirai sample
`add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de` or 64 zeros (an unknown hash).
Check the backend alone with `curl.exe http://127.0.0.1:8000/api/v1/health`.

## Test

```powershell
.venv\Scripts\python -m pytest
```

The tests run offline against saved replies in `tests/fixtures` and need no API keys.

To use the portal from Claude Desktop, see [mcp_server/README.md](mcp_server/README.md).
