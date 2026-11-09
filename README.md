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
| `add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de` | Mirai sample, found by all three |
| `44d88612fea8a8f36de82e1278abb02f` | EICAR test file, found on VirusTotal only |
| `0000000000000000000000000000000000000000000000000000000000000000` | not found anywhere |

## Run the tests

The tests use saved replies in `tests/fixtures`, so they need no internet and no API keys
(they pass with Wi-Fi off):

```
.venv\Scripts\python -m pytest -v
```

You should see `28 passed`. A warning about `httpx2` is expected and harmless.

## Project files

| File | What it does |
|---|---|
| `backend/main.py` | FastAPI app: `/api/v1/health` and `/api/v1/hash/{hash}`; asks all sources at the same time |
| `backend/virustotal.py` | Calls VirusTotal and turns its reply into a result |
| `backend/malwarebazaar.py` | Same for MalwareBazaar |
| `backend/threatfox.py` | Same for ThreatFox |
| `frontend/app.py` | The Streamlit page |
| `tests/` | pytest tests and saved replies |
| `.streamlit/config.toml` | Keeps the page local (127.0.0.1) |
