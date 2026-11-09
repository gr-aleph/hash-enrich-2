# hash-enrich-2: design

## Goal

An analyst types a file hash (MD5, SHA-1 or SHA-256) on a web page and sees what
VirusTotal, MalwareBazaar and ThreatFox know about it, on one page.

## Out of scope

Database, caching, privacy guard, bulk lookups, file upload, login, verdict badge,
dark theme, summary card. The app **never uploads files**; it only looks up hashes.

## Architecture

```
Browser -> Streamlit page (127.0.0.1:8501) -> FastAPI backend (127.0.0.1:8000) -> sources
```

- The frontend gets its data only from the backend, never from a source directly.
- Both parts listen on 127.0.0.1 only, so nobody else on the network can use your keys.
- Two processes in two terminals. No containers.

| File | What it does |
|---|---|
| `backend/main.py` | FastAPI app: `/api/v1/health` and `/api/v1/hash/{hash}`; loads `.env`; asks all sources at the same time |
| `backend/virustotal.py`, `malwarebazaar.py`, `threatfox.py` | One file per source, each with a `lookup_...` function (calls the API) and a `parse_...` function (turns the reply into a result) |
| `frontend/app.py` | The Streamlit page |
| `tests/` | pytest tests; saved replies in `tests/fixtures/<source>/{hit,unknown,bad_key}.json` |
| `pytest.ini` | Lets tests import `backend` from the project folder |
| `.env` | API keys (`VT_API_KEY`, `ABUSECH_AUTH_KEY`). In `.gitignore`, never committed |
| `.env.example` | Same names with placeholder values |
| `.streamlit/config.toml` | Makes the page listen on 127.0.0.1 only |

Style: plain functions and dicts, `requests` library, no classes, no async, no Pydantic.
Files stay under ~120 lines with a plain-English comment above each function.
Fixed settings (backend address, 10 second timeout) are constants at the top of the file.

Calling sources at the same time: `main.py` keeps a `SOURCES` dict (name -> lookup function)
and runs every lookup in its own thread with `ThreadPoolExecutor`, so the wait is about the
slowest source, not all three added up. If a lookup crashes, `main.py` turns that into an
`error` for that source only.

## API

`GET /api/v1/health` -> `200 {"status": "ok"}`

`GET /api/v1/hash/{hash}`: the hash is lowercased and its type comes from its length
(32 = md5, 40 = sha1, 64 = sha256). A valid hash **always** gets 200, even when sources fail.

```json
{"hash": "...", "hash_type": "sha256",
 "sources": {"virustotal": {"status": "ok", "data": {...}, "error": null},
             "malwarebazaar": {...}, "threatfox": {...}}}
```

Invalid hash -> `400 {"error": "Expected 32, 40 or 64 hex characters"}`, no source is called.

Each source result: `status` is `ok` (found), `not_found` or `error`; `data` is a dict when
`ok`, else `null`; `error` is a text message when `error`, else `null`.
One failing source never hides the others. "Not found" does not mean "safe".

### VirusTotal `data`

`malicious`, `suspicious`, `harmless`, `undetected` (from `last_analysis_stats`),
`type_description`, `names`, `first_submission_date` (Unix timestamp converted to UTC text),
`link` (`https://www.virustotal.com/gui/file/<sha256>`).

### Status mapping

| Result | VirusTotal | MalwareBazaar | ThreatFox |
|---|---|---|---|
| `ok` | HTTP 200 | `query_status` `ok` | `query_status` `ok` |
| `not_found` | HTTP 404 | `hash_not_found` | `no_result` |
| `error` (bad key) | HTTP 401 | HTTP 403 `unknown_auth_key` | HTTP 403 `unknown_auth_key` |
| `error` (rate limit) | HTTP 429 (free: 4/min, 500/day) | HTTP 429 | HTTP 429 |
| `error` (other) | missing key (no request sent), timeout, no connection, any other reply | same | same |

## Data sources

| Source | Request |
|---|---|
| VirusTotal | `GET https://www.virustotal.com/api/v3/files/{hash}`, header `x-apikey` |
| MalwareBazaar | `POST https://mb-api.abuse.ch/api/v1/`, form `query=get_info&hash=...`, header `Auth-Key` |
| ThreatFox | `POST https://threatfox-api.abuse.ch/api/v1/`, JSON `{"query": "search_ioc", "search_term": "<hash>", "exact_match": true}`, header `Auth-Key` |

One abuse.ch key covers MalwareBazaar and ThreatFox. ThreatFox uses `search_ioc`, not
`search_hash` (that one returns IOCs linked to a sample, not the hash itself).

## Keys and safety

- Keys live only in `.env`, read with python-dotenv. Never in code, tests or commits.
- The repository is public: a committed key counts as stolen. Revoke it and make a new one.
- Lookups are not private. Never look up hashes of internal files.

## Testing

pytest tests the `parse_...` functions and the API endpoint with saved JSON replies
(a hit, an unknown hash and a bad key for each source). No network, no keys, no mocking libraries.

- Saved replies have the shape `{"status_code": ..., "body": ...}`, with no request headers and
  no keys. abuse.ch replies are real recordings; the VirusTotal bad-key reply was recorded with
  the fake key `not-a-real-key`.
- `tests/test_parse.py`: 9 tests, 3 per source.
- `tests/test_api.py`: 5 tests (health, 400, all found, one failing source doesn't hide the
  others, a crashing lookup becomes an error). They replace the entries in `main.SOURCES` with
  fakes using pytest's built-in `monkeypatch`, so no source is ever called.
- `tests/test_<source>_lookup.py` (one per source, 3 tests each): `requests.get`/`post` is
  replaced with a fake that records what it was asked to send. Checks: a missing key sends
  nothing; the address, headers, body and 10 s timeout are the documented ones; a timeout,
  no connection and a non-JSON reply each give their error message.
- `tests/test_main.py`: 5 tests (md5/sha1/sha256 by length, wrong lengths and non-hex rejected,
  an invalid hash calls no source, the three sources are asked at the same time).
- Known warning: Starlette says its test client will move from `httpx` to `httpx2`. Tests still
  pass; revisit when upgrading.

Test hashes: Mirai `add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de` (all three),
EICAR `44d88612fea8a8f36de82e1278abb02f` (VirusTotal only), 64 zeros (unknown everywhere).

## Milestones

**Milestone 1** (branch `milestone-1`): VirusTotal end to end. The endpoint returns the
VirusTotal result, an invalid hash gets 400, the Streamlit page shows the result, README
explains install and run on Windows, merged by pull request.

**Milestone 2** (branch `milestone-2`): add MalwareBazaar and ThreatFox, called at the same
time (`ThreadPoolExecutor`); a failing source still shows the other two; pytest tests pass
with Wi-Fi off; README updated; merged by pull request.
