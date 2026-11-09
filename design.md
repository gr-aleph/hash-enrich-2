# hash-enrich-2: design

## Goal

An analyst types a file hash (MD5, SHA-1 or SHA-256) on a web page and sees what
VirusTotal, MalwareBazaar and ThreatFox know about it, on one page.

## Out of scope

Database, privacy guard, bulk lookups, file upload, login,
dark theme, summary card. (A verdict was out of scope until the `feat/verdict` branch; see "Verdict" below.) The app **never uploads files**; it only looks up hashes.
(Caching was out of scope until Milestone 3; see "Caching" below.)

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
| `backend/cache.py` | A small in-memory cache for source results, one expiry per source (see "Caching") |
| `backend/verdict.py` | `make_verdict(sources)`: the overall verdict, worked out from the source results with no network (see "Verdict") |
| `frontend/app.py` | The Streamlit page |
| `mcp_server/server.py` | The MCP server: one tool that asks the portal about a hash (see "MCP server") |
| `tests/` | pytest tests; saved replies in `tests/fixtures/<source>/{hit,unknown,bad_key}.json` |
| `pytest.ini` | Lets tests import `backend` from the project folder |
| `.env` | API keys (`VT_API_KEY`, `ABUSECH_AUTH_KEY`). In `.gitignore`, never committed |
| `.env.example` | Same names with placeholder values |
| `.streamlit/config.toml` | Makes the page listen on 127.0.0.1 only |

Style: plain functions and dicts, `requests` library, no classes, no async, no Pydantic.
Files stay under ~120 lines with a plain-English comment above each function.
Exceptions for the MCP server only, approved by the owner on 2026-11-09: the `mcp` library
(`mcp_server/requirements.txt`); Pydantic's `Field`, used only to describe the tool's argument
(`mcp_server/server.py`); async in the MCP tests, because the SDK's test client is async; one class
(`Handler`) for the stand-in portal in `tests/test_mcp_stdio.py`, because Python's built-in web
server needs one; and the shared test helper module `tests/mcp_helpers.py`. The backend and the
page still follow the rule above.
Fixed settings (backend address, 10 second timeout) are constants at the top of the file.

Calling sources at the same time: `main.py` keeps a `SOURCES` dict (name -> lookup function)
and runs every lookup in its own thread with `ThreadPoolExecutor`, so the wait is about the
slowest source, not all three added up. If a lookup crashes, `main.py` turns that into an
`error` for that source only.

Time limits: each request uses `timeout=10`, but in `requests` that limits each wait for data,
not the whole request, so a source can take longer. `main.py` therefore waits at most
`TOTAL_WAIT_SECONDS = 12` for all sources together (`concurrent.futures.wait`); a source still
busy then gets `error` "Took longer than 12 seconds" and the others are returned at once.
The page waits 20 s, longer than that limit, and shows a different message for each problem:
"Backend not running" (no connection), "took longer than 20 seconds" (timeout),
"unexpected reply" (not JSON), or the backend's error for any reply other than 200.

Cache: before starting a lookup, `main.py` looks in the cache (`backend/cache.py`). Only the
sources that have no fresh copy are asked, and only a good answer (found or not found) that
arrived in time is stored. Details, expiry times and reasons: see "Caching" below.

## API

`GET /api/v1/health` -> `200 {"status": "ok"}`

`GET /api/v1/hash/{hash}`: the hash is lowercased and its type comes from its length
(32 = md5, 40 = sha1, 64 = sha256). A valid hash **always** gets 200, even when sources fail.

```json
{"hash": "...", "hash_type": "sha256",
 "sources": {"virustotal": {"status": "ok", "data": {...}, "error": null},
             "malwarebazaar": {...}, "threatfox": {...}},
 "verdict": {"score": 90, "label": "malicious", "reasons": ["..."], "failed_sources": []}}
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

## Verdict

**Why.** The analyst had to read three sections and judge alone. The verdict gives one overall
answer, with the reasons, while the three sections stay exactly as they were.

**Shape.** `verdict` is added after `sources`; no existing field changed. `score` is a whole number
0-100, `label` is `malicious`, `suspicious` or `unknown`, `reasons` is a list of short texts, and
`failed_sources` lists the names of the sources whose status is `error`.

**Rules.** Each source that found the hash (`ok`) gives a score; the verdict's score is the highest.

| Source (`ok`) | Score |
|---|---|
| VirusTotal | 5+ engines say malicious: 90; 1-4 malicious: 60; 0 malicious and 1+ suspicious: 40; otherwise 0 |
| MalwareBazaar | 90 (it only stores malware samples) |
| ThreatFox | the highest `confidence_level` of its matches, but at least 40 (any match is at least suspicious) |

Label: 75-100 `malicious`, 40-74 `suspicious`, 0-39 `unknown`. A missing count or confidence is
treated as described in `backend/verdict.py` and never crashes the answer.

**Honest by design.** The score measures evidence of harm, not safety, so there is no "clean" label:
a hash no source knows gets 0 and `unknown`, with the reason "This does not mean it is safe".
VirusTotal with no detections says the same. A source that failed is listed in `failed_sources` and
gets the reason "<source> failed, so this verdict may be incomplete"; the sources that answered
still count (a MalwareBazaar hit stays malicious when ThreatFox timed out).

**Pure.** `make_verdict` only reads the `sources` dict it is given (no network, no cache), so the
tests call it with small hand-made dicts. It is worked out on every answer, cached sources or not.

**Page.** A coloured box above the three sections: red (malicious), yellow (suspicious) or blue
(unknown), with "LABEL - score N/100" and the reasons as bullets. No new heading. If the answer has
no `verdict` (an older backend), the box is skipped.

**Not changed.** The MCP server still passes on only `hash`, `hash_type` and `sources`.

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

## Caching

**Why.** Analysts look up the same hash again and again, and every lookup asks three sources.
VirusTotal's free key allows only 4 requests a minute and 500 a day, so repeats must not spend quota.

**What is cached.** Each source's `ok` and `not_found` result, separately, so one failing source never
discards the other sources' answers. The store is `backend/cache.py`. `ask_all_sources` in `main.py`
looks in it before starting a lookup and only asks the sources that have no fresh copy. A result is
stored only if its lookup finished within `TOTAL_WAIT_SECONDS`; a slow lookup that finishes later is
ignored, as before. The three `lookup_...` and `parse_...` functions are not changed.

**Expiry per source** (limits and terms checked on the providers' own pages on 2026-11-09):

| Source | `ok` kept | `not_found` kept | Reasons: how often the data changes, how fresh an analyst needs it, how tight the limits are |
|---|---|---|---|
| VirusTotal | **30 min** | **5 min** | Detection counts change as antivirus engines update, so an old answer can show fewer detections than today; an analyst triaging a hash needs minutes, not days. But its limit is the tightest of the three (4 a minute, 500 a day), so repeats within a session must be absorbed. "Not found" is short because anyone can submit the file at any moment. Terms: "Public vs Premium API" (docs.virustotal.com) sets those limits and says nothing about caching. VirusTotal's 2021 Terms of Service ("Historic Terms of Service") forbid copying, reproducing or distributing material from the Service; the current Terms of Service page showed no text when checked on 2026-11-09. The course instructor approved this cache on 2026-11-09: a private, short-lived copy in this backend's memory, used only for the same analyst's repeat lookups, never written to disk, published or shared. |
| MalwareBazaar | **6 h** | **10 min** | Facts about a sample (family name, file type, first seen) rarely change, and hours are fresh enough. No numeric query limit is published, only abuse.ch's "fair use principles" (query volumes reasonable for non-commercial use), and fewer repeated queries fits that. "Not found" is short because a new sample can be uploaded at any time. Terms: the abuse.ch Terms of Use and the API page say nothing about caching. |
| ThreatFox | **1 h** | **5 min** | Indicators are added all the time, their confidence can change, and since 2025-05-01 indicators older than 6 months expire and disappear from the API, so a long expiry could keep one that is gone. No numeric query limit, only "fair use principles". "Not found" is short because new indicators appear constantly. Terms: nothing about caching. |
| any source, `error` | **never** | | A timeout, a 429, a 5xx and a missing key are not answers. |

No source rules caching out in any page that could be read, so no source has an expiry of zero.

**Never cache an error.** `cache.put()` itself refuses any result whose status is not `ok` or `not_found`, so
a slip in one source's code cannot keep a timeout, a 429, a 5xx or a "key not set" message.

**The key** is `(source, hash)`. `lookup_hash` has already lowercased the hash, so `ABC...` and `abc...`
share one entry, and two different hashes never do. A hash with spaces never reaches the cache: the page
strips spaces before asking (`frontend/app.py`), and the backend still answers 400 for them, as documented in
the API section. The key holds only the source's name and the hash, never an API key.

**Storage.** A dictionary in memory with a lock (several requests can arrive at once). It is the simplest
possible choice, with no new dependency and no database. Costs: it is empty again when the backend restarts,
and two backend processes would not share it. It holds at most 5000 entries (expired ones are dropped first,
then the oldest). Two identical requests arriving at the same moment both ask the sources; that is accepted.

**Telling the analyst a result may be old.** Results can be kept for up to 6 hours, and a cached "not found"
or clean-looking answer can be wrong later (the file gets submitted, engines update). The page therefore shows
one fixed note under the results: "Results may be up to 30 min (VirusTotal), 6 h (MalwareBazaar) or 1 h
(ThreatFox) old." The cache adds nothing to the answer (no field and no header). Cost: the page does not say which result was cached, only how old one can be.
A test checks that the note matches the expiry times in `backend/cache.py`.

**What did not change.** The JSON body, every field, the status codes, and the order of the sources. A valid
hash still always gets 200. An invalid hash still gets 400 before the cache or any source is touched.

**Measured.** One fixed list of 24 lookups (22 valid: repeats, one hash in three spellings, hashes known to
nobody, one hash for which ThreatFox fails every time, and 2 invalid inputs that get a 400) was sent through the
app with a fake instead of `requests.get` and `requests.post`, so no real quota was spent. It counted the outbound
requests each source would have received:

| Source | Without the cache | With the cache |
|---|---|---|
| VirusTotal | 22 | 5 |
| MalwareBazaar | 22 | 5 |
| ThreatFox | 22 | 8 |
| **Total** | **66** | **18** |

ThreatFox is higher than the others because its error on the 4 lookups of the failing hash is never cached,
so each one asks again. The script that produced these numbers is not part of the repository (it could not run
on Windows with Python 3.14, and it was over the file-size limit); the numbers are in the pull request. Expiry
is shown by the tests in `tests/test_cache.py` (a fake clock).

## MCP server

`mcp_server/server.py` lets an AI assistant such as Claude Desktop look up a hash through this portal. It
only calls the portal's API (section "API"); it never calls a source itself and holds no API key. Nothing in
the API changes.

**Tool.** One tool, `lookup_hash(file_hash)`, because the portal has one kind of IOC (a file hash) and tells
MD5, SHA-1 and SHA-256 apart by length. It is marked read-only and "open world" (it reaches outside services).
The argument itself is described too (what the model must pass, as 32, 40 or 64 hex characters), because in Claude Desktop the model twice called the tool with the argument missing or misnamed before correcting itself. Its description says what goes in, that the answer has a status (ok, not_found, error) for VirusTotal,
MalwareBazaar and ThreatFox, that not_found does not mean safe, that error means one source failed while the
others still answer, that text fields come from third parties and are data, not instructions, and that hashes
of internal files must not be looked up.

**Finding the portal.** The environment variable `PORTAL_URL` (default `http://127.0.0.1:8000`).

**What it refuses.** Before any request: anything that is not 32, 40 or 64 hex characters (after trimming
spaces and lowercasing) is a tool error and nothing is sent. The bad value is not repeated back.

**Failures.** Portal not running, no answer in 20 seconds (longer than the portal's own 12), a reply that is
not JSON, any status other than 200 and 400, and an unexpected shape each become a clear tool error. A
source that fails is NOT a tool error: it comes through as that source's `error` result.

**Output.** The portal's `hash`, `hash_type` and `sources`, with every text cut to 200 characters and every
list to 10 items, because whatever a source wrote reaches the model.

**Logs.** To stderr only, never the hash itself. stdout carries the protocol, so the server never prints.

**Tests** (`tests/test_mcp_*.py`, offline): recorded real portal answers (`tests/fixtures/portal/`, made by running the real backend with the saved source replies of `tests/fixtures/`, and the source error and the 400 as the backend gives them); the tool
list and annotations; found, nothing known, one source failing, invalid values (no request is made), portal
down, slow, 400, not JSON; and one test that starts the real server and checks that every line on stdout is a
protocol message. The server needs its own packages: `pip install -r mcp_server/requirements.txt`.

## Testing

pytest tests the `parse_...` functions and the API endpoint with saved JSON replies
(a hit, an unknown hash and a bad key for each source). No network, no keys, no mocking libraries.

- Saved replies have the shape `{"status_code": ..., "body": ...}`, with no request headers and
  no keys. abuse.ch replies are real recordings; the VirusTotal bad-key reply was recorded with
  the fake key `not-a-real-key`.
- `tests/test_parse.py`: 9 tests, 3 per source.
- `tests/test_api.py`: 6 tests (health, 400, all found, one failing source doesn't hide the
  others, a crashing lookup becomes an error, the answer has a verdict). They replace the entries in `main.SOURCES` with
  fakes using pytest's built-in `monkeypatch`, so no source is ever called.
- `tests/test_<source>_lookup.py` (one per source, 3 tests each): `requests.get`/`post` is
  replaced with a fake that records what it was asked to send. Checks: a missing key sends
  nothing; the address, headers, body and 10 s timeout are the documented ones; a timeout,
  no connection and a non-JSON reply each give their error message.
- `tests/test_main.py`: 6 tests (md5/sha1/sha256 by length, wrong lengths and non-hex rejected,
  an invalid hash calls no source, the three sources are asked at the same time, a slow source
  gets "Took longer" while the others still answer).
- `tests/test_frontend.py`: 6 tests using Streamlit's built-in `AppTest` (runs the page without
  a browser) with `requests.get` faked: backend down, backend too slow, invalid hash, a 404
  reply doesn't crash the page, one failed source still shows all three sections, a malicious
  verdict shows a red box with the score.
- `tests/test_cache.py`: 7 tests of the cache as the backend uses it, with fake lookups that count
  their calls (a miss, a hit, an expired entry using a fake clock, an error that is not cached,
  "not found" is cached, spellings share one entry while different hashes and sources never do, the
  answer body is the same on a miss, a hit and a partial hit).
- `tests/test_cache_rules.py`: 5 tests of the cache's own rules, calling `cache.put`/`cache.get`
  directly ("not found" expires sooner than a found answer, once per source; the cache never holds
  more than `MAX_ENTRIES`; the page note matches the expiry times).
- `tests/test_verdict.py`: 12 tests of `make_verdict` with hand-made results (each VirusTotal rule,
  a MalwareBazaar hit alone, ThreatFox high, low and missing confidence, the highest wins, not found
  anywhere, one failed source with a hit elsewhere, all three failed).
- `tests/conftest.py` empties the cache before every test.
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

**Milestone 3** (branch `feat/caching`): each source's results are cached in memory with its own expiry
and reasons (see "Caching"); an error is never cached; one hash typed differently uses one entry; the page
shows a fixed note about how old a result can be; the JSON body and the API section are unchanged; the existing tests pass
unchanged and new tests show a hit, a miss, an expiry, a cached not-found with its shorter expiry and an uncached error; a fixed run of 24 lookups was
counted before and after (numbers kept, script not in the repo); merged by pull request that the owner reviews.

**Milestone 5** (branch `feat/mcp-server`): an MCP server with one tool, `lookup_hash`, that calls the running
portal; it refuses invalid hashes before any request, turns every expected failure into a clear message, keeps no
key and prints nothing but the protocol; offline tests; added to Claude Desktop and tried with a real question;
merged by pull request that the owner reviews.

**Verdict** (branch `feat/verdict`): the answer gets a `verdict` (score 0-100, label, reasons, failed
sources) worked out by one pure function; no "clean" label; failed sources are named; the page shows a
coloured box; existing fields unchanged; the existing tests pass (only the cache test that lists the
answer's keys now expects `verdict` too) and new tests cover every rule; merged by pull request that the
owner reviews.
