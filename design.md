# hash-enrich-2: design

## Scope

Look up one file hash in VirusTotal, MalwareBazaar and ThreatFox and return each source's
result plus an overall verdict. Lookup only: the app never uploads files.
Out of scope: database, login, bulk lookup in the API, file upload.

```
Browser -> Streamlit page (frontend/app.py) -> FastAPI backend (backend/main.py) -> sources
MCP client -> MCP server (mcp_server/server.py) -> backend API
```

## Decisions

- The page and the backend listen on 127.0.0.1 only, because the backend spends the user's API keys.
- The page and the MCP server call only the backend API, never a source, so keys, cache and verdict rules exist in one place.
- API keys live only in `.env` (git-ignored, read with python-dotenv), because the repository is public.
- Each source has a `lookup_<source>` function (network) and a `parse_<source>` function (pure), so parsing is tested offline with saved replies.
- ThreatFox is queried with `search_ioc`, not `search_hash`, because `search_hash` returns indicators linked to a sample, not the hash itself.
- Sources are asked in parallel threads under one overall wait limit (`TOTAL_WAIT_SECONDS`, backend/main.py), so the answer takes as long as the slowest source and one slow source never blocks the others.
- The page and the MCP server wait longer than that limit, so a slow source arrives as that source's `error`, not as a client timeout.
- Backend and page use plain functions, dicts and `requests`, with no classes, async or Pydantic, to keep every file short and readable. The MCP server and its tests are the exception (the `mcp` SDK, Pydantic `Field` for the argument description, async test client, one `http.server` handler class), because the SDK and the standard library require them.
- The verdict comes from one pure function, `make_verdict` (backend/verdict.py), run on every answer, so the rules live in one place. The page, the MCP server and the Skill show it and never recompute it.
- The highest score among the sources that found the hash wins, because one strong signal outweighs silence elsewhere.
- An unknown hash is never `safe` and scores below any real evidence, because absence from these sources is not proof of safety. The value is a policy, not a probability.
- `safe` requires VirusTotal to report enough engines with no detection and no source to have failed, because only VirusTotal can report "checked and found nothing" and a failed source might know the file.
- `suspicious` covers both "unknown" and "weak evidence", so the page and the Skill always show the score and the reasons with the label.
- Source results are cached in memory per (source, hash) with a per-source expiry, shorter for `not_found` (backend/cache.py), to save VirusTotal's small free quota while keeping results fresh enough for triage. The cache is empty after a restart and is not shared between processes.
- An `error` result is never cached (`cache.put` refuses it), because a timeout, rate limit or missing key is not an answer.
- The API carries no cache metadata. The page shows a fixed note with the longest possible result age, and a test keeps it equal to the expiry times.
- The MCP tool cuts long text and long lists (limits in mcp_server/server.py), because source text reaches the model. Tool descriptions tell the model to treat it as data.
- The MCP server writes logs to stderr only and never logs the hash, because stdout carries the protocol and hashes can be sensitive.

## API

`GET /api/v1/health` -> `200 {"status": "ok"}`

`GET /api/v1/hash/{hash}`

- The path value is lowercased (not trimmed). It must be 32, 40 or 64 hex characters, giving `hash_type` `md5`, `sha1` or `sha256`.
- Invalid -> `400 {"error": "Expected 32, 40 or 64 hex characters"}`, and no source is called.
- A value containing `/` does not match the route -> FastAPI's `404 {"detail": "Not Found"}`.
- Valid -> always `200`, even when every source fails:

```json
{"hash": "<lowercase hash>", "hash_type": "sha256",
 "sources": {"virustotal": <result>, "malwarebazaar": <result>, "threatfox": <result>},
 "verdict": {"score": 90, "label": "malicious", "reasons": ["..."], "failed_sources": []}}
```

Keys appear in that order, and `sources` is always in the order virustotal, malwarebazaar, threatfox.

**Result:** `{"status": "ok" | "not_found" | "error", "data": object | null, "error": string | null}`.
`data` is set only for `ok`, and `error` (a display message) only for `error`.
`not_found` means the source has no record; it does not mean safe. One failing source never hides the others.

**`data` per source** (any value may be `null`):
- `virustotal`: `malicious`, `suspicious`, `harmless`, `undetected` (integer counts from `last_analysis_stats`),
  `type_description`, `names` (list), `first_submission_date` (`"YYYY-MM-DD HH:MM:SS UTC"`),
  `link` (`https://www.virustotal.com/gui/file/<sha256>`).
- `malwarebazaar` (first sample): `signature`, `file_type`, `tags` (list), `first_seen`, `last_seen`, `origin_country`.
- `threatfox`: `matches`, a list with one entry per ThreatFox record:
  `malware_printable`, `threat_type`, `confidence_level` (0-100), `first_seen`, `malpedia` (URL).

**Status per source:**

| `status` | VirusTotal | MalwareBazaar | ThreatFox |
|---|---|---|---|
| `ok` | HTTP 200 | HTTP 200, `query_status` `ok` | HTTP 200, `query_status` `ok` |
| `not_found` | HTTP 404 | HTTP 200, `hash_not_found` | HTTP 200, `no_result` |
| `error` | any other reply, missing key, no connection, non-JSON reply, no answer within the backend's wait limit | same, including HTTP 401/403 or `unknown_auth_key` (bad key) and HTTP 429 | same as MalwareBazaar |

**`verdict`:**
- `score`: integer, 0 = safe to 100 = malicious.
- `label`: `safe`, `suspicious` or `malicious`, set by score band (backend/verdict.py).
- `reasons`: non-empty list of display texts. Can contain source text, such as a MalwareBazaar signature.
- `failed_sources`: keys of the sources whose `status` is `error`, in source order.

## MCP tool

`mcp_server/server.py` exposes one tool, `lookup_hash(file_hash)`, annotated read-only and open-world.
It calls the backend at `PORTAL_URL` (environment variable) and holds no API key.

- The input is trimmed and lowercased. Anything that is not 32, 40 or 64 hex characters is a tool error, nothing is sent, and the value is not echoed.
- Success returns `{"hash", "hash_type", "verdict", "sources"}` as in the API, with long text and lists cut.
- Tool errors: backend not reachable, no answer in time, non-JSON reply, HTTP 400 (with the backend's reason), any other non-200 status, unexpected shape, and a missing `verdict` (the message asks to restart the portal).
- A failing source is not a tool error. It arrives as that source's `error` result.

## Hash triage Skill

`.claude/skills/hash-triage/SKILL.md` triages a list of hashes with `lookup_hash` and shows the tool's verdict unchanged, so the scoring rules exist only in backend/verdict.py.

## Testing

`pytest` runs offline with no API keys. Source calls are replaced by saved replies (`tests/fixtures/<source>/`) or monkeypatched fakes.
The MCP tests use recorded backend answers (`tests/fixtures/portal/`) and are skipped when the `mcp` package is not installed.
