# A small in-memory cache for source results. Nothing is written to disk, and it is empty again
# when the backend restarts.
#
# The key is (source, hash). main.py has already lowercased the hash, so ABC... and abc... share one
# entry, and two different hashes never do. The key holds only the source's name and the hash,
# never an API key.
#
# An "error" result is NEVER kept: a timeout, a 429, a 5xx and a missing key are not answers.
# The reasons for each expiry are in design.md, section "Caching".

import threading
import time

# How long each source's answers are kept, in seconds: (when found, when "not found").
EXPIRY = {
    "virustotal": (30 * 60, 5 * 60),
    "malwarebazaar": (6 * 60 * 60, 10 * 60),
    "threatfox": (60 * 60, 5 * 60),
}
MAX_ENTRIES = 5000  # a safety limit, so the dictionary cannot grow without end

# The clock is a variable so that tests can replace it and "move time" without waiting.
clock = time.monotonic

# (source, hash) -> (expires_at, result)
_entries = {}
# Several requests can arrive at once, so changes to the dictionary take turns.
_lock = threading.Lock()


# Return the stored result if a fresh copy exists, otherwise None.
# It returns the stored dict itself (not a copy), so nothing should change it.
def get(source, file_hash):
    now = clock()
    with _lock:
        entry = _entries.get((source, file_hash))
        if entry is None:
            return None
        expires_at, result = entry
        if now >= expires_at:
            del _entries[(source, file_hash)]
            return None
    return result


# Keep a result for as long as its source and its status allow. An error is never kept.
def put(source, file_hash, result):
    lifetimes = EXPIRY.get(source)
    if lifetimes is None or result["status"] not in ("ok", "not_found"):
        return
    seconds = lifetimes[0] if result["status"] == "ok" else lifetimes[1]
    now = clock()
    with _lock:
        if len(_entries) >= MAX_ENTRIES:
            make_room(now)
        _entries[(source, file_hash)] = (now + seconds, result)


# Called while holding the lock. Drop the expired entries; if it is still full, drop the oldest one.
def make_room(now):
    for key in [key for key, entry in _entries.items() if now >= entry[0]]:
        del _entries[key]
    if len(_entries) >= MAX_ENTRIES:
        del _entries[next(iter(_entries))]  # a dictionary remembers the order it was filled in


# Empty the cache (the tests do this before every test).
def clear():
    with _lock:
        _entries.clear()
