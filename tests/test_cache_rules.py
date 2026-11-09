# Tests for the cache's own rules (backend/cache.py), calling cache.put and cache.get directly:
# how long each kind of answer is kept, the size limit, and the page note that states the times.
# No source is called, so nothing goes over the internet and no API key is needed.
# (tests/test_cache.py tests the cache as the backend uses it.)

from pathlib import Path

import pytest

from backend import cache

MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
OTHER = "a" * 64
FOUND = {"status": "ok", "data": {"name": "demo"}, "error": None}
NOT_FOUND = {"status": "not_found", "data": None, "error": None}


# Each source keeps "not found" for a shorter time than a found answer (a new sample may appear soon).
# At the shorter time only the not-found answer is gone; at the longer time both are.
@pytest.mark.parametrize("source", list(cache.EXPIRY))
def test_not_found_expires_sooner_than_found(monkeypatch, source):
    found_seconds, not_found_seconds = cache.EXPIRY[source]
    assert not_found_seconds < found_seconds
    now = [1000.0]
    monkeypatch.setattr(cache, "clock", lambda: now[0])
    cache.put(source, MIRAI, FOUND)
    cache.put(source, OTHER, NOT_FOUND)
    now[0] += not_found_seconds - 1
    assert cache.get(source, MIRAI) is not None and cache.get(source, OTHER) is not None
    now[0] += 1
    assert cache.get(source, MIRAI) is not None and cache.get(source, OTHER) is None
    now[0] += found_seconds - not_found_seconds
    assert cache.get(source, MIRAI) is None


def test_the_cache_never_holds_more_than_max_entries(monkeypatch):
    monkeypatch.setattr(cache, "MAX_ENTRIES", 5)
    for number in range(20):
        cache.put("virustotal", f"{number:064x}", FOUND)
        assert len(cache._entries) <= 5
    assert cache.get("virustotal", f"{19:064x}") is not None  # the newest is kept
    assert cache.get("virustotal", f"{0:064x}") is None  # the oldest was dropped


# The fixed note on the page must say the same times as the cache really uses.
def test_the_page_note_matches_the_expiry_times():
    note = (Path(__file__).parent.parent / "frontend" / "app.py").read_text().split("CACHE_NOTE = ")[1].split("\n")[0]
    for found_seconds, label in [(cache.EXPIRY["virustotal"][0], "30 min"),
                                 (cache.EXPIRY["malwarebazaar"][0], "6 h"),
                                 (cache.EXPIRY["threatfox"][0], "1 h")]:
        assert label in note
        assert (found_seconds // 60 if "min" in label else found_seconds // 3600) == int(label.split()[0])
