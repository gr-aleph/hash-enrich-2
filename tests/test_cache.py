# Tests for the cache (backend/cache.py) as the backend uses it.
# The real lookups are swapped for fakes (with monkeypatch) that count how often they are asked,
# so nothing goes over the internet and no API key is needed.

import pytest
from fastapi.testclient import TestClient

from backend import cache, main

client = TestClient(main.app)
MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
OTHER = "a" * 64
FOUND = {"status": "ok", "data": {"name": "demo"}, "error": None}
NOT_FOUND = {"status": "not_found", "data": None, "error": None}
ERROR = {"status": "error", "data": None, "error": "Took longer than 12 seconds"}


# Make a fake lookup that writes down every call and gives its answers one by one (the last one repeats).
def counting_lookup(answers):
    calls = []

    # The fake lookup: write down the call, then give the next answer.
    def lookup(file_hash):
        calls.append(file_hash)
        return answers[min(len(calls), len(answers)) - 1]

    lookup.calls = calls
    return lookup


# Replace all three sources with fakes that give these answers. Returns the fakes by source name.
def use_fakes(monkeypatch, answers):
    fakes = {}
    for name in main.SOURCES:
        fakes[name] = counting_lookup(answers)
        monkeypatch.setitem(main.SOURCES, name, fakes[name])
    return fakes


# Ask the backend about one hash, like the page does.
def ask(file_hash):
    return client.get(f"/api/v1/hash/{file_hash}")


def test_a_miss_asks_every_source(monkeypatch):
    fakes = use_fakes(monkeypatch, [FOUND])
    ask(MIRAI)
    assert [len(fake.calls) for fake in fakes.values()] == [1, 1, 1]


def test_a_hit_does_not_ask_the_sources_again(monkeypatch):
    fakes = use_fakes(monkeypatch, [FOUND])
    ask(MIRAI)
    ask(MIRAI)
    assert [len(fake.calls) for fake in fakes.values()] == [1, 1, 1]


def test_an_expired_entry_is_asked_again_and_each_source_has_its_own_time(monkeypatch):
    fakes = use_fakes(monkeypatch, [FOUND])
    now = [1000.0]
    monkeypatch.setattr(cache, "clock", lambda: now[0])  # a fake clock we can move
    ask(MIRAI)
    now[0] += 31 * 60  # 31 minutes: only VirusTotal (30 minutes) has expired
    ask(MIRAI)
    assert [len(fakes[name].calls) for name in ("virustotal", "malwarebazaar", "threatfox")] == [2, 1, 1]
    now[0] += 7 * 60 * 60  # 7 more hours: everything has expired
    ask(MIRAI)
    assert [len(fakes[name].calls) for name in ("virustotal", "malwarebazaar", "threatfox")] == [3, 2, 2]


def test_an_error_is_not_cached(monkeypatch):
    fakes = use_fakes(monkeypatch, [ERROR, FOUND])  # the first answer is an error, then it works
    first = ask(MIRAI)
    second = ask(MIRAI)
    assert first.json()["sources"]["virustotal"]["status"] == "error"
    assert [len(fake.calls) for fake in fakes.values()] == [2, 2, 2]  # the error was asked again
    assert second.json()["sources"]["virustotal"]["status"] == "ok"
    ask(MIRAI)
    assert [len(fake.calls) for fake in fakes.values()] == [2, 2, 2]  # the good answer is now kept


def test_spellings_share_one_entry_and_different_hashes_and_sources_never_do(monkeypatch):
    fakes = use_fakes(monkeypatch, [FOUND])
    ask(MIRAI)
    ask(MIRAI.upper())  # the same hash typed in capitals: the same entry
    assert [len(fake.calls) for fake in fakes.values()] == [1, 1, 1]
    ask(OTHER)  # a different hash: its own entries
    assert [len(fake.calls) for fake in fakes.values()] == [2, 2, 2]
    # The keys are only (source, hash): one per source and hash, and nothing else (no API key).
    expected = {(name, file_hash) for name in main.SOURCES for file_hash in (MIRAI, OTHER)}
    assert set(cache._entries) == expected


def test_the_answer_body_is_the_same_on_a_miss_a_hit_and_a_partial_hit(monkeypatch):
    use_fakes(monkeypatch, [FOUND])
    miss = ask(MIRAI)
    hit = ask(MIRAI)
    cache.clear()
    cache.put("threatfox", MIRAI, FOUND)  # only the LAST source is cached (it must not jump to the front)
    partial = ask(MIRAI)
    assert hit.text == miss.text == partial.text
    assert list(partial.json()) == ["hash", "hash_type", "sources"]
    assert list(partial.json()["sources"]) == ["virustotal", "malwarebazaar", "threatfox"]


def test_a_not_found_answer_is_cached(monkeypatch):
    fakes = use_fakes(monkeypatch, [NOT_FOUND])
    ask(MIRAI)
    second = ask(MIRAI)
    assert [len(fake.calls) for fake in fakes.values()] == [1, 1, 1]
    assert second.json()["sources"]["virustotal"]["status"] == "not_found"


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
    note = open("frontend/app.py").read().split("CACHE_NOTE = ")[1].split("\n")[0]
    for found_seconds, label in [(cache.EXPIRY["virustotal"][0], "30 min"),
                                 (cache.EXPIRY["malwarebazaar"][0], "6 h"),
                                 (cache.EXPIRY["threatfox"][0], "1 h")]:
        assert label in note
        assert (found_seconds // 60 if "min" in label else found_seconds // 3600) == int(label.split()[0])
