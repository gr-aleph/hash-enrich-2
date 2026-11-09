# Tests for backend/main.py: checking the hash, and how the sources are asked.
# The real lookups are swapped for fakes (with monkeypatch), so nothing goes over the internet.

import time

from fastapi.testclient import TestClient

from backend import main
from backend.main import get_hash_type

client = TestClient(main.app)
MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
called = []  # the fake lookups write down here which hashes they were asked about


# A fake lookup that only remembers it was called.
def recording_lookup(file_hash):
    called.append(file_hash)
    return {"status": "not_found", "data": None, "error": None}


# A fake lookup that takes half a second, like a slow website.
def half_second_lookup(file_hash):
    time.sleep(0.5)
    return {"status": "not_found", "data": None, "error": None}


def test_valid_lengths_give_the_right_type():
    assert get_hash_type("a" * 32) == "md5"
    assert get_hash_type("a" * 40) == "sha1"
    assert get_hash_type("a" * 64) == "sha256"


def test_wrong_lengths_are_rejected():
    assert get_hash_type("a" * 31) is None
    assert get_hash_type("a" * 33) is None
    assert get_hash_type("a" * 65) is None
    assert get_hash_type("") is None


def test_non_hex_character_is_rejected():
    assert get_hash_type("a" * 31 + "g") is None


def test_invalid_hash_calls_no_source(monkeypatch):
    called.clear()
    monkeypatch.setitem(main.SOURCES, "virustotal", recording_lookup)
    monkeypatch.setitem(main.SOURCES, "malwarebazaar", recording_lookup)
    monkeypatch.setitem(main.SOURCES, "threatfox", recording_lookup)
    reply = client.get("/api/v1/hash/abc")
    assert reply.status_code == 400
    assert called == []


def test_sources_are_asked_at_the_same_time(monkeypatch):
    monkeypatch.setitem(main.SOURCES, "virustotal", half_second_lookup)
    monkeypatch.setitem(main.SOURCES, "malwarebazaar", half_second_lookup)
    monkeypatch.setitem(main.SOURCES, "threatfox", half_second_lookup)
    start = time.time()
    reply = client.get(f"/api/v1/hash/{MIRAI}")
    took = time.time() - start
    assert reply.status_code == 200
    # One after another would take 1.5 seconds; at the same time takes about 0.5
    assert took < 1.2
