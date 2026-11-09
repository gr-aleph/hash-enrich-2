# Tests for the backend endpoints. The real lookup functions are swapped out
# (with pytest's built-in monkeypatch) for fakes that return saved replies,
# so no source is ever called and no API key is needed.

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main
from backend.malwarebazaar import parse_malwarebazaar
from backend.threatfox import parse_threatfox
from backend.virustotal import parse_virustotal

FIXTURES = Path(__file__).parent / "fixtures"
MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
PARSERS = {"virustotal": parse_virustotal, "malwarebazaar": parse_malwarebazaar, "threatfox": parse_threatfox}

client = TestClient(main.app)


# Make a fake lookup function that returns the saved reply for one source and case.
def fake_lookup(source, case):
    saved = json.loads((FIXTURES / source / f"{case}.json").read_text())
    return lambda file_hash: PARSERS[source](saved["status_code"], saved["body"])


# Replace every source's lookup with a fake that returns the given case.
def use_saved_replies(monkeypatch, cases):
    for source, case in cases.items():
        monkeypatch.setitem(main.SOURCES, source, fake_lookup(source, case))


def test_health():
    reply = client.get("/api/v1/health")
    assert reply.status_code == 200
    assert reply.json() == {"status": "ok"}


def test_invalid_hash_gets_400():
    reply = client.get("/api/v1/hash/abc")
    assert reply.status_code == 400
    assert reply.json() == {"error": "Expected 32, 40 or 64 hex characters"}


def test_all_sources_found(monkeypatch):
    use_saved_replies(monkeypatch, {"virustotal": "hit", "malwarebazaar": "hit", "threatfox": "hit"})
    reply = client.get(f"/api/v1/hash/{MIRAI.upper()}")
    assert reply.status_code == 200
    body = reply.json()
    assert body["hash"] == MIRAI
    assert body["hash_type"] == "sha256"
    for source in ["virustotal", "malwarebazaar", "threatfox"]:
        assert body["sources"][source]["status"] == "ok"


def test_the_answer_has_a_verdict(monkeypatch):
    use_saved_replies(monkeypatch, {"virustotal": "hit", "malwarebazaar": "hit", "threatfox": "bad_key"})
    body = client.get(f"/api/v1/hash/{MIRAI}").json()
    assert list(body["verdict"]) == ["score", "label", "reasons", "failed_sources"]
    assert body["verdict"]["label"] == "malicious"
    assert body["verdict"]["failed_sources"] == ["threatfox"]


def test_one_failing_source_does_not_hide_the_others(monkeypatch):
    use_saved_replies(monkeypatch, {"virustotal": "bad_key", "malwarebazaar": "hit", "threatfox": "hit"})
    body = client.get(f"/api/v1/hash/{MIRAI}").json()
    assert body["sources"]["virustotal"]["status"] == "error"
    assert body["sources"]["malwarebazaar"]["status"] == "ok"
    assert body["sources"]["threatfox"]["status"] == "ok"


# A lookup that crashes with an unexpected error.
def crashing_lookup(file_hash):
    raise KeyError("something unexpected")


def test_crashing_source_becomes_an_error(monkeypatch):
    use_saved_replies(monkeypatch, {"virustotal": "hit", "malwarebazaar": "unknown", "threatfox": "unknown"})
    monkeypatch.setitem(main.SOURCES, "threatfox", crashing_lookup)
    reply = client.get(f"/api/v1/hash/{MIRAI}")
    assert reply.status_code == 200
    body = reply.json()
    assert body["sources"]["threatfox"]["status"] == "error"
    assert body["sources"]["virustotal"]["status"] == "ok"
    assert body["sources"]["malwarebazaar"]["status"] == "not_found"
