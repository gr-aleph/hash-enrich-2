# Tests for lookup_threatfox: the function that sends the request.
# requests.post is swapped for a fake (with monkeypatch), so nothing goes over the internet
# and no real API key is used.

from types import SimpleNamespace

import requests

from backend.threatfox import lookup_threatfox

HASH = "44d88612fea8a8f36de82e1278abb02f"
sent = []  # the fake requests.post writes down here what it was asked to send


# Fake requests.post: remembers the request and answers like ThreatFox does for an unknown hash.
def fake_post(url, **options):
    sent.append((url, options))
    return SimpleNamespace(status_code=200, json=lambda: {"query_status": "no_result"})


# Fake requests.post that fails like a source that is too slow.
def post_that_times_out(url, **options):
    raise requests.Timeout()


# Fake requests.post that fails like a computer with no internet.
def post_that_cannot_connect(url, **options):
    raise requests.ConnectionError()


# Fake requests.post whose reply is not JSON (for example an HTML error page).
def post_with_html_reply(url, **options):
    return SimpleNamespace(status_code=200, json=reply_is_not_json)


# What .json() does when the reply is not JSON.
def reply_is_not_json():
    raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)


def test_missing_key_sends_nothing(monkeypatch):
    sent.clear()
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.setattr(requests, "post", fake_post)
    result = lookup_threatfox(HASH)
    assert result["error"] == "ABUSECH_AUTH_KEY is not set in .env"
    assert sent == []


def test_sends_the_documented_request(monkeypatch):
    sent.clear()
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    monkeypatch.setattr(requests, "post", fake_post)
    result = lookup_threatfox(HASH)
    assert sent == [("https://threatfox-api.abuse.ch/api/v1/",
                     {"json": {"query": "search_ioc", "search_term": HASH, "exact_match": True},
                      "headers": {"Auth-Key": "test-key"}, "timeout": 10})]
    assert result["status"] == "not_found"


def test_problems_become_error_messages(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")

    monkeypatch.setattr(requests, "post", post_that_times_out)
    assert lookup_threatfox(HASH)["error"] == "Could not reach ThreatFox: Timeout"

    monkeypatch.setattr(requests, "post", post_that_cannot_connect)
    assert lookup_threatfox(HASH)["error"] == "Could not reach ThreatFox: ConnectionError"

    monkeypatch.setattr(requests, "post", post_with_html_reply)
    assert lookup_threatfox(HASH)["error"] == "ThreatFox sent a reply that is not JSON"
