# Tests for lookup_virustotal: the function that sends the request.
# requests.get is swapped for a fake (with monkeypatch), so nothing goes over the internet
# and no real API key is used.

from types import SimpleNamespace

import requests

from backend.virustotal import lookup_virustotal

HASH = "44d88612fea8a8f36de82e1278abb02f"
sent = []  # the fake requests.get writes down here what it was asked to send


# Fake requests.get: remembers the request and answers like VirusTotal does for an unknown hash.
def fake_get(url, **options):
    sent.append((url, options))
    return SimpleNamespace(status_code=404, json=lambda: {"error": {"code": "NotFoundError"}})


# Fake requests.get that fails like a source that is too slow.
def get_that_times_out(url, **options):
    raise requests.Timeout()


# Fake requests.get that fails like a computer with no internet.
def get_that_cannot_connect(url, **options):
    raise requests.ConnectionError()


# Fake requests.get whose reply is not JSON (for example an HTML error page).
def get_with_html_reply(url, **options):
    return SimpleNamespace(status_code=200, json=reply_is_not_json)


# What .json() does when the reply is not JSON.
def reply_is_not_json():
    raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)


def test_missing_key_sends_nothing(monkeypatch):
    sent.clear()
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(requests, "get", fake_get)
    result = lookup_virustotal(HASH)
    assert result["error"] == "VT_API_KEY is not set in .env"
    assert sent == []


def test_sends_the_documented_request(monkeypatch):
    sent.clear()
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(requests, "get", fake_get)
    result = lookup_virustotal(HASH)
    assert sent == [(f"https://www.virustotal.com/api/v3/files/{HASH}",
                     {"headers": {"x-apikey": "test-key"}, "timeout": 10})]
    assert result["status"] == "not_found"


def test_problems_become_error_messages(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    monkeypatch.setattr(requests, "get", get_that_times_out)
    assert lookup_virustotal(HASH)["error"] == "Could not reach VirusTotal: Timeout"

    monkeypatch.setattr(requests, "get", get_that_cannot_connect)
    assert lookup_virustotal(HASH)["error"] == "Could not reach VirusTotal: ConnectionError"

    monkeypatch.setattr(requests, "get", get_with_html_reply)
    assert lookup_virustotal(HASH)["error"] == "VirusTotal sent a reply that is not JSON"
