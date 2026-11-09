# Tests for the Streamlit page (frontend/app.py).
# AppTest (built into Streamlit) runs the page without a browser: we type a hash,
# click the button and read what the page shows.
# requests.get is swapped for a fake (with monkeypatch), so the backend is never called.

from pathlib import Path
from types import SimpleNamespace

import requests
from streamlit.testing.v1 import AppTest

PAGE = str(Path(__file__).parent.parent / "frontend" / "app.py")
MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
NOT_FOUND = {"status": "not_found", "data": None, "error": None}


# Run the page, type a hash, click "Look up", and return the page so a test can read it.
def look_up(file_hash):
    page = AppTest.from_file(PAGE)
    page.run()
    page.text_input[0].input(file_hash)
    page.button[0].click()
    page.run()
    return page


# Fake requests.get: the backend is not running.
def backend_down(url, **options):
    raise requests.ConnectionError()


# Fake requests.get: the backend does not answer in time.
def backend_too_slow(url, **options):
    raise requests.Timeout()


# Fake requests.get: the backend says the hash is invalid.
def backend_says_400(url, **options):
    return SimpleNamespace(status_code=400, json=lambda: {"error": "Expected 32, 40 or 64 hex characters"})


# Fake requests.get: FastAPI's own 404 (what a hash containing "/" gets).
def backend_says_404(url, **options):
    return SimpleNamespace(status_code=404, json=lambda: {"detail": "Not Found"})


# Fake requests.get: a normal answer where one source failed.
def backend_answers(url, **options):
    body = {"hash": MIRAI, "hash_type": "sha256", "sources": {
        "virustotal": NOT_FOUND,
        "malwarebazaar": NOT_FOUND,
        "threatfox": {"status": "error", "data": None, "error": "Took longer than 12 seconds"},
    }}
    return SimpleNamespace(status_code=200, json=lambda: body)


def test_backend_down(monkeypatch):
    monkeypatch.setattr(requests, "get", backend_down)
    page = look_up(MIRAI)
    assert page.error[0].value == "Backend not running at http://127.0.0.1:8000"


def test_backend_too_slow(monkeypatch):
    monkeypatch.setattr(requests, "get", backend_too_slow)
    page = look_up(MIRAI)
    assert page.error[0].value == "The backend took longer than 20 seconds to answer"


def test_invalid_hash_message(monkeypatch):
    monkeypatch.setattr(requests, "get", backend_says_400)
    page = look_up("abc")
    assert page.error[0].value == "Expected 32, 40 or 64 hex characters"


def test_404_does_not_crash_the_page(monkeypatch):
    monkeypatch.setattr(requests, "get", backend_says_404)
    page = look_up("abc/def")
    assert len(page.exception) == 0
    assert page.error[0].value == "The backend answered HTTP 404"


def test_one_failed_source_still_shows_all_three(monkeypatch):
    monkeypatch.setattr(requests, "get", backend_answers)
    page = look_up(MIRAI)
    assert [heading.value for heading in page.subheader] == ["VirusTotal", "MalwareBazaar", "ThreatFox"]
    assert page.error[0].value == "Took longer than 12 seconds"
