# Tests for the parse functions, using real replies saved in tests/fixtures.
# No network and no API keys are needed.

import json
from pathlib import Path

from backend.malwarebazaar import parse_malwarebazaar
from backend.threatfox import parse_threatfox
from backend.virustotal import parse_virustotal

FIXTURES = Path(__file__).parent / "fixtures"


# Read a saved reply and return (status_code, body).
def load(source, case):
    saved = json.loads((FIXTURES / source / f"{case}.json").read_text())
    return saved["status_code"], saved["body"]


# --- VirusTotal ---

def test_virustotal_hit():
    result = parse_virustotal(*load("virustotal", "hit"))
    assert result["status"] == "ok"
    assert result["data"]["malicious"] == 49
    assert result["data"]["first_submission_date"] == "2026-04-17 11:50:24 UTC"
    assert result["data"]["link"].endswith("add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de")


def test_virustotal_unknown():
    assert parse_virustotal(*load("virustotal", "unknown"))["status"] == "not_found"


def test_virustotal_bad_key():
    result = parse_virustotal(*load("virustotal", "bad_key"))
    assert result["status"] == "error"
    assert "API key" in result["error"]


# --- MalwareBazaar ---

def test_malwarebazaar_hit():
    result = parse_malwarebazaar(*load("malwarebazaar", "hit"))
    assert result["status"] == "ok"
    assert result["data"]["signature"] == "Mirai"
    assert result["data"]["tags"] == ["elf", "Mirai"]


def test_malwarebazaar_unknown():
    assert parse_malwarebazaar(*load("malwarebazaar", "unknown"))["status"] == "not_found"


def test_malwarebazaar_bad_key():
    result = parse_malwarebazaar(*load("malwarebazaar", "bad_key"))
    assert result["status"] == "error"
    assert "API key" in result["error"]


# --- ThreatFox ---

def test_threatfox_hit():
    result = parse_threatfox(*load("threatfox", "hit"))
    assert result["status"] == "ok"
    first_match = result["data"]["matches"][0]
    assert first_match["malware_printable"] == "Mirai"
    assert first_match["confidence_level"] == 90


def test_threatfox_unknown():
    assert parse_threatfox(*load("threatfox", "unknown"))["status"] == "not_found"


def test_threatfox_bad_key():
    result = parse_threatfox(*load("threatfox", "bad_key"))
    assert result["status"] == "error"
    assert "API key" in result["error"]
