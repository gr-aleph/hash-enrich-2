# Tests for what the MCP tool says when the portal itself is the problem. Every one is a tool error
# (the model can read the reason), never a crash. See mcp_helpers.py for how the portal is faked.

from types import SimpleNamespace

import pytest
import requests

from mcp_helpers import MIRAI, call_tool, error_text, portal_gives
from mcp_server import server


def test_the_portal_not_running_is_a_tool_error_with_a_clear_message(monkeypatch):
    def refused(url, **options):
        raise requests.ConnectionError()

    monkeypatch.setattr(requests, "get", refused)
    assert "is not running at http://127.0.0.1:8000" in error_text(call_tool(MIRAI))


def test_a_portal_that_is_too_slow_is_a_tool_error(monkeypatch):
    def too_slow(url, **options):
        raise requests.ReadTimeout()

    monkeypatch.setattr(requests, "get", too_slow)
    assert "did not answer within 20 seconds" in error_text(call_tool(MIRAI))


def test_the_portals_own_400_is_a_tool_error_with_its_reason(monkeypatch):
    monkeypatch.setattr(requests, "get", portal_gives("invalid")[0])
    monkeypatch.setattr(server, "check_hash", lambda file_hash: file_hash)  # pretend our own check let it through
    assert "Expected 32, 40 or 64 hex characters" in error_text(call_tool(MIRAI))


@pytest.mark.parametrize("status, body, expected", [
    (500, {"detail": "boom"}, "answered HTTP 500"),
    (200, ["not", "a", "dictionary"], "unexpected shape"),
    (200, {"hash": MIRAI}, "unexpected shape"),
])
def test_other_portal_problems_are_tool_errors(monkeypatch, status, body, expected):
    monkeypatch.setattr(requests, "get", lambda url, **options: SimpleNamespace(status_code=status, json=lambda: body))
    assert expected in error_text(call_tool(MIRAI))


def test_an_answer_that_is_not_json_is_a_tool_error(monkeypatch):
    def not_json():
        raise ValueError("not json")

    monkeypatch.setattr(requests, "get", lambda url, **options: SimpleNamespace(status_code=502, json=not_json))
    assert "not JSON (HTTP 502)" in error_text(call_tool(MIRAI))
