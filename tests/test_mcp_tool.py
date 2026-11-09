# Tests for the tool itself (mcp_server/server.py): what it is called, what it returns, what it refuses.
# See mcp_helpers.py for how the portal is faked.

import asyncio
import json

import pytest
import requests
from mcp import Client
from types import SimpleNamespace

from mcp_helpers import MIRAI, PORTAL_ADDRESS, answer_of, call_tool, error_text, portal_gives, recorded
from mcp_server import server


def test_the_tool_is_listed_with_a_name_a_description_and_a_schema():
    async def run():
        async with Client(server.mcp) as client:
            return (await client.list_tools()).tools

    tools = asyncio.run(run())
    assert [tool.name for tool in tools] == ["lookup_hash"]
    tool = tools[0]
    for word in ("VirusTotal", "MalwareBazaar", "ThreatFox", "not_found", "refused", "confidential"):
        assert word in tool.description
    assert tool.input_schema["required"] == ["file_hash"]
    description = tool.input_schema["properties"]["file_hash"]["description"]  # the model reads this to know what to pass
    assert "hash" in description and "64" in description
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is True


def test_a_normal_answer_has_the_hash_its_type_and_the_three_sources(monkeypatch):
    fake, asked = portal_gives("found")
    monkeypatch.setattr(requests, "get", fake)
    answer = answer_of(call_tool(MIRAI))
    assert (answer["hash"], answer["hash_type"]) == (MIRAI, "sha256")
    assert {name: block["status"] for name, block in answer["sources"].items()} == {
        "virustotal": "ok", "malwarebazaar": "ok", "threatfox": "ok"}
    assert asked == [PORTAL_ADDRESS]


def test_not_found_is_an_answer_not_a_tool_error(monkeypatch):
    monkeypatch.setattr(requests, "get", portal_gives("not_found")[0])
    answer = answer_of(call_tool("0" * 64))
    assert {block["status"] for block in answer["sources"].values()} == {"not_found"}


def test_one_failing_source_is_passed_through_and_the_others_still_answer(monkeypatch):
    monkeypatch.setattr(requests, "get", portal_gives("one_source_error")[0])
    sources = answer_of(call_tool("1" * 40))["sources"]
    assert sources["threatfox"]["status"] == "error"
    assert "API key" in sources["threatfox"]["error"]
    assert sources["virustotal"]["status"] == "ok"


def test_the_hash_is_cleaned_before_it_is_sent(monkeypatch):
    fake, asked = portal_gives("found")
    monkeypatch.setattr(requests, "get", fake)
    call_tool("  " + MIRAI.upper() + "\n")
    assert asked == [PORTAL_ADDRESS]


@pytest.mark.parametrize("bad", ["abc", "", "g" * 32, "a" * 31, "a" * 65, "https://example.com/" + "a" * 20, "a" * 31 + " "])
def test_an_invalid_hash_is_a_tool_error_and_nothing_is_sent(monkeypatch, bad):
    fake, asked = portal_gives("found")
    monkeypatch.setattr(requests, "get", fake)
    message = error_text(call_tool(bad))
    assert "Not a valid hash" in message
    assert "Nothing was looked up" in message
    assert asked == []


def test_long_text_and_long_lists_from_a_source_are_cut(monkeypatch):
    body = json.loads(json.dumps(recorded("found")[1]))
    body["sources"]["virustotal"]["data"]["names"] = ["x" * 5000] + ["name"] * 50
    monkeypatch.setattr(requests, "get", lambda url, **options: SimpleNamespace(status_code=200, json=lambda: body))
    names = answer_of(call_tool(MIRAI))["sources"]["virustotal"]["data"]["names"]
    assert len(names) == server.MAX_ITEMS
    assert len(names[0]) == server.MAX_TEXT + 3 and names[0].endswith("...")
