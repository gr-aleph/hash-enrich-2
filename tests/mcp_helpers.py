# Shared helpers for the MCP server tests (test_mcp_tool.py, test_mcp_portal_problems.py, test_mcp_stdio.py).
# No portal needs to be running. The portal's answers are RECORDINGS of its real API, saved in
# tests/fixtures/portal, made by running the real backend on the saved source replies in tests/fixtures. requests.get is swapped for a
# fake (with monkeypatch) that gives a recording back and writes down every address it was asked for,
# so nothing goes over the internet and no API key is needed.
# asyncio.run runs the SDK's Client (which is async) from an ordinary test function.

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mcp import Client

from mcp_server import server

FIXTURES = Path(__file__).parent / "fixtures" / "portal"
MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"
PORTAL_ADDRESS = f"http://127.0.0.1:8000/api/v1/hash/{MIRAI}"


# Read one recorded portal answer: (status_code, body).
def recorded(name):
    saved = json.loads((FIXTURES / f"{name}.json").read_text())
    return saved["status_code"], saved["body"]


# Make a fake requests.get that answers with the recording `name`.
# Returns (the fake, the list it fills with the addresses it was asked for).
def portal_gives(name):
    status_code, body = recorded(name)
    asked = []

    def fake_get(url, **options):
        asked.append(url)
        return SimpleNamespace(status_code=status_code, json=lambda: body)

    return fake_get, asked


# Call the tool through the SDK's in-memory Client. Returns the result (is_error and content).
def call_tool(file_hash):
    async def run():
        async with Client(server.mcp) as client:
            return await client.call_tool("lookup_hash", {"file_hash": file_hash})

    return asyncio.run(run())


# The answer the model reads: the JSON text in the result's first content block.
def answer_of(result):
    assert not result.is_error
    return json.loads(result.content[0].text)


# The message the model reads when a call fails.
def error_text(result):
    assert result.is_error
    return result.content[0].text
