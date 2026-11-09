# Tests with the REAL server process (mcp_server/server.py started as a subprocess, the way Claude Desktop does).
# The portal is a tiny stand-in on a free local port that gives the recorded "found" answer.
# 1. The SDK's Client can list the tool and call it through the real process.
# 2. Every line the process writes to stdout is an MCP message. This needs its own test because the Client
#    quietly drops a line it cannot read, so a stray print() would not make test 1 fail.

import asyncio
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from mcp import Client, StdioServerParameters

from mcp_helpers import MIRAI, answer_of, recorded

SERVER_FILE = Path(__file__).parent.parent / "mcp_server" / "server.py"


# Start the stand-in portal. Returns the HTTP server (its port is stub.server_address[1]).
def start_stub_portal():
    status_code, body = recorded("found")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = json.dumps(body).encode()
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *arguments):
            pass

    stub = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    return stub


def test_the_real_server_process_can_be_listed_and_called_through_the_client():
    stub = start_stub_portal()
    parameters = StdioServerParameters(command=sys.executable, args=[str(SERVER_FILE)],
                                       env={"PORTAL_URL": f"http://127.0.0.1:{stub.server_address[1]}"})

    async def run():
        async with Client(parameters) as client:
            tools = (await client.list_tools()).tools
            good = await client.call_tool("lookup_hash", {"file_hash": MIRAI})
            bad = await client.call_tool("lookup_hash", {"file_hash": "not-a-hash"})
            return tools, good, bad

    tools, good, bad = asyncio.run(run())
    stub.shutdown()
    assert [tool.name for tool in tools] == ["lookup_hash"]
    assert answer_of(good)["hash"] == MIRAI
    assert bad.is_error and "Not a valid hash" in bad.content[0].text


# Send one JSON-RPC message to the server's input.
def send(process, message):
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def test_every_line_the_real_server_writes_to_stdout_is_an_mcp_message():
    stub = start_stub_portal()
    environment = {**os.environ, "PORTAL_URL": f"http://127.0.0.1:{stub.server_address[1]}"}  # works on Windows and macOS
    process = subprocess.Popen([sys.executable, str(SERVER_FILE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, text=True)
    watchdog = threading.Timer(30, process.kill)  # never hang the test run
    watchdog.start()
    try:
        send(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
        process.stdout.readline()  # the answer to initialize
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "lookup_hash", "arguments": {"file_hash": MIRAI}}})
        process.stdout.readline()  # the answer to the tool call
        process.stdin.close()  # end of input: the server exits and flushes everything it has written
        rest = process.stdout.read()
        process.wait(timeout=10)
    finally:
        watchdog.cancel()
        process.kill()
        stub.shutdown()
    for line in rest.splitlines():
        assert line.strip() == "" or json.loads(line)["jsonrpc"] == "2.0", f"not an MCP message: {line!r}"
