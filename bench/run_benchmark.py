# Fixed-run benchmark: how many outbound web requests does one fixed list of lookups cause?
#
# Run it from the project folder, with the project's Python:
#   python bench/run_benchmark.py before     # on the code WITHOUT the cache -> bench/results/before.json
#   python bench/run_benchmark.py after      # on the code WITH the cache    -> bench/results/after.json
#   python bench/run_benchmark.py compare    # print both tables and check that every answer is unchanged
#
# It spends no real quota:
#   * requests.get and requests.post are replaced by a counting fake that answers from the saved
#     replies in tests/fixtures, so no request leaves the computer;
#   * real network connections are switched off, so a request that escaped the fake would crash
#     instead of being sent;
#   * the keys are dummy values. load_dotenv() never overwrites a setting that already exists,
#     so a real key in .env is never used.
# The list of lookups never changes and the script only talks to the app through its test client,
# so the SAME file runs before and after. Only the code under test differs.

import hashlib
import json
import os
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT = Path(__file__).resolve().parent.parent
FIXTURES = PROJECT / "tests" / "fixtures"
RESULTS = PROJECT / "bench" / "results"
SOURCES = ["virustotal", "malwarebazaar", "threatfox"]


def no_network(*args, **options):
    raise RuntimeError("the benchmark tried to use the network")


# Dummy keys and no network, BEFORE the app is imported.
for key_name in ("VT_API_KEY", "ABUSECH_AUTH_KEY"):
    os.environ[key_name] = "benchmark-dummy-not-a-key"
socket.socket.connect = no_network
socket.getaddrinfo = no_network
sys.path.insert(0, str(PROJECT))

import requests  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402

assert os.environ["VT_API_KEY"] == "benchmark-dummy-not-a-key", "a real key was loaded"

MIRAI = "add97f691f8bd8af5efe0480a90f12bcdcfa089f7432088b4ff8bd0606ff58de"  # found by all three
EICAR = "44d88612fea8a8f36de82e1278abb02f"  # found on VirusTotal only
ZEROS = "0" * 64  # known to nobody
FLAKY = "1" * 40  # VirusTotal and MalwareBazaar answer; ThreatFox fails with an error every time
OTHER = "d41d8cd98f00b204e9800998ecf8427e"  # known to nobody

# Which saved reply each source gives for each hash: (virustotal, malwarebazaar, threatfox)
ANSWERS = {
    MIRAI: ("hit", "hit", "hit"),
    EICAR: ("hit", "unknown", "unknown"),
    ZEROS: ("unknown", "unknown", "unknown"),
    FLAKY: ("hit", "unknown", "bad_key"),
    OTHER: ("unknown", "unknown", "unknown"),
}

# The fixed run: 24 lookups. Repeats, one hash in three spellings (lower, UPPER, mixed case), an error that repeats, invalid input.
RUN = [
    MIRAI, MIRAI, MIRAI.upper(), MIRAI[:32].upper() + MIRAI[32:],
    EICAR, EICAR, EICAR.upper(),
    ZEROS, ZEROS, ZEROS,
    FLAKY, FLAKY, FLAKY,
    MIRAI, EICAR,
    "abc", "%20" + EICAR,  # invalid: too short; a leading space (the page strips spaces, the backend does not)
    MIRAI.upper(),
    OTHER, OTHER, OTHER.upper(),
    MIRAI, FLAKY, ZEROS,
]

counts = {name: 0 for name in SOURCES}


# Build a reply from a saved one, like the replies the tests use.
def saved_reply(source, case):
    saved = json.loads((FIXTURES / source / f"{case}.json").read_text())
    return SimpleNamespace(status_code=saved["status_code"], json=lambda: saved["body"])


# Fake requests.get: only VirusTotal uses GET. The hash is the end of the address.
def fake_get(url, **options):
    counts["virustotal"] += 1
    return saved_reply("virustotal", ANSWERS[url.rsplit("/", 1)[1]][0])


# Fake requests.post: MalwareBazaar sends the hash in a form, ThreatFox in a JSON body.
def fake_post(url, **options):
    if "mb-api" in url:
        counts["malwarebazaar"] += 1
        return saved_reply("malwarebazaar", ANSWERS[options["data"]["hash"]][1])
    counts["threatfox"] += 1
    return saved_reply("threatfox", ANSWERS[options["json"]["search_term"]][2])


# Run the fixed list through the app and save what was counted and what each lookup answered.
def run(label):
    requests.get, requests.post = fake_get, fake_post
    client = TestClient(app)
    lookups = []
    for typed in RUN:
        reply = client.get(f"/api/v1/hash/{typed}")
        # A short fingerprint of the exact answer text, to compare before and after
        lookups.append({"typed": typed[:12] + "...", "status": reply.status_code,
                        "answer": hashlib.sha256(reply.text.encode()).hexdigest()[:12]})
    result = {"label": label, "lookups_made": len(RUN), "requests_per_source": dict(counts),
              "requests_total": sum(counts.values()), "lookups": lookups}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{label}.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{label}: {len(RUN)} lookups")
    for name in SOURCES:
        print(f"  {name:14} {counts[name]:3d} outbound requests")
    print(f"  {'total':14} {result['requests_total']:3d}")


# Print both tables, and check that every lookup gave exactly the same answer both times.
def compare():
    before = json.loads((RESULTS / "before.json").read_text())
    after = json.loads((RESULTS / "after.json").read_text())
    print(f"{'':14} {'before':>7} {'after':>7}")
    for name in SOURCES:
        print(f"{name:14} {before['requests_per_source'][name]:7d} {after['requests_per_source'][name]:7d}")
    print(f"{'total':14} {before['requests_total']:7d} {after['requests_total']:7d}")
    same = before["lookups"] == after["lookups"]
    print("\nevery answer is unchanged" if same else "\nSOME ANSWERS CHANGED")
    sys.exit(0 if same else 1)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode in ("before", "after"):
        run(mode)
    elif mode == "compare":
        compare()
    else:
        print(__doc__ if __doc__ else "usage: python bench/run_benchmark.py before|after|compare")
