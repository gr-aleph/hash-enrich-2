# VirusTotal: look up a file hash.
#   lookup_virustotal  sends the request over the internet
#   parse_virustotal   turns (status_code, json_body) into a result dict (easy to test)
# The API key comes from VT_API_KEY (main.py loads it from .env).

import os
from datetime import datetime, timezone

import requests

TIMEOUT_SECONDS = 10


# Build a result dict in the same shape for every source.
def make_result(status, data=None, error=None):
    return {"status": status, "data": data, "error": error}


# Turn a VirusTotal reply into a result dict.
def parse_virustotal(status_code, body):
    if status_code == 404:
        return make_result("not_found")
    if status_code == 401:
        return make_result("error", error="VirusTotal rejected the API key (HTTP 401)")
    if status_code == 429:
        return make_result("error", error="VirusTotal rate limit reached (HTTP 429), try again later")
    if status_code != 200:
        return make_result("error", error=f"VirusTotal answered HTTP {status_code}")

    sha256 = body["data"]["id"]
    attributes = body["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})

    # first_submission_date is a Unix timestamp (seconds since 1970); make it readable
    first_date = None
    timestamp = attributes.get("first_submission_date")
    if timestamp:
        first_date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    data = {
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "type_description": attributes.get("type_description"),
        "names": attributes.get("names", []),
        "first_submission_date": first_date,
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }
    return make_result("ok", data=data)


# Ask VirusTotal about a hash (lookup only, never uploads a file).
def lookup_virustotal(file_hash):
    key = os.getenv("VT_API_KEY")
    if not key:
        return make_result("error", error="VT_API_KEY is not set in .env")

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        reply = requests.get(url, headers={"x-apikey": key}, timeout=TIMEOUT_SECONDS)
        return parse_virustotal(reply.status_code, reply.json())
    # ValueError must come first: a bad JSON reply counts as both kinds of problem
    except ValueError:
        return make_result("error", error="VirusTotal sent a reply that is not JSON")
    except requests.RequestException as problem:
        return make_result("error", error=f"Could not reach VirusTotal: {type(problem).__name__}")
