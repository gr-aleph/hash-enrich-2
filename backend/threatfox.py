# ThreatFox (abuse.ch): look up a file hash as an IOC (indicator of compromise).
#   lookup_threatfox  sends the request over the internet
#   parse_threatfox   turns (status_code, json_body) into a result dict (easy to test)
# The API key comes from ABUSECH_AUTH_KEY (main.py loads it from .env).
# We use "search_ioc", not "search_hash": search_hash returns IOCs linked to a sample,
# not the hash itself.

import os

import requests

TIMEOUT_SECONDS = 10
URL = "https://threatfox-api.abuse.ch/api/v1/"


# Build a result dict in the same shape for every source.
def make_result(status, data=None, error=None):
    return {"status": status, "data": data, "error": error}


# Turn a ThreatFox reply into a result dict.
def parse_threatfox(status_code, body):
    query_status = body.get("query_status")

    if status_code in (401, 403) or query_status == "unknown_auth_key":
        return make_result("error", error=f"ThreatFox rejected the API key (HTTP {status_code})")
    if status_code == 429:
        return make_result("error", error="ThreatFox rate limit reached (HTTP 429), try again later")
    if status_code != 200:
        return make_result("error", error=f"ThreatFox answered HTTP {status_code}")
    if query_status == "no_result":
        return make_result("not_found")
    if query_status != "ok":
        return make_result("error", error=f"ThreatFox answered {query_status}")

    # ThreatFox can list the same hash more than once, so keep every match
    matches = []
    for ioc in body["data"]:
        matches.append({
            "malware_printable": ioc.get("malware_printable"),
            "threat_type": ioc.get("threat_type"),
            "confidence_level": ioc.get("confidence_level"),
            "first_seen": ioc.get("first_seen"),
            "malpedia": ioc.get("malware_malpedia"),
        })
    return make_result("ok", data={"matches": matches})


# Ask ThreatFox about a hash (lookup only, never uploads a file).
def lookup_threatfox(file_hash):
    key = os.getenv("ABUSECH_AUTH_KEY")
    if not key:
        return make_result("error", error="ABUSECH_AUTH_KEY is not set in .env")

    question = {"query": "search_ioc", "search_term": file_hash, "exact_match": True}
    try:
        reply = requests.post(URL, json=question, headers={"Auth-Key": key}, timeout=TIMEOUT_SECONDS)
        return parse_threatfox(reply.status_code, reply.json())
    # ValueError must come first: a bad JSON reply counts as both kinds of problem
    except ValueError:
        return make_result("error", error="ThreatFox sent a reply that is not JSON")
    except requests.RequestException as problem:
        return make_result("error", error=f"Could not reach ThreatFox: {type(problem).__name__}")
