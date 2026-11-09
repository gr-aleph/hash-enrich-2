# Tests for the overall verdict (backend/verdict.py).
# make_verdict only reads the dicts it is given, so we build small results by hand:
# no network, no saved replies and no monkeypatch needed.

from backend.verdict import make_verdict

NOT_FOUND = {"status": "not_found", "data": None, "error": None}
FAILED = {"status": "error", "data": None, "error": "Took longer than 12 seconds"}
MALWAREBAZAAR_HIT = {"status": "ok", "data": {"signature": "Mirai"}, "error": None}


# A VirusTotal "found" result with these detection counts.
def virustotal_hit(malicious, suspicious=0):
    data = {"malicious": malicious, "suspicious": suspicious, "harmless": 0, "undetected": 60}
    return {"status": "ok", "data": data, "error": None}


# A ThreatFox "found" result with one match at this confidence.
def threatfox_hit(confidence):
    return {"status": "ok", "data": {"matches": [{"confidence_level": confidence}]}, "error": None}


# The three sources in the order the backend sends them.
def sources(virustotal=NOT_FOUND, malwarebazaar=NOT_FOUND, threatfox=NOT_FOUND):
    return {"virustotal": virustotal, "malwarebazaar": malwarebazaar, "threatfox": threatfox}


def test_virustotal_many_engines_is_malicious():
    verdict = make_verdict(sources(virustotal=virustotal_hit(5)))
    assert verdict["score"] == 90
    assert verdict["label"] == "malicious"


def test_virustotal_few_engines_is_suspicious():
    verdict = make_verdict(sources(virustotal=virustotal_hit(2)))
    assert verdict["score"] == 60
    assert verdict["label"] == "suspicious"


def test_virustotal_only_suspicious_engines_is_suspicious():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0, suspicious=3)))
    assert verdict["score"] == 40
    assert verdict["label"] == "suspicious"


def test_virustotal_no_detections_is_unknown_not_safe():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0)))
    assert verdict["score"] == 0
    assert verdict["label"] == "unknown"
    assert "does not mean it is safe" in verdict["reasons"][0]


def test_malwarebazaar_hit_alone_is_malicious():
    verdict = make_verdict(sources(malwarebazaar=MALWAREBAZAAR_HIT))
    assert verdict["score"] == 90
    assert verdict["label"] == "malicious"
    assert "Mirai" in verdict["reasons"][0]


def test_threatfox_high_confidence_is_malicious():
    verdict = make_verdict(sources(threatfox=threatfox_hit(100)))
    assert verdict["score"] == 100
    assert verdict["label"] == "malicious"


def test_threatfox_low_confidence_still_counts_as_suspicious():
    verdict = make_verdict(sources(threatfox=threatfox_hit(30)))
    assert verdict["score"] == 40
    assert verdict["label"] == "suspicious"


def test_threatfox_without_confidence_counts_as_suspicious():
    verdict = make_verdict(sources(threatfox=threatfox_hit(None)))
    assert verdict["score"] == 40


def test_the_highest_source_wins_and_every_hit_gives_a_reason():
    verdict = make_verdict(sources(virustotal=virustotal_hit(2), malwarebazaar=MALWAREBAZAAR_HIT,
                                   threatfox=threatfox_hit(50)))
    assert verdict["score"] == 90
    assert len(verdict["reasons"]) == 3


def test_not_found_anywhere_is_unknown_not_safe():
    verdict = make_verdict(sources())
    assert verdict == {
        "score": 0,
        "label": "unknown",
        "reasons": ["No source that answered knows this hash. This does not mean it is safe."],
        "failed_sources": [],
    }


def test_a_failed_source_is_listed_and_a_hit_elsewhere_still_counts():
    verdict = make_verdict(sources(malwarebazaar=MALWAREBAZAAR_HIT, threatfox=FAILED))
    assert verdict["label"] == "malicious"
    assert verdict["failed_sources"] == ["threatfox"]
    assert "ThreatFox failed, so this verdict may be incomplete." in verdict["reasons"]


def test_all_sources_failed_is_unknown_and_lists_all_three():
    verdict = make_verdict(sources(virustotal=FAILED, malwarebazaar=FAILED, threatfox=FAILED))
    assert verdict["score"] == 0
    assert verdict["label"] == "unknown"
    assert verdict["failed_sources"] == ["virustotal", "malwarebazaar", "threatfox"]
