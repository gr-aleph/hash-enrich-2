# Tests for the overall verdict (backend/verdict.py). Scale: 0 = safe, 100 = malicious.
# make_verdict only reads the dicts it is given, so we build small results by hand:
# no network, no saved replies and no monkeypatch needed.

from backend.verdict import make_verdict

NOT_FOUND = {"status": "not_found", "data": None, "error": None}
FAILED = {"status": "error", "data": None, "error": "Took longer than 12 seconds"}
MALWAREBAZAAR_HIT = {"status": "ok", "data": {"signature": "Mirai"}, "error": None}


# A VirusTotal "found" result with these detection counts (by default 60 engines found nothing).
def virustotal_hit(malicious, suspicious=0, undetected=60):
    data = {"malicious": malicious, "suspicious": suspicious, "harmless": 0, "undetected": undetected}
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
    assert verdict["score"] == 65
    assert verdict["label"] == "suspicious"


def test_virustotal_only_suspicious_engines_is_suspicious():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0, suspicious=3)))
    assert verdict["score"] == 60
    assert verdict["label"] == "suspicious"


def test_virustotal_clean_from_enough_engines_and_all_answered_is_safe():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0)))
    assert verdict["score"] == 0
    assert verdict["label"] == "safe"
    assert verdict["reasons"] == ["VirusTotal: none of 60 engines flags it"]


def test_virustotal_clean_from_too_few_engines_is_suspicious():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0, undetected=10)))
    assert verdict["score"] == 50
    assert verdict["label"] == "suspicious"


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
    assert verdict["score"] == 60
    assert verdict["label"] == "suspicious"


def test_threatfox_without_confidence_counts_as_suspicious():
    verdict = make_verdict(sources(threatfox=threatfox_hit(None)))
    assert verdict["score"] == 60


def test_the_highest_source_wins_and_every_hit_gives_a_reason():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0), malwarebazaar=MALWAREBAZAAR_HIT,
                                   threatfox=threatfox_hit(50)))
    assert verdict["score"] == 90
    assert len(verdict["reasons"]) == 3


def test_not_found_anywhere_is_suspicious_not_safe():
    verdict = make_verdict(sources())
    assert verdict == {
        "score": 50,
        "label": "suspicious",
        "reasons": ["No source knows this hash. Not being known is not proof it is safe, so it needs checking."],
        "failed_sources": [],
    }


def test_clean_on_virustotal_but_a_failed_source_is_not_safe():
    verdict = make_verdict(sources(virustotal=virustotal_hit(0), threatfox=FAILED))
    assert verdict["score"] == 50
    assert verdict["label"] == "suspicious"
    assert verdict["failed_sources"] == ["threatfox"]
    assert "Not called safe because a source failed." in verdict["reasons"]


def test_a_failed_source_is_listed_and_a_hit_elsewhere_still_counts():
    verdict = make_verdict(sources(malwarebazaar=MALWAREBAZAAR_HIT, threatfox=FAILED))
    assert verdict["label"] == "malicious"
    assert verdict["failed_sources"] == ["threatfox"]
    assert "ThreatFox failed, so this verdict may be incomplete." in verdict["reasons"]


def test_all_sources_failed_is_suspicious_and_lists_all_three():
    verdict = make_verdict(sources(virustotal=FAILED, malwarebazaar=FAILED, threatfox=FAILED))
    assert verdict["score"] == 50
    assert verdict["label"] == "suspicious"
    assert verdict["failed_sources"] == ["virustotal", "malwarebazaar", "threatfox"]
