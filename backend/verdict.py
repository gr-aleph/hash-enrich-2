# The overall verdict for one hash, worked out from the sources' results (design.md, "Verdict").
# It only reads the results it is given: no network and no cache, so it is easy to test.
# Fields are read with .get(), so a missing field never crashes the answer (a valid hash always gets 200).
# The score (0-100) says how much evidence of harm we found. 0 means "nothing found",
# never "safe", which is why there is no "clean" label.

MALICIOUS_FROM = 75    # a score of 75 or more is "malicious"
SUSPICIOUS_FROM = 40   # 40 to 74 is "suspicious"; below 40 is "unknown"
VT_MANY_ENGINES = 5    # this many VirusTotal engines saying "malicious" is strong evidence
THREATFOX_LOWEST = 40  # any ThreatFox match scores at least this (so at least "suspicious")

SOURCE_NAMES = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox"}


# Score VirusTotal's detection counts (90, 60, 40 or 0) and say why.
def virustotal_score(data):
    malicious = data.get("malicious") or 0  # a missing count counts as 0
    suspicious = data.get("suspicious") or 0
    if malicious >= VT_MANY_ENGINES:
        return 90, f"VirusTotal: {malicious} engines say malicious"
    if malicious >= 1:
        return 60, f"VirusTotal: {malicious} engine(s) say malicious"
    if suspicious >= 1:
        return 40, f"VirusTotal: no engine says malicious, {suspicious} say suspicious"
    return 0, "VirusTotal knows this file, but no engine flags it. This does not mean it is safe."


# Score a MalwareBazaar hit: it only stores malware samples, so being there is strong evidence.
def malwarebazaar_score(data):
    signature = data.get("signature") or "no signature given"
    return 90, f"MalwareBazaar has this file as a malware sample ({signature})"


# Score a ThreatFox hit: its highest confidence (0-100), but never below THREATFOX_LOWEST.
def threatfox_score(data):
    score = THREATFOX_LOWEST
    for match in data.get("matches", []):
        confidence = match.get("confidence_level")  # None if ThreatFox gave none
        if confidence is not None and confidence > score:
            score = confidence
    return score, f"ThreatFox lists this hash as an indicator (score {score})"


# Which function scores which source
SCORE_FUNCTIONS = {
    "virustotal": virustotal_score,
    "malwarebazaar": malwarebazaar_score,
    "threatfox": threatfox_score,
}


# Turn a score into a label: "malicious", "suspicious" or "unknown".
def label_for(score):
    if score >= MALICIOUS_FROM:
        return "malicious"
    if score >= SUSPICIOUS_FROM:
        return "suspicious"
    return "unknown"


# Work out the verdict from all sources' results ({name: {"status", "data", "error"}}).
# The highest source score wins. Sources that failed are listed, never silently skipped.
def make_verdict(sources):
    score = 0
    reasons = []
    failed_sources = []
    for name, result in sources.items():
        if result["status"] == "ok":
            source_score, reason = SCORE_FUNCTIONS[name](result["data"])
            score = max(score, source_score)
            reasons.append(reason)
        elif result["status"] == "error":
            failed_sources.append(name)
    if not reasons:
        reasons.append("No source that answered knows this hash. This does not mean it is safe.")
    for name in failed_sources:
        reasons.append(f"{SOURCE_NAMES[name]} failed, so this verdict may be incomplete.")
    return {"score": score, "label": label_for(score), "reasons": reasons, "failed_sources": failed_sources}
