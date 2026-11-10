# The overall verdict for one hash, worked out from the sources' results (shape: design.md, section "API").
# It only reads the results it is given: no network and no cache, so it is easy to test.
# Fields are read with .get(), so a missing field never crashes the answer (a valid hash always gets 200).
# Scale: 0 = safe, 100 = malicious. "Safe" needs real proof; a hash nobody knows is suspicious.

SUSPICIOUS_FROM = 30   # 0-29 is "safe", 30-69 is "suspicious"
MALICIOUS_FROM = 70    # 70-100 is "malicious"
UNKNOWN_SCORE = 50     # nobody knows the hash: never "safe", but below any real evidence of harm (a choice, not a probability)
VT_ENOUGH_ENGINES = 30  # VirusTotal must have this many engines check a file before we call it safe
VT_MANY_ENGINES = 5    # this many VirusTotal engines saying "malicious" is strong evidence
THREATFOX_LOWEST = 60  # any ThreatFox match scores at least this (so at least "suspicious")

SOURCE_NAMES = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox"}


# Score VirusTotal's detection counts (90, 65, 60, 50 or 0) and say why.
def virustotal_score(data):
    malicious = data.get("malicious") or 0  # a missing count counts as 0
    suspicious = data.get("suspicious") or 0
    engines = (data.get("harmless") or 0) + (data.get("undetected") or 0)  # engines that found nothing
    if malicious >= VT_MANY_ENGINES:
        return 90, f"VirusTotal: {malicious} engines say malicious"
    if malicious >= 1:
        return 65, f"VirusTotal: {malicious} engine(s) say malicious"
    if suspicious >= 1:
        return 60, f"VirusTotal: no engine says malicious, {suspicious} say suspicious"
    if engines < VT_ENOUGH_ENGINES:
        return UNKNOWN_SCORE, f"VirusTotal: no engine flags it, but only {engines} engines checked it"
    return 0, f"VirusTotal: none of {engines} engines flags it"


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


# Turn a score into a label: "malicious", "suspicious" or "safe".
def label_for(score):
    if score >= MALICIOUS_FROM:
        return "malicious"
    if score >= SUSPICIOUS_FROM:
        return "suspicious"
    return "safe"


# Work out the verdict from all sources' results ({name: {"status", "data", "error"}}).
# The highest score of the sources that know the hash wins. Sources that failed are listed,
# and a hash is never called safe while a source failed.
def make_verdict(sources):
    scores = []
    reasons = []
    failed_sources = []
    for name, result in sources.items():
        if result["status"] == "ok":
            source_score, reason = SCORE_FUNCTIONS[name](result["data"])
            scores.append(source_score)
            reasons.append(reason)
        elif result["status"] == "error":
            failed_sources.append(name)

    if scores:
        score = max(scores)
    else:
        score = UNKNOWN_SCORE
        reasons.append("No source knows this hash. Not being known is not proof it is safe, so it needs checking.")

    for name in failed_sources:
        reasons.append(f"{SOURCE_NAMES[name]} failed, so this verdict may be incomplete.")
    if score < SUSPICIOUS_FROM and failed_sources:
        score = UNKNOWN_SCORE
        reasons.append("Not called safe because a source failed.")

    return {"score": score, "label": label_for(score), "reasons": reasons, "failed_sources": failed_sources}
