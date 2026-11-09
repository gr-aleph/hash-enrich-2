# The Streamlit page. It only talks to our backend, never to the sources directly.
# Start it from the project folder with:
#   .venv\Scripts\python -m streamlit run frontend/app.py

import requests
import streamlit as st

BACKEND_URL = "http://127.0.0.1:8000"
TIMEOUT_SECONDS = 20  # longer than the backend's 12 second limit, so the backend answers first

# The backend keeps answers for a while (design.md, section "Caching"), so a result can be this old.
CACHE_NOTE = "Results may be up to 30 min (VirusTotal), 6 h (MalwareBazaar) or 1 h (ThreatFox) old."

SOURCE_NAMES = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox"}


# Ask the backend about a hash.
# Returns (status_code, body) when the backend answered,
# or (None, message) with a message that says what went wrong.
def ask_backend(file_hash):
    try:
        reply = requests.get(f"{BACKEND_URL}/api/v1/hash/{file_hash}", timeout=TIMEOUT_SECONDS)
    except requests.ConnectionError:
        return None, f"Backend not running at {BACKEND_URL}"
    except requests.Timeout:
        return None, f"The backend took longer than {TIMEOUT_SECONDS} seconds to answer"
    try:
        return reply.status_code, reply.json()
    except ValueError:
        return None, f"The backend sent an unexpected reply (HTTP {reply.status_code})"


# Show the VirusTotal details on the page.
def show_virustotal(data):
    st.write(f"**Detections:** {data['malicious']} malicious, {data['suspicious']} suspicious, "
             f"{data['harmless']} harmless, {data['undetected']} undetected")
    st.write(f"**File type:** {data['type_description']}")
    st.write(f"**Names:** {', '.join(data['names'])}")
    st.write(f"**First submitted:** {data['first_submission_date']}")
    st.markdown(f"[Open on VirusTotal]({data['link']})")


# Show the MalwareBazaar details on the page.
def show_malwarebazaar(data):
    st.write(f"**Signature:** {data['signature']}")
    st.write(f"**File type:** {data['file_type']}")
    st.write(f"**Tags:** {', '.join(data['tags'])}")
    st.write(f"**First seen:** {data['first_seen']}  |  **Last seen:** {data['last_seen']}")
    st.write(f"**Origin country:** {data['origin_country']}")


# Show the ThreatFox details on the page (one line per match).
def show_threatfox(data):
    for match in data["matches"]:
        st.write(f"**{match['malware_printable']}** ({match['threat_type']}), "
                 f"confidence {match['confidence_level']}%, first seen {match['first_seen']}")
        if match["malpedia"]:
            st.markdown(f"[Malpedia page]({match['malpedia']})")


# Which function shows the details of which source
SHOW_FUNCTIONS = {
    "virustotal": show_virustotal,
    "malwarebazaar": show_malwarebazaar,
    "threatfox": show_threatfox,
}


# Which coloured box shows which verdict label: red, yellow or blue
VERDICT_BOXES = {"malicious": st.error, "suspicious": st.warning, "unknown": st.info}


# Show the overall verdict in a coloured box: the label, the score, and the reasons as bullets.
def show_verdict(verdict):
    text = f"**{verdict['label'].upper()}** - score {verdict['score']}/100\n"
    for reason in verdict["reasons"]:
        text += f"\n- {reason}"
    VERDICT_BOXES[verdict["label"]](text)


# Show one source's section: its status, then its details or its error.
def show_source(key, result):
    st.subheader(SOURCE_NAMES[key])
    if result["status"] == "ok":
        SHOW_FUNCTIONS[key](result["data"])
    elif result["status"] == "not_found":
        st.info("Not found. This does not mean the file is safe.")
    else:
        st.error(result["error"])


# The page itself: title, input box, button, results.
st.title("Hash lookup")
file_hash = st.text_input("MD5, SHA-1 or SHA-256 hash").strip()

if st.button("Look up") and file_hash:
    status_code, body = ask_backend(file_hash)
    if status_code is None:
        st.error(body)  # body is the message from ask_backend
    elif status_code != 200:
        # 400 has {"error": "..."}; other codes (like 404 for a hash with "/") may not
        st.error(body.get("error") or f"The backend answered HTTP {status_code}")
    else:
        st.caption(f"{body['hash_type']}: {body['hash']}")
        if "verdict" in body:  # an older backend sends no verdict; then we just skip the box
            show_verdict(body["verdict"])
        for key, result in body["sources"].items():
            show_source(key, result)
        st.caption(CACHE_NOTE)
