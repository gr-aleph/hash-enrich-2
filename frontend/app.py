# The Streamlit page. It only talks to our backend, never to the sources directly.
# Start it from the project folder with:
#   .venv\Scripts\python -m streamlit run frontend/app.py

import requests
import streamlit as st

BACKEND_URL = "http://127.0.0.1:8000"
TIMEOUT_SECONDS = 15  # a bit longer than the backend's 10 second source timeout

SOURCE_NAMES = {"virustotal": "VirusTotal"}


# Ask the backend about a hash. Returns (status_code, body), or (None, None) if the backend is down.
def ask_backend(file_hash):
    try:
        reply = requests.get(f"{BACKEND_URL}/api/v1/hash/{file_hash}", timeout=TIMEOUT_SECONDS)
        return reply.status_code, reply.json()
    except requests.RequestException:
        return None, None


# Show the VirusTotal details on the page.
def show_virustotal(data):
    st.write(f"**Detections:** {data['malicious']} malicious, {data['suspicious']} suspicious, "
             f"{data['harmless']} harmless, {data['undetected']} undetected")
    st.write(f"**File type:** {data['type_description']}")
    st.write(f"**Names:** {', '.join(data['names'])}")
    st.write(f"**First submitted:** {data['first_submission_date']}")
    st.markdown(f"[Open on VirusTotal]({data['link']})")


# Show one source's section: its status, then its details or its error.
def show_source(key, result):
    st.subheader(SOURCE_NAMES[key])
    if result["status"] == "ok":
        show_virustotal(result["data"])
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
        st.error(f"Backend not running at {BACKEND_URL}")
    elif status_code == 400:
        st.error(body["error"])
    else:
        st.caption(f"{body['hash_type']}: {body['hash']}")
        for key, result in body["sources"].items():
            show_source(key, result)
