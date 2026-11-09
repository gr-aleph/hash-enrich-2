# The backend: a FastAPI app with two web addresses (endpoints).
# Start it from the project folder with:
#   .venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

from concurrent.futures import ThreadPoolExecutor, wait

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from backend import cache
from backend.malwarebazaar import lookup_malwarebazaar
from backend.threatfox import lookup_threatfox
from backend.virustotal import lookup_virustotal

# Read the API keys from the .env file into os.environ (once, when the backend starts)
load_dotenv()

app = FastAPI(title="hash-enrich-2")

HEX_CHARACTERS = "0123456789abcdef"
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
TOTAL_WAIT_SECONDS = 12  # longest the backend waits for the sources, all together

# Every source we ask: its name in the response -> the function that looks it up
SOURCES = {
    "virustotal": lookup_virustotal,
    "malwarebazaar": lookup_malwarebazaar,
    "threatfox": lookup_threatfox,
}


# Return "md5", "sha1" or "sha256" for a valid lowercase hash, or None if it is not valid.
def get_hash_type(file_hash):
    if len(file_hash) not in HASH_TYPES:
        return None
    for character in file_hash:
        if character not in HEX_CHARACTERS:
            return None
    return HASH_TYPES[len(file_hash)]


# Ask all sources at the same time (one thread each) and collect their results.
# A source whose answer is already in the cache (cache.py) is not asked again.
# We wait at most TOTAL_WAIT_SECONDS. A source that is still busy then gets an error,
# so one slow source never holds back the others.
# If one source crashes, only that source shows an error; the others still answer.
def ask_all_sources(file_hash):
    results = {}
    pool = ThreadPoolExecutor()
    running = {}
    for name, lookup in SOURCES.items():
        cached = cache.get(name, file_hash)
        if cached is not None:
            results[name] = cached
        else:
            # Start every lookup without waiting for the previous one to finish
            running[name] = pool.submit(lookup, file_hash)
    # Wait at most TOTAL_WAIT_SECONDS, then see which lookups are done
    finished, not_finished = wait(running.values(), timeout=TOTAL_WAIT_SECONDS)
    for name, job in running.items():
        if job in not_finished:
            results[name] = {"status": "error", "data": None,
                             "error": f"Took longer than {TOTAL_WAIT_SECONDS} seconds"}
            continue
        try:
            results[name] = job.result()
        except Exception as problem:
            results[name] = {"status": "error", "data": None,
                             "error": f"Unexpected problem: {type(problem).__name__}"}
        else:
            cache.put(name, file_hash, results[name])  # keeps a found or not-found answer, never an error
    # Answer now; a slow lookup may still finish in the background, and its result is ignored
    pool.shutdown(wait=False)
    # Always return the sources in the same order, whether they came from the cache or not
    return {name: results[name] for name in SOURCES}


# Health check: lets you (or a script) see that the backend is running.
@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


# Look up one hash and return what each source knows about it.
@app.get("/api/v1/hash/{file_hash}")
def lookup_hash(file_hash: str):
    file_hash = file_hash.lower()
    hash_type = get_hash_type(file_hash)
    if hash_type is None:
        return JSONResponse(status_code=400, content={"error": "Expected 32, 40 or 64 hex characters"})

    return {
        "hash": file_hash,
        "hash_type": hash_type,
        "sources": ask_all_sources(file_hash),
    }
