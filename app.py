import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from modules import whois_scan, dns_scan, port_scan, geo_scan, ssl_scan, llm_analysis

app = FastAPI()

# ── Request model ─────────────────────────────────────────────────────────────
# Pydantic model validates the incoming JSON body automatically —
# if "target" is missing or not a string, FastAPI returns a 422 error.
class ScanRequest(BaseModel):
    target: str

# ── Scan endpoint ─────────────────────────────────────────────────────────────
@app.post("/scan")
def scan(request: ScanRequest):
    """
    Run all OSINT modules on the target and return the full results.
    Modules run sequentially — each result is added to the results dict
    before being passed to the next module.
    """
    target = request.target.strip()
    results = {}
    results["domain"] = target

    results["whois"] = whois_scan.run(target)
    results["dns"]   = dns_scan.run(target)
    results["ports"] = port_scan.run(target)
    results["geo"]   = geo_scan.run(target)
    results["ssl"]   = ssl_scan.run(target)

    # LLM analysis runs last — it needs the full results dict as input
    results["analysis"] = llm_analysis.run(results)

    return results

# ── Static files ──────────────────────────────────────────────────────────────
# Serves everything in the /static folder at the /static URL path.
# index.html lives here and is served separately at the root route below.
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def index():
    # Serve index.html when the user visits the root URL
    return FileResponse("static/index.html")