import os
import re
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from modules import whois_scan, dns_scan, port_scan, geo_scan, ssl_scan, llm_analysis

# add this function above the scan endpoint
def is_valid_target(target: str) -> bool:
    """
    Basic validation to reject obviously invalid targets before
    running any modules. Accepts domains and IPv4 addresses.
    Does not do full RFC compliance — just catches garbage input
    like empty strings, random words, or special characters.
    """

    # IPv4 pattern — four octets of 0-255
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, target):
        # Make sure each octet is actually 0-255
        parts = target.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True

    # Domain pattern — letters, numbers, hyphens, dots, optional port
    # Requires at least one dot and a valid TLD (2+ characters)
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True

    return False


app = FastAPI()

# ── Request model ─────────────────────────────────────────────────────────────
# Pydantic model validates the incoming JSON body automatically —
# if "target" is missing or not a string, FastAPI returns a 422 error.
class ScanRequest(BaseModel):
    target: str

# ── Scan endpoint ─────────────────────────────────────────────────────────────
@app.post("/scan")
def scan(request: ScanRequest):
    target = request.target.strip()

    # Reject invalid input immediately — no modules run, no API calls wasted
    if not is_valid_target(target):
        return {
            "domain": target,
            "error": "invalid_input",
            "message": f'"{target}" is not a valid domain or IP address.'
        }

    results = {}
    results["domain"] = target

    results["whois"] = whois_scan.run(target)
    results["dns"]   = dns_scan.run(target)
    results["ports"] = port_scan.run(target)
    results["geo"]   = geo_scan.run(target)
    results["ssl"]   = ssl_scan.run(target)
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