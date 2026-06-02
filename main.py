import json
import sys
from modules import whois_scan, dns_scan

def run(target: str):
    # Central results dictionary — every module adds its own key here.
    # This is what eventually gets passed to the LLM for analysis.
    results = {"domain":target}

    print(f"[*] Running WHOIS on {target}...")
    print(f"[*] Running DNS scan on {target}...")
    # Each module exposes a run(target) function that returns a dict.
    # We just call it and store the result under its key.
    results["whois"] = whois_scan.run(target)

    # As you build new modules, uncomment and add them here in order.
    # The pattern is always the same:
    #   results["<key>"] = <module_name>.run(target)
    results["dns"]   = dns_scan.run(target)
    # results["ports"] = port_scan.run(target)
    # results["ssl"]   = ssl_scan.run(target)

    # Pretty-print the full results as JSON.
    # indent=2 keeps it human-readable in the terminal.
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    # sys.argv[0] is always the script name itself, so the target
    # domain/IP is at index 1. If missing, exit with usage hint.
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain>")
        sys.exit(1)
    run(sys.argv[1])