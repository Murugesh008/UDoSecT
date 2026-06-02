import whois     
from datetime import datetime

def run(target: str) -> dict:
    """
    Query WHOIS data for a given domain.
    Returns a flat dict with cleaned, normalized fields.
    On failure, returns {"error": "<message>"} so the pipeline
    never crashes — the LLM can note the failure in its report.
    """
    try:
        # whois.whois() does the full WHOIS lookup.
        # The returned object has attributes like .registrar, .creation_date etc.
        w = whois.whois(target)

        def fmt_date(d):
            # WHOIS dates can come back as a list of datetimes (some registrars
            # return multiple dates), a single datetime, or a raw string.
            # We always want just one clean YYYY-MM-DD string.
            if isinstance(d, list): d = d[0]          # take the first if multiple
            if isinstance(d, datetime): return d.strftime("%Y-%m-%d")
            return str(d) if d else None               # fallback for raw strings

        return {
            "registrar": w.registrar,
            "creation_date": fmt_date(w.creation_date),
            "expiry_date": fmt_date(w.expiration_date),
            "updated_date": fmt_date(w.updated_date),

            # name_servers can be mixed-case — normalize to lowercase
            # for consistent comparison across scans.
            "name_servers": [ns.lower() for ns in (w.name_servers or [])],

            # Status strings come in two formats from different registrars
            # We only want the status code itself (first word).
            # set() removes duplicates that appear in both formats.
            "status": list(set([
                s.split()[0]
                for s in (w.status if isinstance(w.status, list) else [w.status])
            ])),

            # Emails associated with the domain registration (abuse, admin etc.)
            # Can be a single string or a list depending on the registrar.
            "emails": w.emails if isinstance(w.emails, list) else [w.emails],
        }

    except Exception as e:
        # Return error as a dict so the pipeline stays intact.
        # Never raise here — a failed module shouldn't stop other modules.
        return {"error": str(e)}