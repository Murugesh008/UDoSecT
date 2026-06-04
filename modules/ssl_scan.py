import ssl
import socket
from datetime import datetime

def run(target: str) -> dict:
    """
    Retrieve and analyze the SSL/TLS certificate for a given domain.
    Connects on port 443 and pulls the certificate details directly —
    no third party API needed, uses Python's built-in ssl module.
    """

    try:
        # ssl.create_default_context() sets up a secure context with
        # certificate verification enabled by default — same as a browser.
        context = ssl.create_default_context()

        # We wrap a raw socket with SSL to perform the handshake.
        # server_hostname is required for SNI (Server Name Indication) —
        # many servers host multiple domains on one IP, SNI tells the
        # server which certificate to present.
        with socket.create_connection((target, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:

                # get_peercert() returns the certificate as a nested dict
                # with fields like subject, issuer, notAfter etc.
                cert = ssock.getpeercert()

                # version() returns the negotiated TLS protocol string
                # e.g. "TLSv1.2", "TLSv1.3"
                tls_version = ssock.version()

        # ── Subject ───────────────────────────────────────────────────────
        # cert["subject"] is a tuple of tuples:
        # (( "commonName", "*.google.com" ), ( "organizationName", "Google" ))
        # We flatten it into a plain dict for clean access.
        subject = dict(x[0] for x in cert.get("subject", []))

        # ── Issuer ────────────────────────────────────────────────────────
        # Same nested tuple structure as subject — flatten the same way.
        issuer = dict(x[0] for x in cert.get("issuer", []))

        # ── Validity dates ────────────────────────────────────────────────
        # Dates come as strings in this format: "May 12 08:00:00 2025 GMT"
        # We parse and reformat to YYYY-MM-DD for consistency with
        # the date format used in whois_scan.py
        date_format = "%b %d %H:%M:%S %Y %Z"

        not_before_raw = cert.get("notBefore", "")
        not_after_raw  = cert.get("notAfter", "")

        not_before = datetime.strptime(not_before_raw, date_format).strftime("%Y-%m-%d") if not_before_raw else None
        not_after  = datetime.strptime(not_after_raw,  date_format).strftime("%Y-%m-%d") if not_after_raw  else None

        # ── Days until expiry ─────────────────────────────────────────────
        # Useful signal for the LLM — a cert expiring in 7 days is a red flag.
        days_until_expiry = None
        if not_after:
            delta = datetime.strptime(not_after, "%Y-%m-%d") - datetime.utcnow()
            days_until_expiry = delta.days

        # ── Subject Alternative Names (SANs) ──────────────────────────────
        # SANs list every domain this cert is valid for.
        # Format in the cert: (("DNS", "*.google.com"), ("DNS", "google.com"))
        # We extract just the domain strings.
        san_raw = cert.get("subjectAltName", [])
        sans = [value for record_type, value in san_raw if record_type == "DNS"]

        return {
            # The common name — usually the primary domain on the cert
            "common_name": subject.get("commonName"),

            "issuer": {
                "organization": issuer.get("organizationName"),
                "common_name":  issuer.get("commonName"),
                "country":      issuer.get("countryName"),
            },

            "valid_from":        not_before,
            "valid_until":       not_after,
            "days_until_expiry": days_until_expiry,

            # TLS version negotiated — older versions (TLSv1.0, TLSv1.1)
            # are considered insecure and worth flagging in the report
            "tls_version": tls_version,

            # Full list of domains covered by this certificate
            "subject_alt_names": sans,

            # Serial number uniquely identifies this cert —
            # useful for cross-referencing with cert transparency logs
            "serial_number": str(cert.get("serialNumber", "")),
        }

    except ssl.SSLCertVerificationError as e:
        # Certificate failed verification — expired, self-signed,
        # or domain mismatch. Worth flagging explicitly, not just "error".
        return {"error": f"SSL verification failed: {str(e)}"}

    except socket.timeout:
        return {"error": "Connection timed out on port 443"}

    except ConnectionRefusedError:
        return {"error": "Port 443 is closed — target may not support HTTPS"}

    except Exception as e:
        return {"error": str(e)}