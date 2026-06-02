import dns.resolver
import socket

def run(target: str) -> dict:
    """
    Enumerate DNS records for a given domain.
    Queries the most useful record types for OSINT purposes.
    Each record type is fetched independently so one failure
    doesn't wipe out the rest of the results.
    """

    def query(domain, record_type):
        """
        Helper to query a single DNS record type.
        Returns a list of strings, or an empty list on failure.
        We never want a missing record type to crash the whole scan.
        """
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [r.to_text() for r in answers]
        except Exception:
            # Common reasons this fails:
            #   - Record type doesn't exist for this domain (NXDOMAIN)
            #   - Timeout reaching the DNS server
            #   - Domain has no records of this type
            # All treated the same — return empty list, move on.
            return []

    # A record — maps domain to IPv4 address(es).
    # Multiple A records usually means load balancing.
    a_records = query(target, "A")

    # AAAA record — maps domain to IPv6 address(es).
    # Empty here is common — many domains don't have IPv6 yet.
    aaaa_records = query(target, "AAAA")

    # MX records — mail servers responsible for receiving email.
    # Format is "priority hostname" e.g. "10 mail.google.com"
    # Useful for identifying email providers (GSuite, Outlook etc.)
    mx_records = query(target, "MX")

    # TXT records — free-form text attached to the domain.
    # Often contains SPF rules, DKIM keys, domain verification tokens.
    # Very useful for OSINT — reveals services the domain uses.
    txt_records = query(target, "TXT")

    # CNAME — canonical name, i.e. this domain is an alias for another.
    # e.g. "www.example.com → example.com"
    cname_records = query(target, "CNAME")

    # Reverse DNS — given the IP, what hostname does it resolve back to?
    # A mismatch between forward and reverse DNS can be a red flag.
    reverse_dns = None
    if a_records:
        try:
            # We only check the first A record IP for reverse lookup.
            # gethostbyaddr returns (hostname, alias_list, ip_list)
            reverse_dns = socket.gethostbyaddr(a_records[0])[0]
        except Exception:
            # Reverse DNS is often not configured — not suspicious on its own.
            reverse_dns = None

    return {
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "mx_records": mx_records,
        "txt_records": txt_records,
        "cname_records": cname_records,
        "reverse_dns": reverse_dns,
    }