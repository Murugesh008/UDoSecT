import nmap    # python-nmap library — pip install python-nmap
               # also requires nmap installed on your system:
               # Windows: https://nmap.org/download.html
               # Linux/Mac: sudo apt install nmap / brew install nmap

def run(target: str) -> dict:
    """
    Scan the most common ports on a target domain or IP.
    Uses nmap's default top-1000 ports — covers the vast majority
    of real-world services without taking too long.
    """

    try:
        scanner = nmap.PortScanner()

        # -sV  : probe open ports to detect the service and version running
        # -T4  : aggressive timing — faster scan, acceptable for OSINT
        # --top-ports 1000 : scan the 1000 most commonly used ports
        #                    instead of all 65535, keeps it fast
        scanner.scan(target, arguments="-sV -T4 --top-ports 1000")

        # nmap resolves the domain to an IP internally.
        # scanner.all_hosts() returns the list of scanned IPs.
        # We take the first one since we're scanning a single target.
        hosts = scanner.all_hosts()
        if not hosts:
            return {"error": "No hosts found — target may be unreachable"}

        host = hosts[0]
        host_data = scanner[host]

        open_ports = []

        # nmap organizes results by protocol (tcp, udp etc.)
        # We focus on TCP — most services run on TCP.
        for proto in host_data.all_protocols():
            # sorted() so ports appear in ascending order in the output
            for port in sorted(host_data[proto].keys()):
                port_info = host_data[proto][port]

                # Only include open ports — filtered/closed aren't useful here
                if port_info["state"] == "open":
                    open_ports.append({
                        "port": port,
                        "protocol": proto,

                        # Common service name e.g. "http", "https", "ssh", "ftp"
                        "service": port_info.get("name", "unknown"),

                        # Specific software detected e.g. "Apache httpd 2.4.41"
                        # Empty string if -sV couldn't fingerprint it
                        "version": port_info.get("version", ""),

                        # Extra detail e.g. OS type, extra banners
                        "extra_info": port_info.get("extrainfo", ""),
                    })

        return {
            # The actual IP nmap scanned (useful when input was a domain)
            "ip_scanned": host,

            # Total number of open ports found — quick signal for the LLM
            "open_port_count": len(open_ports),

            "open_ports": open_ports,
        }

    except Exception as e:
        return {"error": str(e)}