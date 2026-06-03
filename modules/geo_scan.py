import requests 

def run(target: str) -> dict:
    """
    Geolocate a domain or IP address using the ip-api.com free tier.
    No API key required — completely free up to 45 requests/minute.
    We first resolve the domain to an IP, then query the geolocation API.
    """

    try:
        # ip-api.com accepts both IPs and domain names directly.
        # The 'fields' parameter limits the response to only what we need —
        # keeps the output clean and avoids unnecessary data.
        fields = ",".join([
            "status",       # "success" or "fail" — tells us if lookup worked
            "country",      # Full country name e.g. "United States"
            "countryCode",  # ISO 3166-1 alpha-2 e.g. "US"
            "region",       # Region/state code e.g. "CA"
            "regionName",   # Full region name e.g. "California"
            "city",         # City name
            "zip",          # Postal code
            "lat",          # Latitude — useful for map visualizations later
            "lon",          # Longitude
            "timezone",     # e.g. "America/Los_Angeles"
            "isp",          # Internet Service Provider name
            "org",          # Organization name (often more specific than ISP)
            "as",           # Autonomous System number + name e.g. "AS15169 Google LLC"
        ])

        url = f"http://ip-api.com/json/{target}?fields={fields}"

        # timeout=5 prevents hanging if the API is slow —
        # we don't want one module to stall the entire pipeline
        response = requests.get(url, timeout=5)
        data = response.json()

        # ip-api returns status="fail" for private IPs, invalid domains etc.
        if data.get("status") == "fail":
            return {"error": f"Geolocation failed for target: {target}"}

        # Remove the status field from output — it's only useful for error checking
        data.pop("status", None)

        return data

    except requests.exceptions.Timeout:
        return {"error": "Geolocation request timed out"}

    except Exception as e:
        return {"error": str(e)}