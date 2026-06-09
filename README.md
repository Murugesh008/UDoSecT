# 🔍 UDoSecT (USER DOMAIN SECURITY TOOL)

> An open source intelligence (OSINT) tool that scans a target domain or IP, aggregates data across multiple recon modules, and uses an LLM to generate a structured threat intelligence report.


---

## 📸 What It Does

Enter a domain or IP → the tool runs all recon modules in sequence → an LLM analyzes the aggregated data → you get a color-coded threat report with risk score, findings, and recommendations.

```
google.com   →   RISK: LOW    / Score: 10
example.com  →   RISK: MEDIUM / Score: 40
freemoviesdownload.net → RISK: CRITICAL / Score: 98
```

---

## 🧩 Architecture

```
Target (domain / IP)
        ↓
┌─────────────────────────────┐
│      Data Gathering Layer   │
│  whois │ dns │ ports │ geo  │
│           ssl               │
└────────────┬────────────────┘
             ↓
     Aggregator (main results dict)
             ↓
┌─────────────────────────────┐
│      LLM Analysis Layer     │
│  Groq API / llama-3.3-70b   │
│  risk score + findings +    │
│  recommendations            │
└────────────┬────────────────┘
             ↓
┌─────────────────────────────┐
│     FastAPI Backend         │
│     POST /scan              │
└────────────┬────────────────┘
             ↓
┌─────────────────────────────┐
│   Cyberpunk HTML/CSS/JS     │
│   Frontend (index.html)     │
└─────────────────────────────┘
```

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Backend | FastAPI + Uvicorn |
| Frontend | Vanilla HTML / CSS / JS |
| WHOIS | python-whois |
| DNS | dnspython |
| Port Scanning | python-nmap + nmap |
| Geolocation | ip-api.com (free, no key) |
| SSL Analysis | Python built-in ssl + socket |
| LLM | Groq API (llama-3.3-70b-versatile) |
| Env Management | python-dotenv |

---

## 📁 Project Structure

```
osint_tool/
├── app.py                  ← FastAPI backend, /scan endpoint
├── static/
│   └── index.html          ← Frontend UI
├── modules/
│   ├── whois_scan.py       ← WHOIS lookup
│   ├── dns_scan.py         ← DNS enumeration
│   ├── port_scan.py        ← Port scanning (nmap)
│   ├── geo_scan.py         ← IP geolocation
│   ├── ssl_scan.py         ← SSL certificate analysis
│   └── llm_analysis.py     ← LLM threat report generation
├── .env                    ← API keys (never committed)
├── .gitignore
└── requirements.txt
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.10+
- nmap installed on your system
  - **Windows**: https://nmap.org/download.html
  - **Linux**: `sudo apt install nmap`
  - **Mac**: `brew install nmap`
- A free Groq API key from https://console.groq.com

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/osint-tool.git
cd osint-tool
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up your API key
Create a `.env` file in the project root:
```
GROQ_API_KEY=your_key_here
```

### 4. Run the server
```bash
uvicorn app:app --reload
```

### 5. Open in browser
```
http://localhost:8000
```

---

## 🔬 Modules

### `whois_scan.py`
Queries WHOIS data for the target domain — registrar, creation date, expiry date, nameservers, status codes, and contact emails. Dates are normalized to `YYYY-MM-DD`. Status codes are deduplicated and stripped of URL suffixes.

### `dns_scan.py`
Enumerates DNS records using dnspython — A, AAAA, MX, NS, TXT, and CNAME records. Also performs a reverse DNS lookup on the primary A record IP.

### `port_scan.py`
Scans the top 1000 TCP ports using nmap with service detection (`-sV -T4`). Returns open ports with service name, version, and extra info where available.

### `geo_scan.py`
Geolocates the target using ip-api.com (free, no API key required). Returns country, city, ISP, ASN, timezone, and coordinates. Includes a 5-second timeout to avoid stalling the pipeline.

### `ssl_scan.py`
Connects to port 443 and retrieves the SSL/TLS certificate using Python's built-in ssl module. Returns issuer, validity dates, days until expiry, TLS version, and all Subject Alternative Names (SANs).

### `llm_analysis.py`
Sends the full aggregated results JSON to the Groq API (llama-3.3-70b-versatile) with a carefully engineered prompt that produces a structured JSON response containing:
- `risk_level` — LOW / MEDIUM / HIGH / CRITICAL
- `risk_score` — 0 to 100
- `summary` — 2-3 sentence overview
- `findings` — list of categorized findings with severity
- `recommendations` — actionable next steps

---

## 🌐 API

### `POST /scan`

**Request:**
```json
{
  "target": "google.com"
}
```

**Response:**
```json
{
  "domain": "google.com",
  "whois": { ... },
  "dns": { ... },
  "ports": { ... },
  "geo": { ... },
  "ssl": { ... },
  "analysis": {
    "risk_level": "LOW",
    "risk_score": 10,
    "summary": "...",
    "findings": [ ... ],
    "recommendations": [ ... ]
  }
}
```

**Invalid input returns:**
```json
{
  "domain": "notadomain!!",
  "error": "invalid_input",
  "message": "\"notadomain!!\" is not a valid domain or IP address."
}
```

---

## 🧪 Test Targets

| Target | Expected Risk | Notes |
|---|---|---|
| `google.com` | LOW (~10) | Well configured, reputable |
| `github.com` | LOW (~15) | Strong security posture |
| `example.com` | MEDIUM (~40) | Placeholder domain, no real owner |
| `freemoviesdownload.net` | CRITICAL (~95+) | Unreachable, suspicious name |

---

## 👥 Authors

Built by two tech undergraduates as a portfolio project at the intersection of cybersecurity and AI/ML.
- Murugesh and Shrivatshan
---


