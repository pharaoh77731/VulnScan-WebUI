# 🔐 VulnScan Pro — Vulnerability Assessment Platform

> A fully deployable web-based penetration testing dashboard — network scanning, web application analysis, CVE mapping, OS detection, and downloadable HTML reports.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![Nmap](https://img.shields.io/badge/Nmap-Powered-green?style=flat-square)
![NVD](https://img.shields.io/badge/NVD-CVE%20API-red?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## ⚠️ Legal Disclaimer

**This tool is for authorised security testing only.**
Scanning systems without explicit written permission is illegal under the Computer Misuse Act (UK), CFAA (US), and equivalent laws worldwide. The author accepts no responsibility for misuse.

---

## Overview

VulnScan Pro is a real penetration testing platform with a dark terminal-themed web dashboard. Built in Python with Flask backend and vanilla JS frontend — no frameworks needed.

### What it does

- **Network scanning** — 5 scan profiles powered by Nmap with service version detection
- **OS detection** — Identifies operating system of scanned hosts
- **Banner grabbing** — Captures raw TCP banners from open ports
- **CVE mapping** — Live NVD API 2.0 queries for real CVEs with CVSS scores
- **Web application scanning** — Security headers, SSL/TLS, sensitive paths, subdomain enumeration
- **Risk scoring** — 0–100 overall risk score per scan
- **HTML reports** — Download professional colour-coded reports
- **Async scanning** — Non-blocking job engine with real-time progress
- **Scan history** — View and re-download past scans
- **REST API** — Authenticated Flask API for pipeline integration
- **Docker support** — One command to deploy anywhere

---

## Project Structure

```
VulnScanPro/
├── start.py                  # ← Single command to run everything
├── Dockerfile
├── docker-compose.yml
├── .gitignore
├── README.md
├── backend/
│   ├── app.py                # Flask API + scan engine + web scanner
│   └── requirements.txt
└── frontend/
    └── index.html            # Full dashboard (HTML + CSS + JS in one file)
```

---

## Quickstart — One Command

```bash
python start.py
```

That's it. The launcher will:
1. Check your Python version
2. Create a virtual environment
3. Install all dependencies
4. Check nmap is installed
5. Generate a secure API key
6. Launch the server
7. Open the dashboard in your browser automatically

---

## Manual Setup

```bash
git clone https://github.com/pharaoh77731/VulnScanPro.git
cd VulnScanPro

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r backend/requirements.txt

export VULNSCAN_API_KEY=your-secret-key   # Windows: $env:VULNSCAN_API_KEY="your-key"
python backend/app.py
```

Then open **http://localhost:5000**

---

## Prerequisites

**Python 3.8+** and **nmap** must be installed.

```bash
# Linux
sudo apt install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

> Network scanning (port scan) requires **root/admin** privileges.
> Web scanning works without root.

---

## Dashboard Features

### Network Scan Tab
- Enter target IP, hostname, or CIDR range
- Choose from 5 scan profiles:

| Profile | Description |
|---------|-------------|
| Quick | Top 100 ports — fastest |
| Standard | Ports 1–1024 — recommended |
| Full | All 65535 ports — thorough |
| Stealth | SYN scan — low noise |
| Vuln Scripts | NSE vulnerability scripts |

- Toggle "Also run web scan on target" for a combined scan
- Real-time progress log while scanning
- Download full HTML report when complete

### Web Scan Tab
- Enter a URL or domain (e.g. `example.com` or `https://example.com`)
- Checks:
  - **Security headers** — HSTS, CSP, X-Frame-Options, etc.
  - **SSL/TLS** — Certificate expiry, protocol version
  - **Sensitive paths** — `.env`, `.git/config`, `/admin`, `/swagger.json`, etc.
  - **Subdomains** — DNS brute-force against common wordlist

### Scan History Tab
- View all past scans with status and timestamp
- Click any scan to reload its results
- Download HTML report for any completed scan

---

## REST API

All endpoints require `X-API-Key` header.

```bash
# Health check (no auth required)
curl http://localhost:5000/api/health

# Network scan (async)
curl -X POST http://localhost:5000/api/scan \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1","ports":"1-1024","scan_type":"standard","include_web":true}'

# Poll job status
curl http://localhost:5000/api/jobs/JOB_ID \
  -H "X-API-Key: YOUR_KEY"

# Download HTML report
curl http://localhost:5000/api/jobs/JOB_ID/report \
  -H "X-API-Key: YOUR_KEY" -o report.html

# Web scan only (synchronous)
curl -X POST http://localhost:5000/api/scan/web \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'

# List all jobs
curl http://localhost:5000/api/jobs \
  -H "X-API-Key: YOUR_KEY"
```

---

## Docker

```bash
# Build and run
docker-compose up --build

# With custom API key
VULNSCAN_API_KEY=my-secret-key docker-compose up --build

# CLI only (no compose)
docker build -t vulnscan-pro .
docker run -p 5000:5000 \
  -e VULNSCAN_API_KEY=my-secret-key \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  vulnscan-pro
```

> `NET_ADMIN` and `NET_RAW` capabilities are required for nmap SYN scanning inside Docker.

---

## Security Design

| Concern | Mitigation |
|---------|-----------|
| API authentication | `X-API-Key` header required on all scan endpoints |
| API key storage | Loaded from `VULNSCAN_API_KEY` env var — never hardcoded |
| Rate limiting | Flask-Limiter: 10 scans/minute, 200/day |
| Input validation | All IPs, hostnames, port ranges validated before scanning |
| Concurrent scans | Max 5 simultaneous jobs configurable via `MAX_SCAN_THREADS` |
| Logging | All requests and scan events written to `vulnscan.log` |

---

## Roadmap

- [x] 5 scan profiles (Quick / Standard / Full / Stealth / Vuln Scripts)
- [x] Async job engine with real-time progress
- [x] OS detection
- [x] Banner grabbing
- [x] Web application scanner (headers, SSL, paths, subdomains)
- [x] Downloadable HTML reports
- [x] Scan history with reload
- [x] Docker + docker-compose
- [x] Single-command launcher
- [ ] User authentication (login page)
- [ ] Email report delivery
- [ ] OWASP Top 10 automated checks
- [ ] Scheduled recurring scans
- [ ] Export to PDF

---

## Author

**Bhupendra Singh**
[GitHub](https://github.com/pharaoh77731)

---

## License

[MIT License](LICENSE)
