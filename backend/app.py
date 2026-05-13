"""
VulnScan Pro v3.0 — Vulnerability Assessment & Penetration Testing Tool
Author: Bhupendra Singh | Security Analyst
GitHub: https://github.com/pharaoh77731

Upgrades in v3.0:
- Web application scanning (security headers, SSL/TLS, sensitive paths, subdomains)
- Download HTML report endpoint
- Banner grabbing on open ports
- Improved risk scoring
"""

import os
import re
import json
import uuid
import socket
import ssl
import logging
import datetime
import ipaddress
import threading
import requests
import concurrent.futures
from functools import wraps
from collections import defaultdict

import nmap
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

requests.packages.urllib3.disable_warnings()

# ── App Setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app, resources={r"/api/*": {"origins": "*"}})

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("vulnscan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# NOTE: No global nmap instance — each scan job creates its own PortScanner()
#       to avoid race conditions when concurrent scans run simultaneously.
_health_nm = nmap.PortScanner()   # used only for the health-check version query

# ── Config ────────────────────────────────────────────────────────────────────
_DEFAULT_KEY    = "change-this-secret-key-in-production"
API_KEY         = os.environ.get("VULNSCAN_API_KEY", _DEFAULT_KEY)
MAX_SCAN_THREADS= int(os.environ.get("MAX_SCAN_THREADS", "5"))

if API_KEY == _DEFAULT_KEY:
    import warnings
    warnings.warn(
        "\n⚠  VULNSCAN_API_KEY is still the default placeholder. "
        "Set the VULNSCAN_API_KEY environment variable before exposing this server.\n",
        stacklevel=1,
    )

jobs      = {}
jobs_lock = threading.Lock()

# ── Auth ──────────────────────────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if key != API_KEY:
            logger.warning(f"Unauthorized attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized. Provide a valid X-API-Key header."}), 401
        return f(*args, **kwargs)
    return decorated

# ── Validation ────────────────────────────────────────────────────────────────
def validate_target(target):
    if not target:
        return False, "Target is required."
    target = target.strip()
    try:
        ipaddress.IPv4Address(target)
        return True, None
    except ValueError:
        pass
    hostname_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(hostname_regex, target):
        return True, None
    try:
        ipaddress.ip_network(target, strict=False)
        return True, None
    except ValueError:
        pass
    return False, f"Invalid target: '{target}'."

def validate_ports(ports):
    if not ports:
        return True, None
    pattern = r"^(\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$"
    if not re.match(pattern, ports):
        return False, "Invalid port format. Use '80', '1-1024', or '22,80,443'."
    return True, None

def validate_scan_type(scan_type):
    allowed = {"quick", "standard", "full", "stealth", "vuln"}
    if scan_type not in allowed:
        return False, f"Invalid scan type. Choose from: {', '.join(allowed)}"
    return True, None

# ── Scan Profiles ─────────────────────────────────────────────────────────────
SCAN_PROFILES = {
    "quick":    {"args": "-sV --open -T4 --top-ports 100",       "desc": "Top 100 ports"},
    "standard": {"args": "-sV --open -T4",                        "desc": "Ports 1-1024"},
    "full":     {"args": "-sV --open -T4 -p-",                   "desc": "All 65535 ports"},
    "stealth":  {"args": "-sS -sV --open -T2",                   "desc": "SYN stealth scan"},
    "vuln":     {"args": "-sV --open -T4 --script=vuln",         "desc": "NSE vuln scripts"},
}

# ── Risk Engine ───────────────────────────────────────────────────────────────
RISKY_SERVICES = {
    "ftp":      {"risk": "High",     "reason": "Often allows anonymous login or transmits credentials in plaintext."},
    "telnet":   {"risk": "Critical", "reason": "Unencrypted remote access. Replace with SSH immediately."},
    "smtp":     {"risk": "Medium",   "reason": "Can be abused for open relay or user enumeration."},
    "http":     {"risk": "Medium",   "reason": "Unencrypted web traffic. Upgrade to HTTPS."},
    "smb":      {"risk": "High",     "reason": "Common target for lateral movement and ransomware (EternalBlue)."},
    "rdp":      {"risk": "High",     "reason": "Brute-force and credential stuffing target. Restrict to VPN."},
    "mysql":    {"risk": "High",     "reason": "Database port exposed. Should never be internet-facing."},
    "ms-sql-s": {"risk": "High",     "reason": "Database port exposed. Should never be internet-facing."},
    "ssh":      {"risk": "Low",      "reason": "Generally secure. Ensure key-based auth and disable root login."},
    "https":    {"risk": "Low",      "reason": "Encrypted web traffic. Verify TLS version and certificate."},
    "dns":      {"risk": "Medium",   "reason": "Can be abused for zone transfer or DNS amplification."},
    "snmp":     {"risk": "High",     "reason": "Often uses default community strings. Can leak device info."},
    "vnc":      {"risk": "High",     "reason": "Remote desktop — often exposed with weak or no auth."},
    "mongodb":  {"risk": "Critical", "reason": "NoSQL database — often exposed with no authentication."},
    "redis":    {"risk": "Critical", "reason": "In-memory database — frequently misconfigured with no auth."},
    "ldap":     {"risk": "High",     "reason": "Directory service — can leak user/org info if misconfigured."},
    "pop3":     {"risk": "Medium",   "reason": "Email retrieval — credentials may be sent in plaintext."},
    "imap":     {"risk": "Medium",   "reason": "Email access — use IMAPS (993) instead."},
}

RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

REMEDIATIONS = {
    "telnet":   "Disable Telnet. Use SSH with key-based authentication.",
    "ftp":      "Disable anonymous FTP. Use SFTP or FTPS.",
    "http":     "Force HTTPS with a valid TLS certificate. Implement HSTS.",
    "smb":      "Patch SMB (MS17-010). Disable SMBv1. Restrict to internal networks.",
    "rdp":      "Restrict RDP to VPN. Enable NLA. Use MFA.",
    "mysql":    "Bind MySQL to localhost. Never expose port 3306 to the internet.",
    "ms-sql-s": "Disable SA account. Restrict access via firewall.",
    "snmp":     "Disable SNMPv1/v2. Use SNMPv3 with authentication.",
    "dns":      "Disable zone transfers to unauthorised hosts. Use DNSSEC.",
    "smtp":     "Disable open relay. Implement SPF, DKIM, DMARC.",
    "ssh":      "Disable root login. Use SSH keys. Consider fail2ban.",
    "vnc":      "Restrict VNC to localhost. Tunnel over SSH.",
    "mongodb":  "Enable MongoDB authentication. Bind to localhost. Use TLS.",
    "redis":    "Enable Redis requirepass. Bind to localhost.",
    "ldap":     "Enforce LDAP authentication. Use LDAPS (636).",
    "pop3":     "Use POP3S (995). Enforce TLS.",
    "imap":     "Use IMAPS (993). Enforce TLS.",
}

def get_risk(service_name):
    for key, data in RISKY_SERVICES.items():
        if key in service_name.lower():
            return data["risk"], data["reason"]
    return "Info", "No known risk profile for this service."

def get_remediation(service_name, risk):
    for key, rem in REMEDIATIONS.items():
        if key in service_name.lower():
            return rem
    if risk in ("High", "Critical"):
        return "Review this service. Apply firewall rules to restrict access."
    return "Monitor this service for unusual activity."

# ── CVE Lookup ────────────────────────────────────────────────────────────────
def lookup_cves(service, version, max_cves=3):
    """
    Query NVD API 2.0 for CVEs. Includes exponential-backoff retry
    to handle the NVD public rate limit (~5 req/s without an API key).
    """
    if not service or service in ("unknown", ""):
        return []
    query = f"{service} {version}".strip()
    import time
    for attempt in range(3):
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": query, "resultsPerPage": max_cves},
                timeout=8,
            )
            if resp.status_code == 429:
                time.sleep(2 ** attempt)   # 1s, 2s, 4s
                continue
            if resp.status_code != 200:
                return []
            items = resp.json().get("vulnerabilities", [])
            cves = []
            for item in items:
                cve_id = item["cve"]["id"]
                desc   = item["cve"].get("descriptions", [{}])[0].get("value", "No description.")
                metrics= item["cve"].get("metrics", {})
                score  = "N/A"
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                cves.append({
                    "id": cve_id, "score": score,
                    "description": desc[:250],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
            return cves
        except Exception:
            if attempt == 2:
                return []
            import time; time.sleep(2 ** attempt)
    return []

# ── Banner Grabbing ───────────────────────────────────────────────────────────
def grab_banner(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            return banner[:200] if banner else ""
    except Exception:
        return ""

# ── Network Scan ──────────────────────────────────────────────────────────────
def run_scan(target, ports, scan_type="standard"):
    """
    Each call creates its own PortScanner instance so concurrent jobs
    never share state and cannot corrupt each other's results.
    """
    profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["standard"])
    args    = profile["args"]
    port_arg= f"-p {ports}" if ports else ""
    if "-p-" not in args and port_arg:
        args = f"{args} {port_arg}"

    local_nm = nmap.PortScanner()          # ← thread-safe: one instance per job
    local_nm.scan(hosts=target, arguments=args + " -O")
    results = []

    for host in local_nm.all_hosts():
        host_entry = {
            "host":         host,
            "state":        local_nm[host].state(),
            "hostname":     local_nm[host].hostname() or "",
            "os_guess":     _extract_os(local_nm, host),
            "ports":        [],
            "overall_risk": "Info",
            "cve_count":    0,
        }
        highest_risk = 0

        for proto in local_nm[host].all_protocols():
            for port in sorted(local_nm[host][proto].keys()):
                svc          = local_nm[host][proto][port]
                service_name = svc.get("name", "unknown")
                product      = svc.get("product", "")
                version      = svc.get("version", "")
                extra        = svc.get("extrainfo", "")
                full_version = " ".join(filter(None, [product, version, extra])).strip()

                risk_level, risk_reason = get_risk(service_name)
                cves   = lookup_cves(service_name, full_version)
                banner = grab_banner(host, port)

                host_entry["ports"].append({
                    "port":        port,
                    "protocol":    proto,
                    "state":       svc.get("state", "unknown"),
                    "service":     service_name,
                    "product":     product,
                    "version":     full_version,
                    "banner":      banner,
                    "risk":        risk_level,
                    "risk_reason": risk_reason,
                    "cves":        cves,
                    "remediation": get_remediation(service_name, risk_level),
                    "script_output": svc.get("script", {}),
                })
                host_entry["cve_count"] += len(cves)

                if RISK_ORDER.get(risk_level, 0) > highest_risk:
                    highest_risk = RISK_ORDER[risk_level]
                    host_entry["overall_risk"] = risk_level

        results.append(host_entry)
    return results

def _extract_os(scanner, host):
    try:
        osmatch = scanner[host].get("osmatch", [])
        if osmatch:
            return osmatch[0].get("name", "Unknown")
    except Exception:
        pass
    return "Unknown"

# ── Web Scanner ───────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"risk": "High",   "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "X-Frame-Options":           {"risk": "Medium", "fix": "Add: X-Frame-Options: DENY"},
    "X-Content-Type-Options":    {"risk": "Medium", "fix": "Add: X-Content-Type-Options: nosniff"},
    "Content-Security-Policy":   {"risk": "High",   "fix": "Implement a Content-Security-Policy header."},
    "X-XSS-Protection":          {"risk": "Low",    "fix": "Add: X-XSS-Protection: 1; mode=block"},
    "Referrer-Policy":           {"risk": "Low",    "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy":        {"risk": "Low",    "fix": "Add a Permissions-Policy header restricting camera, mic, geolocation."},
}

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/admin", "/admin/login",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/config.php", "/config.yml", "/config.json",
    "/backup", "/backup.zip", "/db.sql",
    "/api/v1/users", "/api/users", "/swagger.json",
    "/actuator/env", "/.DS_Store", "/server-status",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "api", "dev",
    "staging", "test", "admin", "portal", "dashboard",
    "vpn", "remote", "shop", "blog", "support",
    "cdn", "webmail", "autodiscover", "ns1", "ns2",
]

def check_headers(url, timeout=8):
    result = {"url": url, "findings": [], "present_headers": []}
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        result["status_code"]  = resp.status_code
        result["server"]       = resp.headers.get("Server", "Not disclosed")
        result["final_url"]    = resp.url
        result["x_powered_by"] = resp.headers.get("X-Powered-By", "")

        for header, info in SECURITY_HEADERS.items():
            if header not in resp.headers:
                result["findings"].append({
                    "header": header,
                    "risk":   info["risk"],
                    "issue":  f"Missing {header} header.",
                    "fix":    info["fix"],
                })
            else:
                result["present_headers"].append(header)

        if resp.headers.get("Server") and resp.headers["Server"] not in ("", "Server"):
            result["findings"].append({
                "header": "Server",
                "risk":   "Low",
                "issue":  f"Server header discloses: {resp.headers['Server']}",
                "fix":    "Remove or genericise the Server header.",
            })
        if resp.headers.get("X-Powered-By"):
            result["findings"].append({
                "header": "X-Powered-By",
                "risk":   "Low",
                "issue":  f"X-Powered-By discloses: {resp.headers['X-Powered-By']}",
                "fix":    "Remove X-Powered-By header.",
            })
    except Exception as e:
        result["error"] = str(e)
    return result

def check_ssl(hostname, port=443):
    result = {"hostname": hostname, "port": port}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=5),
                             server_hostname=hostname) as s:
            cert      = s.getpeercert()
            expiry_str= cert.get("notAfter", "")
            expiry    = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
            days_left = (expiry - datetime.datetime.utcnow()).days if expiry else None
            result.update({
                "subject":   dict(x[0] for x in cert.get("subject", [])),
                "issuer":    dict(x[0] for x in cert.get("issuer", [])),
                "expires":   expiry_str,
                "days_left": days_left,
                "protocol":  s.version(),
                "risk":      "Critical" if (days_left is not None and days_left < 0) else
                             "High"     if (days_left is not None and days_left < 14) else
                             "Medium"   if (days_left is not None and days_left < 30) else "Low",
                "issue":     "Certificate EXPIRED" if (days_left is not None and days_left < 0) else
                             f"Expires in {days_left} days" if days_left is not None else "Certificate valid",
            })
    except Exception as e:
        result.update({"risk": "Info", "issue": "Could not check SSL", "error": str(e)})
    return result

def check_sensitive_paths(base_url, timeout=5):
    findings = []
    base_url = base_url.rstrip("/")
    def probe(path):
        try:
            resp = requests.get(f"{base_url}{path}", timeout=timeout, verify=False, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                risk = "Critical" if path in ("/.env","/.git/config","/db.sql","/backup.zip") else \
                       "High"     if resp.status_code == 200 else "Medium"
                return {"path": path, "status_code": resp.status_code, "risk": risk,
                        "issue": f"Path '{path}' returned HTTP {resp.status_code}"}
        except Exception:
            pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(probe, SENSITIVE_PATHS):
            if result:
                findings.append(result)
    return sorted(findings, key=lambda x: {"Critical":0,"High":1,"Medium":2}.get(x["risk"],3))

def enumerate_subdomains(domain, timeout=1.5):
    found = []
    def resolve(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip}
        except socket.gaierror:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(resolve, COMMON_SUBDOMAINS):
            if result:
                found.append(result)
    return sorted(found, key=lambda x: x["subdomain"])

def run_web_scan(target):
    url = target if target.startswith(("http://","https://")) else f"https://{target}"
    hostname = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
    is_ip = False
    try:
        ipaddress.IPv4Address(hostname)
        is_ip = True
    except ValueError:
        pass

    return {
        "target":    target,
        "url":       url,
        "headers":   check_headers(url),
        "ssl":       check_ssl(hostname) if not is_ip else None,
        "sensitive_paths": check_sensitive_paths(url),
        "subdomains":      enumerate_subdomains(hostname) if not is_ip else [],
    }

# ── Report Generator ──────────────────────────────────────────────────────────
def generate_network_report(scan_results, target, ports, scan_type, duration_s):
    summary    = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
    total_cves = 0
    for host in scan_results:
        total_cves += host.get("cve_count", 0)
        for port in host["ports"]:
            risk = port.get("risk","Info")
            summary[risk] = summary.get(risk, 0) + 1

    risk_score = min(100, (
        summary["Critical"] * 25 + summary["High"] * 15 +
        summary["Medium"]   * 8  + summary["Low"]  * 2
    ))

    return {
        "report_metadata": {
            "tool":            "VulnScan Pro",
            "version":         "3.0.0",
            "author":          "Bhupendra Singh",
            "generated_at":    datetime.datetime.utcnow().isoformat() + "Z",
            "target":          target,
            "ports_scanned":   ports or SCAN_PROFILES.get(scan_type,{}).get("desc",""),
            "scan_type":       scan_type,
            "duration_seconds":round(duration_s, 2),
        },
        "executive_summary": {
            **summary,
            "total_open_ports": sum(len(h["ports"]) for h in scan_results),
            "total_cves_found": total_cves,
            "hosts_scanned":    len(scan_results),
            "risk_score":       risk_score,
        },
        "findings": scan_results,
    }

def generate_html_report(report, web_results=None):
    """Build a full HTML report for download."""
    meta    = report.get("report_metadata", {})
    summary = report.get("executive_summary", {})
    findings= report.get("findings", [])
    risk_score = summary.get("risk_score", 0)

    findings_html = ""
    for host in findings:
        if not host.get("ports"):
            continue
        findings_html += f"""
        <div class="host-card">
          <div class="host-header">
            <div><strong>{host['host']}</strong> {f"({host['hostname']})" if host.get('hostname') else ''}
              &nbsp;<span class="badge badge-{host.get('overall_risk','Info').lower()}">{host.get('overall_risk','Info')}</span>
            </div>
            <div style="font-size:12px;color:#888;">OS: {host.get('os_guess','Unknown')} · {len(host['ports'])} open ports · {host.get('cve_count',0)} CVEs</div>
          </div>
          <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th><th>Banner</th><th>CVEs</th><th>Remediation</th></tr></thead>
            <tbody>
        """
        for p in host.get("ports", []):
            cves_html = " ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{c["id"]}" target="_blank">{c["id"]} ({c["score"]})</a>' for c in p.get("cves",[]))
            findings_html += f"""
              <tr>
                <td><code>{p['port']}/{p['protocol']}</code></td>
                <td>{p['service']}</td>
                <td style="font-size:11px;color:#888">{p.get('version','—')}</td>
                <td><span class="badge badge-{p['risk'].lower()}">{p['risk']}</span></td>
                <td style="font-size:11px;color:#888;font-family:monospace">{p.get('banner','—')[:60]}</td>
                <td style="font-size:11px">{cves_html or '—'}</td>
                <td style="font-size:11px">{p.get('remediation','')}</td>
              </tr>"""
        findings_html += "</tbody></table></div>"

    web_html = ""
    if web_results:
        headers_rows = "".join(
            f'<tr><td>{f["header"]}</td><td><span class="badge badge-{f["risk"].lower()}">{f["risk"]}</span></td><td>{f["issue"]}</td><td style="font-size:11px">{f["fix"]}</td></tr>'
            for f in web_results.get("headers",{}).get("findings",[])
        )
        path_rows = "".join(
            f'<tr><td><code>{p["path"]}</code></td><td>{p["status_code"]}</td><td><span class="badge badge-{p["risk"].lower()}">{p["risk"]}</span></td></tr>'
            for p in web_results.get("sensitive_paths",[])
        )
        ssl = web_results.get("ssl") or {}
        sub_rows = "".join(
            f'<tr><td>{s["subdomain"]}</td><td>{s["ip"]}</td></tr>'
            for s in web_results.get("subdomains",[])
        )
        web_html = f"""
        <h2>🌍 Web Application Findings</h2>
        <h3>Security Headers</h3>
        <table><thead><tr><th>Header</th><th>Risk</th><th>Issue</th><th>Fix</th></tr></thead>
        <tbody>{headers_rows or '<tr><td colspan=4>All headers present ✓</td></tr>'}</tbody></table>
        <h3>SSL/TLS</h3>
        <p>Protocol: <strong>{ssl.get('protocol','N/A')}</strong> · Expires: <strong>{ssl.get('expires','N/A')}</strong> · Days left: <strong>{ssl.get('days_left','N/A')}</strong> · Risk: <span class="badge badge-{ssl.get('risk','info').lower()}">{ssl.get('risk','N/A')}</span></p>
        <h3>Sensitive Paths ({len(web_results.get('sensitive_paths',[]))} accessible)</h3>
        <table><thead><tr><th>Path</th><th>HTTP Status</th><th>Risk</th></tr></thead>
        <tbody>{path_rows or '<tr><td colspan=3>No sensitive paths exposed ✓</td></tr>'}</tbody></table>
        <h3>Subdomains ({len(web_results.get('subdomains',[]))} found)</h3>
        <table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead>
        <tbody>{sub_rows or '<tr><td colspan=2>None discovered</td></tr>'}</tbody></table>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>VulnScan Pro Report — {meta.get('target','')}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background:#f5f5f5; color:#222; margin:0; padding:20px; }}
    .header {{ background:linear-gradient(135deg,#1a2a4a,#2980b9); color:#fff; padding:30px 40px; border-radius:10px; margin-bottom:24px; }}
    .header h1 {{ margin:0 0 6px; font-size:26px; }} .header p {{ margin:0; opacity:0.85; font-size:14px; }}
    .summary {{ display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:24px; }}
    .stat {{ background:#fff; border-radius:8px; padding:16px; text-align:center; box-shadow:0 1px 4px rgba(0,0,0,0.08); }}
    .stat-value {{ font-size:28px; font-weight:bold; }}
    .stat-label {{ font-size:11px; color:#888; text-transform:uppercase; letter-spacing:1px; margin-top:4px; }}
    .host-card {{ background:#fff; border-radius:8px; margin-bottom:20px; overflow:hidden; box-shadow:0 1px 4px rgba(0,0,0,0.08); }}
    .host-header {{ background:#2c3e50; color:#fff; padding:14px 20px; }}
    table {{ width:100%; border-collapse:collapse; }}
    th {{ background:#f0f0f0; padding:10px 14px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#666; }}
    td {{ padding:10px 14px; border-bottom:1px solid #eee; font-size:13px; vertical-align:top; }}
    h2 {{ color:#1a2a4a; margin:28px 0 14px; }} h3 {{ color:#2980b9; margin:20px 0 10px; }}
    .badge {{ padding:2px 10px; border-radius:12px; font-size:11px; font-weight:bold; }}
    .badge-critical {{ background:#fdecea; color:#c0392b; }}
    .badge-high {{ background:#fef0e6; color:#e67e22; }}
    .badge-medium {{ background:#fefde6; color:#f39c12; }}
    .badge-low {{ background:#eafaf1; color:#27ae60; }}
    .badge-info {{ background:#f4f4f4; color:#888; }}
    a {{ color:#2980b9; }}
    .footer {{ text-align:center; color:#888; font-size:12px; margin-top:30px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🔐 VulnScan Pro — Security Assessment Report</h1>
    <p>Target: <strong>{meta.get('target','')}</strong> · Profile: <strong>{meta.get('scan_type','')}</strong> · Generated: <strong>{meta.get('generated_at','')[:19].replace('T',' ')} UTC</strong> · Duration: <strong>{meta.get('duration_seconds','')}s</strong></p>
  </div>
  <div class="summary">
    {''.join(f'<div class="stat"><div class="stat-value" style="color:{"#c0392b" if l=="Critical" else "#e67e22" if l=="High" else "#f39c12" if l=="Medium" else "#27ae60" if l=="Low" else "#888"}">{summary.get(l,0)}</div><div class="stat-label">{l}</div></div>' for l in ["Critical","High","Medium","Low","Info"])}
    <div class="stat"><div class="stat-value" style="color:#2980b9">{risk_score}/100</div><div class="stat-label">Risk Score</div></div>
  </div>
  <h2>🌐 Network Findings</h2>
  {findings_html or '<p style="color:#888">No open ports found.</p>'}
  {web_html}
  <div class="footer">Generated by VulnScan Pro v3.0 · github.com/pharaoh77731 · For authorised testing only.</div>
</body>
</html>"""

# ── Async Job Engine ──────────────────────────────────────────────────────────
def _run_job(job_id, target, ports, scan_type, include_web):
    with jobs_lock:
        jobs[job_id]["status"]     = "running"
        jobs[job_id]["started_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    start = datetime.datetime.utcnow()
    try:
        results      = run_scan(target, ports, scan_type)
        duration     = (datetime.datetime.utcnow() - start).total_seconds()
        report       = generate_network_report(results, target, ports, scan_type, duration)
        web_results  = None

        if include_web:
            try:
                web_results = run_web_scan(target)
                report["web_findings"] = web_results
            except Exception as e:
                report["web_error"] = str(e)

        html_report = generate_html_report(report, web_results)

        with jobs_lock:
            jobs[job_id].update({
                "status":       "completed",
                "completed_at": datetime.datetime.utcnow().isoformat() + "Z",
                "report":       report,
                "html_report":  html_report,
            })
        logger.info(f"Job {job_id} completed in {duration:.1f}s")
    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}", exc_info=True)
        with jobs_lock:
            jobs[job_id].update({"status": "failed", "error": str(e)})

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":      "ok",
        "version":     "3.0.0",
        "nmap_version": _health_nm.nmap_version(),
        "active_jobs": sum(1 for j in jobs.values() if j["status"] == "running"),
    }), 200

@app.route("/api/scan/profiles", methods=["GET"])
def scan_profiles():
    return jsonify({k: v["desc"] for k, v in SCAN_PROFILES.items()}), 200

@app.route("/api/scan", methods=["POST"])
@require_api_key
@limiter.limit("10 per minute")
def scan_async():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    target      = data.get("target", "").strip()
    ports       = data.get("ports", "").strip()
    scan_type   = data.get("scan_type", "standard").strip()
    include_web = data.get("include_web", False)

    ok, err = validate_target(target)
    if not ok:
        return jsonify({"error": err}), 400
    if ports:
        ok, err = validate_ports(ports)
        if not ok:
            return jsonify({"error": err}), 400
    ok, err = validate_scan_type(scan_type)
    if not ok:
        return jsonify({"error": err}), 400

    with jobs_lock:
        active = sum(1 for j in jobs.values() if j["status"] == "running")
    if active >= MAX_SCAN_THREADS:
        return jsonify({"error": "Too many concurrent scans. Please wait."}), 429

    job_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[job_id] = {
            "job_id":       job_id,
            "status":       "queued",
            "target":       target,
            "ports":        ports,
            "scan_type":    scan_type,
            "include_web":  include_web,
            "submitted_at": datetime.datetime.utcnow().isoformat() + "Z",
            "started_at":   None,
            "completed_at": None,
            "report":       None,
            "html_report":  None,
            "error":        None,
        }

    thread = threading.Thread(
        target=_run_job,
        args=(job_id, target, ports, scan_type, include_web),
        daemon=True
    )
    thread.start()
    logger.info(f"Job {job_id} queued for {target} [web={include_web}]")
    return jsonify({"job_id": job_id, "status": "queued"}), 202

@app.route("/api/scan/web", methods=["POST"])
@require_api_key
@limiter.limit("20 per minute")
def web_scan_only():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required."}), 400
    try:
        return jsonify(run_web_scan(target)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/jobs/<job_id>", methods=["GET"])
@require_api_key
def get_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404
    # Don't send html_report in JSON poll — it's large
    safe = {k: v for k, v in job.items() if k != "html_report"}
    return jsonify(safe), 200

@app.route("/api/jobs/<job_id>/report", methods=["GET"])
@require_api_key
def download_report(job_id):
    """Download the HTML report for a completed job."""
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404
    if job["status"] != "completed":
        return jsonify({"error": f"Job is {job['status']}, not completed."}), 400
    html = job.get("html_report", "")
    if not html:
        return jsonify({"error": "No report available."}), 404

    import io
    ts     = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    target = job["target"].replace(".", "_")
    filename = f"vulnscan_{target}_{ts}.html"
    return send_file(
        io.BytesIO(html.encode()),
        mimetype="text/html",
        as_attachment=True,
        download_name=filename,
    )

@app.route("/api/jobs", methods=["GET"])
@require_api_key
def list_jobs():
    with jobs_lock:
        job_list = [
            {k: v for k, v in j.items() if k not in ("report","html_report")}
            for j in jobs.values()
        ]
    return jsonify(sorted(job_list, key=lambda x: x["submitted_at"], reverse=True)), 200

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"VulnScan Pro v3.0 starting on port {port}")
    app.run(debug=debug, host="0.0.0.0", port=port)
