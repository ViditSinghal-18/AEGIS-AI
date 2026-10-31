"""
AEGIS-AI: Passive OSINT Collection Engine.
Safely gathers public DNS, TLS, HTTP, Certificate Transparency, and WAF/CDN intelligence
without intrusive active scanning or port probing. Completely serverless-compatible (runs on Vercel).
"""

from __future__ import annotations

import datetime
import json
import os
import re
import socket
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from discovery.safe_fetch import safe_fetch, SafeFetchError, resolve_and_validate_hostname


# Common CDN and WAF Header / Body / Host Signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "server: cloudflare"],
    "CloudFront (AWS)": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "server: akamai"],
    "Fastly": ["x-fastly-request-id", "fastly-restarts"],
    "Imperva / Incapsula": ["x-cdn: incapsula", "incap_ses", "visid_incap"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
    "Varnish": ["x-varnish"],
    "Azure Front Door": ["x-azure-ref", "x-ms-ref"]
}


def extract_html_title(html_content: str) -> str:
    """Extract page title from HTML string safely."""
    from html.parser import HTMLParser

    class _TitleParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self._in_title = False
            self.title = ""

        def handle_starttag(self, tag, attrs):
            if tag.lower() == "title":
                self._in_title = True

        def handle_endtag(self, tag):
            if tag.lower() == "title":
                self._in_title = False

        def handle_data(self, data):
            if self._in_title:
                self.title += data

    parser = _TitleParser()
    try:
        parser.feed(html_content[:50000])  # limit search window
    except Exception:
        return ""
    return parser.title.strip()[:200]


def detect_waf_and_cdn(headers: Dict[str, str], body: str = "", cnames: Optional[List[str]] = None) -> Dict[str, Any]:
    """Detect WAF or CDN presence using HTTP response headers and DNS CNAMEs."""
    detected = []
    header_blob = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers.items())
    cnames_blob = " ".join(cnames or []).lower()

    for provider, sigs in WAF_SIGNATURES.items():
        matched = False
        for sig in sigs:
            if sig.lower() in header_blob or (cnames and sig.lower() in cnames_blob):
                detected.append(provider)
                matched = True
                break

    is_behind_waf = len(detected) > 0
    return {
        "detected": is_behind_waf,
        "providers": list(dict.fromkeys(detected)),
        "mitigation_factor": 0.6 if is_behind_waf else 1.0,
        "details": f"Protected by {', '.join(detected)}" if detected else "Direct exposure (no WAF/CDN signature detected)"
    }


def probe_passive_dns(domain: str) -> Dict[str, Any]:
    """
    Query DNS A, AAAA, MX, TXT, SPF, and DMARC records safely.
    Uses socket resolution and nslookup / DoH fallback without external dependencies.
    """
    records: Dict[str, Any] = {
        "domain": domain,
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "spf_present": False,
        "spf_record": None,
        "dmarc_present": False,
        "dmarc_record": None,
        "issues": [],
        "evidence": {}
    }

    # 1. Resolve A and AAAA records via standard socket
    try:
        addr_info = socket.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in records["A"]:
                records["A"].append(ip)
            elif family == socket.AF_INET6 and ip not in records["AAAA"]:
                records["AAAA"].append(ip)
    except socket.gaierror as e:
        records["issues"].append(f"dns-resolution-error: Failed to resolve {domain}: {e}")

    # 2. Query TXT and SPF records via nslookup
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            line_s = line.strip()
            if "text =" in line_s or "v=spf1" in line_s:
                txt_val = line_s.split("text =", 1)[-1].strip().strip('"') if "text =" in line_s else line_s
                records["TXT"].append(txt_val)
                if "v=spf1" in txt_val.lower():
                    records["spf_present"] = True
                    records["spf_record"] = txt_val
    except Exception:
        pass

    if not records["spf_present"]:
        records["issues"].append("email-missing-spf: No SPF (Sender Policy Framework) record found. Domain susceptible to email spoofing.")

    # 3. Query DMARC record (_dmarc.<domain>)
    try:
        proc_dmarc = subprocess.run(["nslookup", "-type=TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=5)
        for line in proc_dmarc.stdout.splitlines():
            line_s = line.strip()
            if "v=DMARC1" in line_s:
                records["dmarc_present"] = True
                dmarc_val = line_s.split("text =", 1)[-1].strip().strip('"') if "text =" in line_s else line_s
                records["dmarc_record"] = dmarc_val
                break
    except Exception:
        pass

    if not records["dmarc_present"]:
        records["issues"].append("email-missing-dmarc: No DMARC record found. Domain lacks policy enforcement for unauthorized mail senders.")

    # 4. Query MX records
    try:
        proc_mx = subprocess.run(["nslookup", "-type=MX", domain], capture_output=True, text=True, timeout=5)
        for line in proc_mx.stdout.splitlines():
            line_s = line.strip()
            if "mail exchanger =" in line_s:
                mx_host = line_s.split("mail exchanger =", 1)[-1].strip()
                records["MX"].append(mx_host)
    except Exception:
        pass

    return records


def probe_passive_tls(domain: str) -> Dict[str, Any]:
    """
    Safely inspect the public TLS certificate on port 443.
    Uses pre-resolved pinned IP and server_hostname (SNI) to prevent SSRF and DNS rebinding.
    """
    tls_info: Dict[str, Any] = {
        "reachable": False,
        "protocol": None,
        "cipher": None,
        "issuer": None,
        "subject": None,
        "sans": [],
        "valid_from": None,
        "valid_to": None,
        "days_until_expiry": None,
        "is_expired": False,
        "is_self_signed": False,
        "issues": []
    }

    try:
        validated_ips = resolve_and_validate_hostname(domain)
        pinned_ip = validated_ips[0]
    except Exception as exc:
        tls_info["issues"].append(f"tls-aborted: IP resolution failed or blocked: {exc}")
        return tls_info

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((pinned_ip, 443), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                tls_info["reachable"] = True
                tls_info["protocol"] = ssock.version()
                tls_cipher = ssock.cipher()
                if tls_cipher:
                    tls_info["cipher"] = tls_cipher[0]

                cert = ssock.getpeercert()
                if cert:
                    # Expiry evaluation
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        tls_info["valid_to"] = exp_dt.isoformat()
                        days_left = (exp_dt - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                        tls_info["days_until_expiry"] = days_left
                        if days_left < 0:
                            tls_info["is_expired"] = True
                            tls_info["issues"].append(f"tls-cert-expired: Public certificate expired {abs(days_left)} days ago.")
                        elif days_left < 15:
                            tls_info["issues"].append(f"tls-cert-expiring-soon: Public certificate expires in {days_left} days.")

                    not_before_str = cert.get("notBefore")
                    if not_before_str:
                        start_dt = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                        tls_info["valid_from"] = start_dt.isoformat()

                    # Issuer & Subject
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    tls_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown")
                    tls_info["subject"] = subject_dict.get("commonName", "Unknown")

                    # Subject Alternative Names (SANs)
                    sans = []
                    for san_type, san_val in cert.get("subjectAltName", ()):
                        if san_type == "DNS":
                            sans.append(san_val)
                    tls_info["sans"] = sans[:25]  # Cap to first 25

                    if tls_info["issuer"] == tls_info["subject"] and tls_info["issuer"] != "Unknown":
                        tls_info["is_self_signed"] = True
                        tls_info["issues"].append("tls-self-signed: Public TLS certificate is self-signed.")

                # Check protocol version
                if tls_info["protocol"] in ["TLSv1", "TLSv1.1"]:
                    tls_info["issues"].append(f"tls-deprecated-version: Obsolete and insecure protocol {tls_info['protocol']} negotiated.")

    except ssl.SSLCertVerificationError as exc:
        tls_info["issues"].append(f"tls-cert-invalid: Certificate verification failed: {exc}")
    except Exception as exc:
        tls_info["issues"].append(f"tls-connection-failed: {exc.__class__.__name__}: {exc}")

    return tls_info


def probe_passive_http(domain: str) -> Dict[str, Any]:
    """
    Execute safe HTTP/HTTPS probes to analyze security headers, server tokens, cookies, and CORS.
    Uses safe_fetch (SSRF protected, redirect limited, size capped).
    """
    urls_to_try = [f"https://{domain}/", f"http://{domain}/"]
    response = None
    final_url = urls_to_try[0]
    errors = []

    for url in urls_to_try:
        try:
            response = safe_fetch(url, timeout=5.0)
            final_url = url
            break
        except SafeFetchError as exc:
            errors.append(f"Probe to {url} skipped: {exc}")
        except Exception as exc:
            errors.append(f"Probe to {url} failed: {exc.__class__.__name__}")

    if response is None:
        return {
            "reachable": False,
            "url": final_url,
            "status_code": None,
            "headers": {},
            "missing_security_headers": [],
            "cookie_issues": [],
            "cors_issues": [],
            "version_disclosure": [],
            "waf_detection": {"detected": False, "providers": [], "mitigation_factor": 1.0, "details": "Unreachable"},
            "title": "",
            "errors": errors or ["Host unreachable over HTTP/HTTPS."]
        }

    header_map = {k.lower(): v for k, v in response.headers.items()}
    security_headers = [
        ("strict-transport-security", "HSTS missing: Insecure HTTP downgrade attacks possible."),
        ("content-security-policy", "CSP missing: Application vulnerable to Cross-Site Scripting (XSS) and code injection."),
        ("x-frame-options", "X-Frame-Options missing: Vulnerable to Clickjacking via UI redressing."),
        ("x-content-type-options", "X-Content-Type-Options missing: MIME-type sniffing can lead to script execution."),
        ("referrer-policy", "Referrer-Policy missing: Sensitive URL path/query parameters may leak to external referrers."),
        ("permissions-policy", "Permissions-Policy missing: Browser features (camera, mic, geolocation) not restricted.")
    ]

    missing = []
    for h, desc in security_headers:
        if h not in header_map:
            # Only flag HSTS for HTTPS
            if h == "strict-transport-security" and not final_url.startswith("https"):
                continue
            missing.append({"header": h, "description": desc})

    # Cookies audit
    cookie_issues = []
    raw_cookie_headers = response.headers.get("set-cookie", "")
    for cookie in response.cookies:
        if not cookie.secure and final_url.startswith("https"):
            cookie_issues.append(f"Cookie '{cookie.name}' missing Secure attribute.")
        if "httponly" not in raw_cookie_headers.lower():
            cookie_issues.append(f"Cookie '{cookie.name}' missing HttpOnly attribute.")
        if "samesite" not in raw_cookie_headers.lower():
            cookie_issues.append(f"Cookie '{cookie.name}' missing SameSite attribute.")

    # CORS audit
    cors_issues = []
    allow_origin = header_map.get("access-control-allow-origin", "").strip()
    if allow_origin == "*":
        cors_issues.append("Wildcard CORS (Access-Control-Allow-Origin: *) permits arbitrary third-party origin reading.")

    # Version disclosure
    version_disclosure = []
    server_hdr = header_map.get("server")
    if server_hdr:
        version_disclosure.append(f"Server header disclosure: '{server_hdr}'")
    powered_by = header_map.get("x-powered-by")
    if powered_by:
        version_disclosure.append(f"X-Powered-By disclosure: '{powered_by}'")

    waf_data = detect_waf_and_cdn(response.headers, body=response.text[:2000])

    return {
        "reachable": True,
        "url": final_url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "server_banner": server_hdr or "",
        "powered_by": powered_by or "",
        "missing_security_headers": missing,
        "cookie_issues": list(dict.fromkeys(cookie_issues)),
        "cors_issues": cors_issues,
        "version_disclosure": version_disclosure,
        "waf_detection": waf_data,
        "title": extract_html_title(response.text),
        "errors": errors
    }


def query_certificate_transparency(domain: str, limit: int = 20) -> List[str]:
    """
    Passively discover subdomains from public Certificate Transparency logs (crt.sh).
    Timeouts and size limits enforced via safe_fetch.
    """
    subdomains: set[str] = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = safe_fetch(url, timeout=6.0, headers={"User-Agent": "AEGIS-Security-Discovery/1.0"})
        if res.status_code == 200:
            entries = res.json()
            for entry in entries:
                name_val = entry.get("name_value", "")
                for raw_name in name_val.split("\n"):
                    clean = raw_name.strip().lower()
                    if clean and not clean.startswith("*.") and domain in clean:
                        subdomains.add(clean)
                        if len(subdomains) >= limit:
                            break
                if len(subdomains) >= limit:
                    break
    except Exception:
        # Certificate Transparency is purely passive discovery; failure must never break pipeline
        pass

    return sorted(list(subdomains))


def run_passive_recon(target: str) -> Dict[str, Any]:
    """
    Run complete passive OSINT collection on target domain.
    Aggregates DNS, TLS, HTTP, WAF, and Certificate Transparency into a unified report.
    """
    start_time = time.time()
    dns_data = probe_passive_dns(target)
    tls_data = probe_passive_tls(target)
    http_data = probe_passive_http(target)
    ct_subdomains = query_certificate_transparency(target, limit=20)
    duration = round(time.time() - start_time, 2)

    return {
        "target": target,
        "mode": "PASSIVE OSINT",
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "duration_seconds": duration,
        "dns": dns_data,
        "tls": tls_data,
        "http": http_data,
        "certificate_transparency_subdomains": ct_subdomains,
        "waf": http_data.get("waf_detection", {"detected": False, "providers": [], "mitigation_factor": 1.0}),
        "inferred_technologies": [
            b for b in [http_data.get("server_banner"), http_data.get("powered_by")] if b
        ]
    }
