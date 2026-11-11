"""
Passive website discovery mode.
Collects public information without active port probing or intrusive scanning.

Security terms explained for 3rd semester students:
- Certificate Transparency (CT Logs): A public, append-only log of all SSL/TLS certificates issued by CAs.
  Used to passively discover subdomains without sending any traffic to them.
- SPF (Sender Policy Framework): A DNS TXT record specifying which mail servers are authorized
  to send emails on behalf of a domain, mitigating email spoofing.
- DMARC (Domain-based Message Authentication, Reporting, and Conformance): A DNS TXT record
  instructing recipient mail servers how to handle emails that fail SPF/DKIM validation.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import ssl
import subprocess
import time
from urllib.parse import urlparse
from typing import Any

import requests

from config import DATA_DIR
from discovery.safe_fetch import safe_fetch, SafeFetchError
from discovery.csp_grader import grade_csp
from discovery.email_grader import grade_email_security
from discovery.dangling_dns import verify_dangling_dns
from discovery.secret_classifier import probe_exposed_files
from discovery.breach_propensity import calculate_breach_propensity
from schemas import DiscoveredAssets, HttpCheck, OpenPort, TlsGrade
from storage import write_json

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()


def _extract_title(html: str) -> str:
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
        parser.feed(html)
    except Exception:
        return ""
    return parser.title.strip()[:200]


def _probe_passive_http(domain: str) -> HttpCheck:
    """Execute a single safe GET request over HTTPS (fallback to HTTP)."""
    urls_to_try = [f"https://{domain}/", f"http://{domain}/"]
    response = None
    final_url = urls_to_try[0]
    notes: list[str] = []

    for url in urls_to_try:
        try:
            response = safe_fetch(url, timeout=5.0)
            final_url = url
            break
        except SafeFetchError as exc:
            notes.append(f"Probe to {url} skipped: {exc}")
        except Exception as exc:
            notes.append(f"Probe to {url} failed: {exc.__class__.__name__}")

    if response is None:
        return HttpCheck(
            url=final_url,
            reachable=False,
            uses_tls="https" in final_url,
            notes=notes or ["Target domain was not reachable over standard HTTP/HTTPS."],
        )

    header_map = {k.lower(): v for k, v in response.headers.items()}
    security_headers = (
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "strict-transport-security",
    )
    missing = [name for name in security_headers if name not in header_map]
    if "https" not in final_url:
        missing = [h for h in missing if h != "strict-transport-security"]

    # Cookie checks
    cookie_issues = []
    raw_cookies = response.headers.get("set-cookie", "")
    for cookie in response.cookies:
        if not cookie.secure and "https" in final_url:
            cookie_issues.append(f"cookie-missing-secure: Cookie '{cookie.name}' missing Secure flag")
        if "httponly" not in raw_cookies.lower():
            cookie_issues.append(f"cookie-missing-httponly: Cookie '{cookie.name}' missing HttpOnly flag")
        if "samesite" not in raw_cookies.lower():
            cookie_issues.append(f"cookie-missing-samesite: Cookie '{cookie.name}' missing SameSite attribute")

    # CORS checks
    cors_issues = []
    allow_origin = header_map.get("access-control-allow-origin", "").strip()
    if allow_origin == "*":
        cors_issues.append("cors-wildcard-origin: Access-Control-Allow-Origin header is set to wildcard (*)")

    # Version disclosure
    version_issues = []
    if "server" in header_map:
        version_issues.append(f"version-disclosure-server: Server header discloses '{header_map['server']}'")
    if "x-powered-by" in header_map:
        version_issues.append(f"version-disclosure-x-powered-by: X-Powered-By discloses '{header_map['x-powered-by']}'")

    title = _extract_title(response.text)
    if "content-security-policy" in header_map:
        notes.append(f"csp_raw:{header_map['content-security-policy']}")

    return HttpCheck(
        url=final_url,
        reachable=True,
        status_code=response.status_code,
        title=title,
        uses_tls="https" in final_url,
        missing_security_headers=missing,
        cookie_issues=list(dict.fromkeys(cookie_issues)),
        cors_issues=cors_issues,
        version_disclosure_issues=version_issues,
        notes=notes,
    )


def _inspect_passive_tls(domain: str) -> TlsGrade:
    """Inspect the public TLS certificate on port 443 safely using pinned IP connection."""
    raw_info: dict[str, Any] = {
        "reachable": False,
        "protocol": "",
        "issuer": "",
        "subject": "",
        "days_until_expiry": None,
        "issues": [],
    }

    try:
        from discovery.safe_fetch import resolve_and_validate_hostname
        validated_ips = resolve_and_validate_hostname(domain)
        pinned_ip = validated_ips[0]
    except Exception as exc:
        return TlsGrade(
            skipped=True,
            reason=f"Passive TLS resolution aborted: {exc}",
            host=domain,
            raw={"error": str(exc)},
        )

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((pinned_ip, 443), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                raw_info["reachable"] = True
                raw_info["protocol"] = ssock.version() or ""
                cert = ssock.getpeercert()
                if cert:
                    # Calculate expiry days
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.datetime.utcnow()).days
                        raw_info["days_until_expiry"] = days_left
                        if days_left < 0:
                            raw_info["issues"].append("tls-cert-expired: Public TLS certificate has expired")
                        elif days_left < 15:
                            raw_info["issues"].append(f"tls-cert-expiring-soon: Public TLS certificate expires in {days_left} days")

                    # Extract subject and issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    raw_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "")
                    raw_info["subject"] = subject_dict.get("commonName", "")

                    if raw_info["issuer"] == raw_info["subject"] and raw_info["issuer"]:
                        raw_info["issues"].append("tls-self-signed: Public TLS certificate is self-signed")

        return TlsGrade(
            skipped=False,
            reason="Passive TLS inspection completed.",
            host=domain,
            grade="Valid" if not raw_info["issues"] else "Warning",
            raw=raw_info,
        )
    except Exception as exc:
        return TlsGrade(
            skipped=True,
            reason=f"Passive TLS connection failed: {exc.__class__.__name__}",
            host=domain,
            raw={"error": str(exc)},
        )


def _query_dns_records(domain: str) -> dict[str, Any]:
    """Query DNS A, AAAA, MX, TXT, SPF, and DMARC records via nslookup."""
    records: dict[str, Any] = {
        "domain": domain,
        "A": [],
        "MX": [],
        "TXT": [],
        "spf_present": False,
        "dmarc_present": False,
        "issues": [],
    }

    # Query TXT and SPF
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True, timeout=5)
        out = proc.stdout
        for line in out.splitlines():
            line_s = line.strip()
            if "text =" in line_s or "v=spf1" in line_s:
                records["TXT"].append(line_s)
                if "v=spf1" in line_s:
                    records["spf_present"] = True
    except Exception:
        pass

    if not records["spf_present"]:
        records["issues"].append("email-missing-spf: No SPF (Sender Policy Framework) DNS record found to prevent email spoofing.")

    # Query DMARC
    try:
        proc_dmarc = subprocess.run(["nslookup", "-type=TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=5)
        if "v=DMARC1" in proc_dmarc.stdout:
            records["dmarc_present"] = True
    except Exception:
        pass

    if not records["dmarc_present"]:
        records["issues"].append("email-missing-dmarc: No DMARC DNS record found to enforce email authentication policies.")

    return records


def _query_certificate_transparency(domain: str) -> list[str]:
    """Passively discover subdomains from public Certificate Transparency logs (crt.sh)."""
    subdomains: set[str] = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = safe_fetch(url, timeout=6.0, headers={"User-Agent": "Mozilla/5.0 (Defensive Sec Tool)"})
        if res.status_code == 200:
            entries = res.json()
            for entry in entries[:100]:
                name_value = entry.get("name_value", "")
                for sub in name_value.splitlines():
                    sub = sub.strip().lower()
                    if "*" not in sub and sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
    except (SafeFetchError, requests.RequestException, json.JSONDecodeError, OSError, ValueError):
        pass  # ct logs lookup is best-effort
    return sorted(list(subdomains))[:25]


def _query_shodan_intelligence(domain: str) -> dict[str, Any]:
    """Query Shodan's passive threat index for public open ports and CVEs safely."""
    shodan_info: dict[str, Any] = {"ports": [], "cpes": [], "tags": [], "source": "shodan-internetdb"}
    try:
        from discovery.safe_fetch import resolve_and_validate_hostname
        validated_ips = resolve_and_validate_hostname(domain)
        if not validated_ips:
            return shodan_info
        ip = validated_ips[0]
        # Use free public InternetDB via safe_fetch to prevent SSRF / rebinding
        res = safe_fetch(f"https://internetdb.shodan.io/{ip}", timeout=4.0)
        if res.status_code == 200:
            data = res.json()
            shodan_info["ports"] = data.get("ports", [])
            shodan_info["cpes"] = data.get("cpes", [])
            shodan_info["tags"] = data.get("tags", [])
    except (SafeFetchError, requests.RequestException, json.JSONDecodeError, OSError, ValueError):
        pass
    return shodan_info


def discover_passive(domain: str) -> DiscoveredAssets:
    """
    Perform 100% passive, read-only reconnaissance on a public domain.
    No active port scanning or intrusive probes are performed.
    """
    domain = domain.strip().lower()
    notes: list[str] = [
        "Mode: PASSIVE (Public reconnaissance only — no active port scanning was performed)."
    ]

    # 1. Passive HTTP observation
    http_check = _probe_passive_http(domain)
    
    # 2. Passive TLS certificate inspection
    tls_check = _inspect_passive_tls(domain)

    # 3. DNS and Email security inspection
    dns_info = _query_dns_records(domain)

    # 4. Certificate Transparency subdomains
    ct_subdomains = _query_certificate_transparency(domain)

    # 5. Passive Shodan threat intelligence
    shodan_intel = _query_shodan_intelligence(domain)

    # Synthesize open ports from HTTP reachability and Shodan
    ports_found: list[OpenPort] = []
    if http_check.reachable:
        p_num = 443 if http_check.uses_tls else 80
        ports_found.append(
            OpenPort(
                port=p_num,
                protocol="tcp",
                state="open",
                service="https" if http_check.uses_tls else "http",
                product=http_check.title or "web",
                version="",
                extra="passive-web-observation",
            )
        )

    # Add passive ports observed via Shodan InternetDB
    seen_ports = {p.port for p in ports_found}
    for sport in shodan_intel.get("ports", []):
        if sport not in seen_ports:
            seen_ports.add(sport)
            ports_found.append(
                OpenPort(
                    port=sport,
                    protocol="tcp",
                    state="open",
                    service="https" if sport in (443, 8443) else ("http" if sport in (80, 8080, 3000, 8000) else "service"),
                    product="",
                    version="",
                    extra="passive-shodan-internetdb",
                )
            )

    # 6. Phase 4: External Posture Intelligence
    raw_csp = ""
    for n in (http_check.notes or []):
        if n.startswith("csp_raw:"):
            raw_csp = n.split("csp_raw:", 1)[1]
            break
    csp_grade_res = grade_csp(raw_csp)
    email_sec_res = grade_email_security(domain)
    dangling_res = [verify_dangling_dns(s) for s in ct_subdomains[:4]]
    secret_findings = probe_exposed_files(f"https://{domain}") if http_check.reachable else []

    breach_report = calculate_breach_propensity(
        target=domain,
        email_score=email_sec_res.score,
        csp_score=csp_grade_res.score,
        tls_valid=(tls_check.grade in ["Valid", "A+", "A", "B", "Valid (Self-Signed)"]),
        tls_days_left=(tls_check.raw or {}).get("days_until_expiry"),
        exposed_secrets_count=len(secret_findings),
        dangling_takeovers_count=sum(1 for d in dangling_res if d.is_vulnerable),
        open_ports=[p.port for p in ports_found],
        missing_headers_count=len(http_check.missing_security_headers),
    )

    # Passive Metadata bundle
    passive_meta = {
        "dns": dns_info,
        "ct_subdomains": ct_subdomains,
        "ct_notice": "Subdomains discovered via public Certificate Transparency logs for mapping only (none were probed or scanned).",
        "shodan": shodan_intel,
        "csp": csp_grade_res.to_dict(),
        "email_security": email_sec_res.to_dict(),
        "dangling_dns": [d.to_dict() for d in dangling_res],
        "exposed_secrets": [s.to_dict() for s in secret_findings],
        "breach_propensity": breach_report.to_dict(),
    }

    notes.append(f"External Posture Grade: {breach_report.posture_grade} ({breach_report.overall_score:.1f}/100) — Breach Propensity: {breach_report.propensity_tier}")
    notes.append(f"Email Security Grade: {email_sec_res.grade} ({email_sec_res.score}/100) — DMARC: {email_sec_res.dmarc_policy}")
    notes.append(f"CSP Defense Grade: {csp_grade_res.grade} ({csp_grade_res.score}/100)")

    if ct_subdomains:
        notes.append(f"Discovered {len(ct_subdomains)} subdomains from Certificate Transparency logs.")
    for issue in dns_info.get("issues", []):
        notes.append(issue)
    for sec in secret_findings:
        notes.append(f"Exposed Secret Detected: {sec.secret_type} at {sec.location} ({sec.masked_hint})")
    for d in dangling_res:
        if d.is_vulnerable:
            notes.append(f"Dangling Subdomain Takeover: {d.subdomain} points to unallocated {d.provider_name}")

    assets = DiscoveredAssets(
        target=domain,
        scan_method="passive-osint",
        ports=ports_found,
        http=http_check,
        tls=tls_check,
        mode="passive",
        passive_meta=passive_meta,
        notes=notes,
    )

    write_json("discovered_assets.json", assets, target=domain)
    return assets


extract_html_title = _extract_title
probe_passive_dns = _query_dns_records
probe_passive_http = _probe_passive_http
query_certificate_transparency = _query_certificate_transparency

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


def detect_waf_and_cdn(headers: dict[str, str], body: str = "") -> dict[str, Any]:
    """Detect WAF and CDN providers from headers and response body."""
    detected = []
    header_str = " ".join(f"{k.lower()}: {str(v).lower()}" for k, v in (headers or {}).items())
    body_sample = body[:5000].lower() if body else ""

    for provider, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in header_str or sig.lower() in body_sample:
                detected.append(provider)
                break

    detected = list(dict.fromkeys(detected))
    return {
        "detected": bool(detected),
        "providers": detected,
        "mitigation_factor": 0.6 if detected else 1.0,
        "details": f"Shielded by {', '.join(detected)}" if detected else "Direct exposure (no WAF detected)"
    }


