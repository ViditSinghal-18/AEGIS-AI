"""
Passive HTTP checks: reachability, page title, TLS vs plain HTTP, security headers,
cookie hardening flags, CORS policy, and software version disclosure.

Security terms explained for 3rd semester students:
- Security Headers (CSP, HSTS, XFO, XCTO, Referrer-Policy): Defensive instructions sent by
  the web server that instruct the client's browser to restrict malicious behavior (e.g. framing, script injection).
- Cookie Flags:
  * Secure: Instructs browser to only send cookies over HTTPS encrypted connections.
  * HttpOnly: Blocks client-side JavaScript from accessing cookies (document.cookie), mitigating XSS token theft.
  * SameSite (Strict/Lax/None): Controls whether cookies are sent along with cross-site requests, mitigating CSRF.
- CORS (Cross-Origin Resource Sharing): A mechanism where headers like 'Access-Control-Allow-Origin: *'
  determine which external websites can read API responses. A wildcard '*' allows any untrusted domain to read data.
- Version Disclosure: Headers like 'Server: Apache/2.4.49' or 'X-Powered-By: Express' reveal underlying tech stacks
  to potential attackers, making targeted CVE exploitation easier.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
import urllib3

from config import is_loopback, require_allowed_target

# Local Docker Juice Shop often uses HTTP; we skip TLS verify only on loopback.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from schemas import HttpCheck

# Baseline security headers to check
SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "strict-transport-security",
)


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def _extract_title(html: str) -> str:
    parser = _TitleParser()
    try:
        parser.feed(html)
    except Exception:
        return ""
    return parser.title.strip()[:200]


def _check_cookies(response: requests.Response) -> list[str]:
    """Inspect Set-Cookie headers for Secure, HttpOnly, and SameSite flags."""
    issues: list[str] = []
    # Check raw Set-Cookie headers
    raw_cookies = response.headers.get("set-cookie", "")
    if not raw_cookies and not response.cookies:
        return issues

    for cookie in response.cookies:
        cookie_name = cookie.name
        # Secure flag check (especially relevant if on HTTPS)
        if not cookie.secure:
            issues.append(f"cookie-missing-secure: Cookie '{cookie_name}' missing Secure flag")
        
        # HttpOnly flag check
        # In requests, cookie._rest often holds httponly or check raw header
        is_httponly = "httponly" in raw_cookies.lower() or getattr(cookie, "has_nonstandard_attr", lambda k: False)("HttpOnly")
        if not is_httponly and not getattr(cookie, "_rest", {}).get("HttpOnly"):
            issues.append(f"cookie-missing-httponly: Cookie '{cookie_name}' missing HttpOnly flag")

        # SameSite attribute check
        has_samesite = "samesite" in raw_cookies.lower() or getattr(cookie, "_rest", {}).get("SameSite")
        if not has_samesite:
            issues.append(f"cookie-missing-samesite: Cookie '{cookie_name}' missing SameSite attribute")

    return list(dict.fromkeys(issues))  # Deduplicate


def _check_cors(headers: dict[str, str]) -> list[str]:
    """Inspect CORS configuration headers for wildcard or overly permissive origins."""
    issues: list[str] = []
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    if allow_origin == "*":
        issues.append("cors-wildcard-origin: Access-Control-Allow-Origin header is set to wildcard (*)")
    elif allow_origin == "null":
        issues.append("cors-null-origin: Access-Control-Allow-Origin header is set to 'null'")
    return issues


def _check_version_disclosure(headers: dict[str, str]) -> list[str]:
    """Inspect response headers for banner/software version leakage."""
    issues: list[str] = []
    server = headers.get("server", "").strip()
    if server:
        issues.append(f"version-disclosure-server: Server header discloses software banner '{server}'")

    x_powered_by = headers.get("x-powered-by", "").strip()
    if x_powered_by:
        issues.append(f"version-disclosure-x-powered-by: X-Powered-By header discloses technology stack '{x_powered_by}'")

    return issues


def probe_http(target: str, port: int = 3000, use_tls: bool = False) -> HttpCheck:
    host = require_allowed_target(target)
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    notes: list[str] = []
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            verify=False if is_loopback(host) else True,
        )
    except requests.RequestException as exc:
        return HttpCheck(
            url=url,
            reachable=False,
            uses_tls=use_tls,
            notes=[f"HTTP probe failed: {exc.__class__.__name__}"],
        )

    parsed = urlparse(response.url)
    if parsed.hostname and not (
        parsed.hostname.lower() in {host, "localhost", "127.0.0.1"}
    ):
        notes.append("Refused to follow a redirect off the allowlisted host.")
        return HttpCheck(url=url, reachable=True, status_code=response.status_code, notes=notes)

    header_map = {k.lower(): v for k, v in response.headers.items()}
    missing = [name for name in SECURITY_HEADERS if name not in header_map]
    if not use_tls:
        # HSTS only applies to HTTPS; do not flag it on plain HTTP localhost.
        missing = [h for h in missing if h != "strict-transport-security"]
        notes.append("Service is HTTP, not HTTPS (no TLS on this probe).")

    # Extra passive detections
    cookie_issues = _check_cookies(response)
    cors_issues = _check_cors(header_map)
    version_issues = _check_version_disclosure(header_map)

    title = _extract_title(response.text) if "html" in header_map.get("content-type", "") else ""
    if "juice shop" in title.lower() or "juice shop" in response.text[:2000].lower():
        notes.append("Page identifies as OWASP Juice Shop (expected lab target).")

    return HttpCheck(
        url=url,
        reachable=True,
        status_code=response.status_code,
        title=title,
        uses_tls=use_tls,
        missing_security_headers=missing,
        cookie_issues=cookie_issues,
        cors_issues=cors_issues,
        version_disclosure_issues=version_issues,
        notes=notes,
    )
