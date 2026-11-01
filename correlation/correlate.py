"""Merge discovery JSON with NVD matches into one correlated findings file."""

from __future__ import annotations

from correlation.enrich import enrich_cves
from correlation.nvd_lookup import lookup_cves
from schemas import CorrelatedAsset, CorrelatedFindings, CveRecord
from storage import read_json, write_json

# Real severity mapping for configuration issues.
# Keys are lowercased substrings matched against the issue string;
# first match wins, so order from most- to least-specific matters.
_ISSUE_SEVERITY: list[tuple[str, str]] = [
    # Actively exploitable or confidentiality risk
    ("without tls encryption", "High"),
    ("weak tls grade", "High"),
    ("cors: wildcard", "High"),
    ("server version disclosure", "Medium"),
    # Missing security headers — ordered by impact
    ("strict-transport-security", "High"),   # HSTS missing → downgrade possible
    ("content-security-policy", "Medium"),   # CSP missing → XSS amplification
    ("x-frame-options", "Medium"),           # XFO missing → clickjacking
    ("x-content-type-options", "Low"),       # XCTO missing → MIME sniffing
    ("referrer-policy", "Low"),              # cosmetic privacy header
    ("permissions-policy", "Low"),           # feature policy, low urgency
    # Cookie hygiene
    ("cookie", "Medium"),
    # DNS / email security
    ("spf", "Medium"),
    ("dmarc", "Medium"),
    ("dns email security", "Medium"),
    # Informational
    ("certificate transparency", "Info"),
    ("open tcp/", "Info"),
]

_DEFAULT_SEVERITY = "Medium"


def _issue_severity(issue: str) -> str:
    """Return the most appropriate severity label for a config-check issue."""
    lower = issue.lower()
    for keyword, sev in _ISSUE_SEVERITY:
        if keyword in lower:
            return sev
    return _DEFAULT_SEVERITY


def _load_discovered() -> dict:
    return read_json("discovered_assets.json")


def _config_issues(discovered: dict) -> list[tuple[str, str]]:
    """Return a deduplicated list of (issue_text, severity) tuples.

    Deduplication prevents multi-port scans from repeating the same
    header findings for every open port.
    """
    seen: set[str] = set()
    issues: list[tuple[str, str]] = []

    def _add(text: str) -> None:
        if text and text not in seen:
            seen.add(text)
            issues.append((text, _issue_severity(text)))

    for raw in discovered.get("ports") or []:
        port = raw.get("port")
        if raw.get("state") == "open" and port in {80, 443, 3000, 8000, 8080}:
            _add(f"Open TCP/{port} web service on the lab host.")

    http = discovered.get("http") or {}
    if http.get("reachable") and not http.get("uses_tls"):
        _add("Service is reachable over HTTP without TLS encryption.")
    for header in http.get("missing_security_headers") or []:
        _add(f"Missing security header: {header}")
    for cookie_issue in http.get("cookie_issues") or []:
        _add(cookie_issue)
    for cors_issue in http.get("cors_issues") or []:
        _add(cors_issue)
    for ver_issue in http.get("version_disclosure_issues") or []:
        _add(ver_issue)

    tls = discovered.get("tls") or {}
    if not tls.get("skipped") and tls.get("grade") in {"C", "D", "E", "F", "T"}:
        _add(f"Weak TLS grade from SSL Labs: {tls.get('grade')}")

    # Passive DNS issues (SPF / DMARC)
    passive_dns_issues = discovered.get("passive_meta", {}).get("dns", {}).get("issues") or []
    for dns_issue in passive_dns_issues:
        _add(f"DNS Email Security: {dns_issue}")

    # Passive CT subdomains summary note
    ct_subs = discovered.get("passive_meta", {}).get("ct_subdomains") or []
    if ct_subs:
        _add(
            f"Certificate Transparency Mapping: Found {len(ct_subs)} associated subdomains"
            " (informational only; not scanned)."
        )

    return issues


def correlate(discovered: dict | None = None) -> CorrelatedFindings:
    discovered = discovered or _load_discovered()
    target = discovered.get("target", "")
    # shared_issues_rich is [(text, severity), ...]
    shared_issues_rich = _config_issues(discovered)
    # schemas.CorrelatedAsset.config_issues still accepts plain strings
    shared_issues = [text for text, _ in shared_issues_rich]
    assets: list[CorrelatedAsset] = []
    seen_queries: dict[str, list[CveRecord]] = {}

    ports: list[dict] = discovered.get("ports") or []
    if not ports:
        assets.append(
            CorrelatedAsset(
                target=target,
                port=None,
                service="none",
                product="",
                version="",
                exposure="No open ports found on the scanned set.",
                cves=[],
                config_issues=shared_issues,
            )
        )
    for raw in ports:
        product = raw.get("product") or raw.get("service") or ""
        version = raw.get("version") or ""
        query_key = f"{product}|{version}"
        if query_key not in seen_queries:
            raw_cves = lookup_cves(product, version) if product and product != "unknown" else []
            seen_queries[query_key] = enrich_cves(raw_cves)
        cves = seen_queries[query_key]
        port = raw.get("port")
        exposure = (
            f"Open {raw.get('protocol', 'tcp')}/{port} "
            f"service={raw.get('service') or 'unknown'} "
            f"product={product or 'n/a'} version={version or 'n/a'}"
        )
        assets.append(
            CorrelatedAsset(
                target=target,
                port=port,
                service=raw.get("service") or "",
                product=product,
                version=version,
                exposure=exposure,
                cves=cves,
                config_issues=shared_issues if port in {80, 443, 3000, 8000, 8080} else [],
            )
        )

    if shared_issues and not any(a.config_issues for a in assets):
        assets.append(
            CorrelatedAsset(
                target=target,
                port=None,
                service="http-config",
                product="",
                version="",
                exposure="HTTP configuration checks",
                cves=[],
                config_issues=shared_issues,
            )
        )

    result = CorrelatedFindings(
        target=target,
        assets=assets,
        mode=discovered.get("mode", "active"),
        notes=list(discovered.get("notes") or []),
    )
    write_json("correlated_findings.json", result)
    return result
