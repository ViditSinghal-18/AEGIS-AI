"""
AEGIS-AI: Multi-Source Perimeter Vulnerability Correlation Engine.
Correlates real discovery evidence (passive OSINT and active port/banner scans)
with the National Vulnerability Database (NVD API 2.0) and Google OSV.
STRICT HONESTY RULES:
- Never assumes Node.js/Express when headers are missing.
- Extracts real web servers (Nginx, Apache, Caddy, Cloudflare, IIS) from Server banners.
- Audits missing security headers, cookie flags, TLS certificates, and DNS authentication records.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from correlation.nvd_lookup import query_nvd_by_cve, query_osv_package
from ast_analyzer import analyze_source_tree, evaluate_component_reachability


def extract_components_from_discovery(discovery_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Extract components and versions honestly from HTTP banners, Server headers,
    and open port service banners. Does NOT fabricate fallback packages.
    """
    components = []
    http_data = discovery_data.get("http", discovery_data.get("http_fingerprint", {}))
    server_banner = http_data.get("server_banner") or http_data.get("server", "")
    powered_by = http_data.get("powered_by") or http_data.get("x_powered_by", "")

    # Parse Server banner: e.g. "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)"
    if server_banner:
        match = re.search(r"([A-Za-z\-]+)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", server_banner)
        if match:
            components.append({
                "name": match.group(1).lower(),
                "version": match.group(2),
                "ecosystem": "generic",
                "source": f"HTTP Server header: '{server_banner}'"
            })
        else:
            components.append({
                "name": server_banner.split()[0].lower(),
                "version": "unknown",
                "ecosystem": "generic",
                "source": f"HTTP Server header: '{server_banner}'"
            })

    # Parse X-Powered-By
    if powered_by:
        match = re.search(r"([A-Za-z\-]+)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", powered_by)
        if match:
            components.append({
                "name": match.group(1).lower(),
                "version": match.group(2),
                "ecosystem": "npm" if "express" in powered_by.lower() else "generic",
                "source": f"HTTP X-Powered-By header: '{powered_by}'"
            })
        else:
            components.append({
                "name": powered_by.strip().lower(),
                "version": "unknown",
                "ecosystem": "npm" if "express" in powered_by.lower() else "generic",
                "source": f"HTTP X-Powered-By header: '{powered_by}'"
            })

    # Parse service banners from discovered assets
    for asset in discovery_data.get("discovered_assets", []):
        product = asset.get("product", "")
        version = asset.get("version", "")
        if product:
            components.append({
                "name": product.lower(),
                "version": version or "unknown",
                "ecosystem": "generic",
                "source": f"Active banner on port {asset.get('port')}"
            })

    # Deduplicate by name
    dedup = {}
    for c in components:
        dedup[c["name"]] = c
    return list(dedup.values())


def correlate_findings(
    discovery_data: Dict[str, Any],
    source_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Correlates discovery telemetry into a unified list of actionable security findings.
    """
    findings: List[Dict[str, Any]] = []

    # 1. Security Headers Audit
    http_data = discovery_data.get("http", discovery_data.get("http_fingerprint", {}))
    missing_headers = http_data.get("missing_security_headers", [])
    for mh in missing_headers:
        hdr_name = mh.get("header") if isinstance(mh, dict) else str(mh)
        hdr_desc = mh.get("description") if isinstance(mh, dict) else f"Missing HTTP defense-in-depth header {hdr_name}"
        
        # Determine severity and CVSS
        if hdr_name in ["content-security-policy", "strict-transport-security"]:
            sev = "Medium"
            cvss = 5.3
        elif hdr_name in ["x-frame-options", "x-content-type-options"]:
            sev = "Low"
            cvss = 4.3
        else:
            sev = "Low"
            cvss = 3.1

        findings.append({
            "title": f"Missing Security Header: {hdr_name.upper()}",
            "source": "passive_headers",
            "severity": sev,
            "cvss_score": cvss,
            "related_cves": [],
            "description": hdr_desc,
            "evidence": f"HTTP response from {discovery_data.get('target', 'host')} omitted '{hdr_name}' header.",
            "remediation": f"Configure web server or reverse proxy to inject '{hdr_name}' header.",
            "exposure_context": "HTTP Perimeter"
        })

    # 2. Cookie Security Audit
    cookie_issues = http_data.get("cookie_issues", [])
    for ci in cookie_issues:
        findings.append({
            "title": "Insecure Cookie Flag Configuration",
            "source": "passive_cookies",
            "severity": "Medium",
            "cvss_score": 5.0,
            "related_cves": [],
            "description": ci,
            "evidence": f"Set-Cookie attribute inspection: {ci}",
            "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all session cookies.",
            "exposure_context": "HTTP Session Handling"
        })

    # 3. CORS Wildcard Exposure
    for cors in http_data.get("cors_issues", []):
        findings.append({
            "title": "Permissive Wildcard Cross-Origin Resource Sharing (CORS)",
            "source": "passive_cors",
            "severity": "Medium",
            "cvss_score": 6.5,
            "related_cves": [],
            "description": cors,
            "evidence": "Access-Control-Allow-Origin: *",
            "remediation": "Restrict Access-Control-Allow-Origin to trusted domains and disallow credentials.",
            "exposure_context": "Public API Perimeter"
        })

    # 4. Information Disclosure in Headers
    for vd in http_data.get("version_disclosure", []):
        findings.append({
            "title": "Software Version Disclosure in HTTP Header",
            "source": "passive_headers",
            "severity": "Low",
            "cvss_score": 3.0,
            "related_cves": [],
            "description": vd,
            "evidence": vd,
            "remediation": "Suppress server banners using 'server_tokens off' in Nginx or ServerTokens Prod in Apache.",
            "exposure_context": "Perimeter Fingerprinting"
        })

    # 5. TLS Certificate Audit
    tls_data = discovery_data.get("tls", discovery_data.get("tls_data", {}))
    for issue in tls_data.get("issues", []):
        is_crit = "expired" in issue.lower() or "self-signed" in issue.lower()
        findings.append({
            "title": "TLS Certificate Security Gap",
            "source": "passive_tls",
            "severity": "Critical" if is_crit else "High",
            "cvss_score": 8.1 if is_crit else 6.5,
            "related_cves": [],
            "description": issue,
            "evidence": f"TLS Inspection on port 443: {issue}",
            "remediation": "Renew public certificate with a trusted Certificate Authority (e.g. Let's Encrypt).",
            "exposure_context": "TLS Cryptographic Perimeter"
        })

    # 6. DNS Security Audit (SPF / DMARC)
    dns_data = discovery_data.get("dns", {})
    for issue in dns_data.get("issues", []):
        findings.append({
            "title": "Missing DNS Email Authentication Record",
            "source": "dns_audit",
            "severity": "Medium",
            "cvss_score": 5.4,
            "related_cves": [],
            "description": issue,
            "evidence": issue,
            "remediation": "Publish valid SPF TXT record and DMARC policy at _dmarc.<domain>.",
            "exposure_context": "DNS Domain Authentication"
        })

    # 7. Discovered Components Vulnerability Lookup (NVD & OSV)
    components = extract_components_from_discovery(discovery_data)

    # If source path is provided, add manifest dependencies
    source_analysis = analyze_source_tree(source_path) if source_path else None
    if source_analysis and source_analysis.get("source_provided"):
        for pkg in source_analysis.get("declared_packages", []):
            components.append({
                "name": pkg,
                "version": "manifest",
                "ecosystem": "npm" if "package.json" in str(source_path) else "pypi",
                "source": "Source Code Manifest"
            })

    for comp in components:
        c_name = comp["name"]
        ecosystem = comp.get("ecosystem", "generic")
        # Query OSV
        vulns = query_osv_package(c_name, ecosystem=ecosystem if ecosystem in ["npm", "pypi"] else "npm")
        for v in vulns[:5]:  # Top 5 per package
            cve_aliases = v.get("cve_aliases", [])
            findings.append({
                "title": f"Vulnerability in {c_name}: {v.get('vuln_id')}",
                "source": "cve_correlation",
                "severity": v.get("severity", "Medium"),
                "cvss_score": v.get("cvss_score", 5.0),
                "related_cves": cve_aliases,
                "description": v.get("summary", ""),
                "evidence": f"Component '{c_name}' detected via {comp.get('source')}. Advisory {v.get('vuln_id')}.",
                "remediation": f"Upgrade '{c_name}' to the latest patched release.",
                "affected_component": c_name,
                "exposure_context": f"Component Dependency ({c_name})"
            })

    # 8. Active Port Scan Findings
    for asset in discovery_data.get("discovered_assets", []):
        port = asset.get("port")
        service = asset.get("service", "unknown")
        # Flag risky administrative or plaintext services
        if port in [21, 23, 3389, 5432, 3306]:
            findings.append({
                "title": f"Sensitive Service Directly Exposed on Port {port} ({service})",
                "source": "active_port_scan",
                "severity": "High",
                "cvss_score": 7.5,
                "related_cves": [],
                "description": f"Internal database or management service ({service}) exposed to public network on port {port}.",
                "evidence": f"Port {port}/TCP open, service: {service}.",
                "remediation": "Restrict access via firewall rules or place behind VPN / IP allowlist.",
                "exposure_context": f"Public Ingress Port {port}"
            })

    return findings
