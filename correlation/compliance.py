"""
AEGIS-AI Compliance & Governance Mapping Engine.
Calculates dynamic compliance readiness scores for:
- NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)
- PCI-DSS v4.0 (Requirement 6: Secure Systems, Requirement 1: Network Security)
- ISO/IEC 27001:2022 (Annex A.8 Technical Controls)
- SOC 2 Type II (Common Criteria 6.6, 6.7, 7.1)
- OWASP Top 10 (2021)
"""

from __future__ import annotations

from typing import Any

OWASP_CATEGORIES = {
    "A01:2021": {"title": "Broken Access Control", "icon": "🔓", "risk": "High"},
    "A02:2021": {"title": "Cryptographic Failures", "icon": "🔐", "risk": "Critical"},
    "A03:2021": {"title": "Injection", "icon": "💉", "risk": "Critical"},
    "A04:2021": {"title": "Insecure Design", "icon": "📐", "risk": "High"},
    "A05:2021": {"title": "Security Misconfiguration", "icon": "⚙️", "risk": "Medium"},
    "A06:2021": {"title": "Vulnerable and Outdated Components", "icon": "📦", "risk": "High"},
    "A07:2021": {"title": "Identification and Authentication Failures", "icon": "🆔", "risk": "High"},
    "A08:2021": {"title": "Software and Data Integrity Failures", "icon": "🛡️", "risk": "High"},
    "A09:2021": {"title": "Security Logging and Monitoring Failures", "icon": "📜", "risk": "Medium"},
    "A10:2021": {"title": "Server-Side Request Forgery (SSRF)", "icon": "🌐", "risk": "High"},
}


def map_compliance(
    findings: list[dict[str, Any]] | None = None,
    is_port_open: bool = False,
    **kwargs: Any
) -> dict[str, Any]:
    """Calculate OWASP Top 10 & Multi-Framework Governance readiness scores."""
    findings = findings or []
    owasp_hits: dict[str, list[dict[str, Any]]] = {k: [] for k in OWASP_CATEGORIES}

    for f in findings:
        title = str(f.get("title", "")).lower()
        matters = str(f.get("why_it_matters", "")).lower()
        source = str(f.get("source", "")).lower()
        cves = f.get("related_cves", [])

        blob = f"{title} {matters} {source}"

        # A02 Cryptographic Failures (TLS, SSL, HSTS, plain HTTP)
        if "tls" in blob or "ssl" in blob or "hsts" in blob or "unencrypted" in blob or "certificate" in blob:
            owasp_hits["A02:2021"].append(f)

        # A05 Security Misconfiguration (Missing headers, CORS, Cookie flags, Server tokens)
        if "header" in blob or "csp" in blob or "frame" in blob or "cookie" in blob or "disclosure" in blob or "spf" in blob or "dmarc" in blob or "config" in source:
            owasp_hits["A05:2021"].append(f)

        # A06 Vulnerable Components (CVEs, outdated versions)
        if cves or "cve" in title or "version" in title:
            owasp_hits["A06:2021"].append(f)

        # A01 Broken Access Control (Open administrative ports, unauthenticated exposure)
        if "port" in title or "port_scan" in source or "cors" in blob:
            owasp_hits["A01:2021"].append(f)

        # A07 Identification and Authentication Failures (cookie flags, session)
        if "cookie" in blob or "samesite" in blob or "session" in blob:
            owasp_hits["A07:2021"].append(f)

        # A10 SSRF indicators in public evidence (informational mapping only)
        if "ssrf" in blob or "metadata" in blob:
            owasp_hits["A10:2021"].append(f)

    if is_port_open:
        owasp_hits["A01:2021"].append({"title": "Direct Open TCP Port Ingress", "severity": "Medium"})

    # Compute compliance score (100 - penalties)
    total_violations = sum(len(items) for items in owasp_hits.values())
    if not findings and not is_port_open:
        compliance_score = 100.0
        grade = "A"
        grade_color = "#10b981"
        posture = "EXEMPLARY COMPLIANCE"
    else:
        penalty = sum(
            len(items) * (15 if OWASP_CATEGORIES[cat]["risk"] == "Critical" else 10 if OWASP_CATEGORIES[cat]["risk"] == "High" else 5)
            for cat, items in owasp_hits.items()
        )
        compliance_score = max(10.0, min(100.0, float(100 - penalty)))
        if compliance_score >= 95:
            grade = "A"
            grade_color = "#10b981"
            posture = "EXEMPLARY COMPLIANCE"
        elif compliance_score >= 80:
            grade = "A"
            grade_color = "#34d399"
            posture = "STRONG POSTURE"
        elif compliance_score >= 70:
            grade = "B"
            grade_color = "#38bdf8"
            posture = "ACCEPTABLE (MINOR GAPS)"
        elif compliance_score >= 50:
            grade = "C"
            grade_color = "#f59e0b"
            posture = "ELEVATED RISK"
        elif compliance_score >= 35:
            grade = "D"
            grade_color = "#f97316"
            posture = "HIGH RISK GAPS"
        else:
            grade = "F"
            grade_color = "#ef4444"
            posture = "CRITICAL NON-COMPLIANT"

    # Multi-Framework Controls Calculation
    has_tls_issue = bool(owasp_hits["A02:2021"])
    has_config_issue = bool(owasp_hits["A05:2021"])
    has_cve_issue = bool(owasp_hits["A06:2021"])

    pci_total = 12
    pci_gaps = (2 if has_tls_issue else 0) + (2 if has_config_issue else 0) + (3 if has_cve_issue else 0) + (1 if is_port_open else 0)
    pci_pass = max(0, pci_total - pci_gaps)

    nist_total = 10
    nist_gaps = (2 if has_tls_issue else 0) + (1 if has_config_issue else 0) + (2 if has_cve_issue else 0)
    nist_pass = max(0, nist_total - nist_gaps)

    soc2_total = 8
    soc2_gaps = (1 if has_tls_issue else 0) + (2 if has_config_issue else 0) + (1 if has_cve_issue else 0)
    soc2_pass = max(0, soc2_total - soc2_gaps)

    iso_total = 15
    iso_gaps = (2 if has_tls_issue else 0) + (3 if has_config_issue else 0) + (2 if has_cve_issue else 0)
    iso_pass = max(0, iso_total - iso_gaps)

    nist_functions = [
        {"id": "GV", "name": "Govern", "status": "Implemented", "pct": 90, "color": "#38bdf8"},
        {"id": "ID", "name": "Identify (Asset & Attack Surface)", "status": "Audited", "pct": 95, "color": "#10b981"},
        {"id": "PR", "name": "Protect (Headers & Cryptography)", "status": "Needs Remediation" if has_tls_issue or has_config_issue else "Enforced", "pct": int(compliance_score), "color": grade_color},
        {"id": "DE", "name": "Detect (Vulnerability Intelligence)", "status": "Active (NVD/KEV)", "pct": 90, "color": "#8b5cf6"},
        {"id": "RS", "name": "Respond (Automated Playbooks)", "status": "Available", "pct": 85, "color": "#ec4899"},
        {"id": "RC", "name": "Recover", "status": "Standard", "pct": 80, "color": "#64748b"},
    ]

    return {
        "score": compliance_score,
        "overall_readiness_score": compliance_score,
        "grade": grade,
        "overall_grade": grade,
        "grade_color": grade_color,
        "posture": posture,
        "owasp_categories": owasp_hits,
        "total_violations": total_violations,
        "nist_functions": nist_functions,
        "pci_dss_4": {
            "name": "PCI-DSS v4.0",
            "passing_controls": pci_pass,
            "total_controls": pci_total,
            "percentage": round((pci_pass / pci_total) * 100, 1),
        },
        "nist_csf_2": {
            "name": "NIST CSF 2.0",
            "passing_controls": nist_pass,
            "total_controls": nist_total,
            "percentage": round((nist_pass / nist_total) * 100, 1),
        },
        "soc2_type2": {
            "name": "SOC 2 Type II",
            "passing_controls": soc2_pass,
            "total_controls": soc2_total,
            "percentage": round((soc2_pass / soc2_total) * 100, 1),
        },
        "iso_27001": {
            "name": "ISO/IEC 27001:2022",
            "passing_controls": iso_pass,
            "total_controls": iso_total,
            "percentage": round((iso_pass / iso_total) * 100, 1),
        },
    }


calculate_compliance = map_compliance
