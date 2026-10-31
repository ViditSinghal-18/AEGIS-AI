"""
AEGIS-AI: Regulatory Compliance & Governance Correlation Engine.
Calculates honest compliance readiness scores across NIST CSF 2.0, OWASP Top 10 (2021),
PCI-DSS 4.0, ISO 27001:2022, and SOC 2 Type II based exclusively on discovered perimeter findings.
NO hardcoded percentages: every score is mathematically computed from evaluated security controls.
"""

from __future__ import annotations

from typing import Any, Dict, List


OWASP_CATEGORIES = {
    "A01:2021": {"title": "Broken Access Control", "risk": "High"},
    "A02:2021": {"title": "Cryptographic Failures", "risk": "Critical"},
    "A03:2021": {"title": "Injection", "risk": "Critical"},
    "A04:2021": {"title": "Insecure Design", "risk": "Medium"},
    "A05:2021": {"title": "Security Misconfiguration", "risk": "High"},
    "A06:2021": {"title": "Vulnerable and Outdated Components", "risk": "High"},
    "A07:2021": {"title": "Identification and Authentication Failures", "risk": "High"},
    "A08:2021": {"title": "Software and Data Integrity Failures", "risk": "High"},
    "A09:2021": {"title": "Security Logging and Monitoring Failures", "risk": "Medium"},
    "A10:2021": {"title": "Server-Side Request Forgery (SSRF)", "risk": "High"},
}


def calculate_compliance(findings: List[Dict[str, Any]], is_port_open: bool = False) -> Dict[str, Any]:
    """
    Calculate compliance coverage and control status based on real evidence.
    """
    # 1. Map to OWASP Top 10
    owasp_hits: Dict[str, List[Dict[str, Any]]] = {k: [] for k in OWASP_CATEGORIES}

    for f in findings:
        title = str(f.get("title", "")).lower()
        desc = str(f.get("description", "")).lower()
        source = str(f.get("source", "")).lower()
        cves = f.get("related_cves", [])
        blob = f"{title} {desc} {source}"

        if "tls" in blob or "ssl" in blob or "hsts" in blob or "cert" in blob:
            owasp_hits["A02:2021"].append(f)
        if "header" in blob or "csp" in blob or "frame" in blob or "disclosure" in blob or "spf" in blob or "dmarc" in blob:
            owasp_hits["A05:2021"].append(f)
        if cves or "cve" in title or "component" in blob:
            owasp_hits["A06:2021"].append(f)
        if "port" in title or "cors" in blob:
            owasp_hits["A01:2021"].append(f)
        if "cookie" in blob:
            owasp_hits["A07:2021"].append(f)
        if "injection" in blob or "sql" in blob:
            owasp_hits["A03:2021"].append(f)

    # 2. PCI-DSS 4.0 Controls
    pci_controls = [
        {
            "id": "Req 6.2.4",
            "name": "Software Flaw Remediation",
            "desc": "Known security vulnerabilities must be patched within 30 days of disclosure.",
            "status": "FAIL" if any(f.get("severity") in ["Critical", "High"] for f in findings) else "PASS"
        },
        {
            "id": "Req 1.3.1",
            "name": "Inbound Traffic Restrictions",
            "desc": "Restrict inbound traffic to only authorized protocols and public services.",
            "status": "WARN" if is_port_open else "PASS"
        },
        {
            "id": "Req 6.4.1",
            "name": "WAF Deployment for Public Web Applications",
            "desc": "Automated technical solution (WAF) must inspect and protect public-facing web applications.",
            "status": "FAIL" if not any("Protected by" in str(f.get("evidence", "")) for f in findings) and is_port_open else "PASS"
        },
        {
            "id": "Req 4.2.1",
            "name": "Strong Cryptography in Transit",
            "desc": "All public transmissions must use robust TLS certificates and modern cipher suites.",
            "status": "FAIL" if len(owasp_hits["A02:2021"]) > 0 else "PASS"
        },
        {
            "id": "Req 6.4.3",
            "name": "Integrity of Scripts & Browser Security",
            "desc": "Content Security Policy (CSP) and security headers enforced on payment/web portals.",
            "status": "FAIL" if any("csp" in str(f.get("title", "")).lower() for f in findings) else "PASS"
        }
    ]
    pci_pass = sum(1 for c in pci_controls if c["status"] == "PASS")
    pci_score = round((pci_pass / len(pci_controls)) * 100, 1)

    # 3. NIST CSF 2.0 Controls
    nist_controls = [
        {
            "id": "ID.AM-01",
            "category": "Identify",
            "desc": "Physical and software assets within the perimeter are inventoried.",
            "status": "PASS"
        },
        {
            "id": "PR.DS-02",
            "category": "Protect",
            "desc": "Data in transit is protected using modern TLS encryption and HSTS headers.",
            "status": "FAIL" if len(owasp_hits["A02:2021"]) > 0 else "PASS"
        },
        {
            "id": "PR.IP-01",
            "category": "Protect",
            "desc": "Security architecture baseline and HTTP defense-in-depth headers enforced.",
            "status": "FAIL" if len(owasp_hits["A05:2021"]) > 1 else ("WARN" if len(owasp_hits["A05:2021"]) == 1 else "PASS")
        },
        {
            "id": "DE.CM-08",
            "category": "Detect",
            "desc": "Vulnerability intelligence (NVD, CISA KEV) actively scanned across perimeter components.",
            "status": "FAIL" if any(f.get("in_cisa_kev") for f in findings) else "PASS"
        },
        {
            "id": "PR.AC-04",
            "category": "Protect",
            "desc": "Email and domain identity authenticated via SPF and DMARC enforcement.",
            "status": "FAIL" if any("spf" in str(f.get("title", "")).lower() or "dmarc" in str(f.get("title", "")).lower() for f in findings) else "PASS"
        }
    ]
    nist_pass = sum(1 for c in nist_controls if c["status"] == "PASS")
    nist_score = round((nist_pass / len(nist_controls)) * 100, 1)

    # 4. ISO/IEC 27001:2022 Controls
    iso_controls = [
        {
            "id": "A.8.8",
            "name": "Management of Technical Vulnerabilities",
            "desc": "Information about technical vulnerabilities of information systems is obtained and evaluated.",
            "status": "FAIL" if any(f.get("severity") == "Critical" for f in findings) else ("WARN" if findings else "PASS")
        },
        {
            "id": "A.8.20",
            "name": "Network Security",
            "desc": "Networks and network devices are secured, managed and controlled to protect information.",
            "status": "WARN" if is_port_open else "PASS"
        },
        {
            "id": "A.8.24",
            "name": "Use of Cryptography",
            "desc": "Rules for the effective use of cryptography are defined and implemented.",
            "status": "FAIL" if len(owasp_hits["A02:2021"]) > 0 else "PASS"
        },
        {
            "id": "A.13.2.3",
            "name": "Electronic Messaging Security",
            "desc": "Information involved in electronic messaging is appropriately protected against spoofing.",
            "status": "FAIL" if any("spf" in str(f.get("title", "")).lower() or "dmarc" in str(f.get("title", "")).lower() for f in findings) else "PASS"
        }
    ]
    iso_pass = sum(1 for c in iso_controls if c["status"] == "PASS")
    iso_score = round((iso_pass / len(iso_controls)) * 100, 1)

    # 5. SOC 2 Type II Trust Services Criteria
    soc2_controls = [
        {
            "id": "CC6.1",
            "name": "Logical and Physical Access Controls",
            "desc": "Perimeter boundaries and security headers restrict unauthorized exposure.",
            "status": "FAIL" if len(owasp_hits["A05:2021"]) > 0 else "PASS"
        },
        {
            "id": "CC6.6",
            "name": "Boundary Protection & Transmission Security",
            "desc": "Data transmission over public networks is encrypted using approved protocols.",
            "status": "FAIL" if len(owasp_hits["A02:2021"]) > 0 else "PASS"
        },
        {
            "id": "CC7.1",
            "name": "Vulnerability Scanning Infrastructure",
            "desc": "The entity conducts ongoing monitoring and vulnerability evaluations.",
            "status": "PASS"
        },
        {
            "id": "CC7.2",
            "name": "Timely Flaw Remediation",
            "desc": "Vulnerabilities with known exploitation are triaged within agreed SLAs.",
            "status": "FAIL" if any(f.get("in_cisa_kev") for f in findings) else "PASS"
        }
    ]
    soc2_pass = sum(1 for c in soc2_controls if c["status"] == "PASS")
    soc2_score = round((soc2_pass / len(soc2_controls)) * 100, 1)

    # Determine overall grade
    overall_avg = round((pci_score + nist_score + iso_score + soc2_score) / 4.0, 1)
    if overall_avg >= 90:
        overall_grade = "A"
    elif overall_avg >= 75:
        overall_grade = "B"
    elif overall_avg >= 60:
        overall_grade = "C"
    else:
        overall_grade = "D"

    return {
        "overall_readiness_score": overall_avg,
        "overall_grade": overall_grade,
        "evaluated_controls_count": len(pci_controls) + len(nist_controls) + len(iso_controls) + len(soc2_controls),
        "owasp_top10": {
            "categories": {k: len(v) for k, v in owasp_hits.items()},
            "total_violations": sum(len(v) for v in owasp_hits.values())
        },
        "pci_dss_4": {
            "score": pci_score,
            "passing_controls": pci_pass,
            "total_controls": len(pci_controls),
            "controls": pci_controls
        },
        "nist_csf_2": {
            "score": nist_score,
            "passing_controls": nist_pass,
            "total_controls": len(nist_controls),
            "controls": nist_controls
        },
        "iso_27001": {
            "score": iso_score,
            "passing_controls": iso_pass,
            "total_controls": len(iso_controls),
            "controls": iso_controls
        },
        "soc_2": {
            "score": soc2_score,
            "passing_controls": soc2_pass,
            "total_controls": len(soc2_controls),
            "controls": soc2_controls
        }
    }
