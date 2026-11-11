"""
Empirical Breach Propensity & External Posture Index.

Inspired by:
    Liu, Y., et al. "Cloudy with a Chance of Breach: Forecasting Cyber Security Incidents."
    In Proceedings of the 24th USENIX Security Symposium, 2015.

Aggregates observable perimeter hygiene indicators into a calibrated external
posture score (0 - 100) and breach propensity tier (Low to Critical):
1. Email hygiene (SPF, DMARC, MTA-STS, TLS-RPT)
2. Content Security Policy defense grade
3. TLS certificate validity, expiration, and cipher posture
4. Exposed secrets, VCS directories (/.git/HEAD), and sensitive .env files
5. Verified dangling DNS / subdomain takeover vulnerabilities
6. Open administrative & database perimeter attack surface
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BreachPropensityReport:
    """Consolidated external cybersecurity posture & incident propensity assessment."""

    target: str
    overall_score: float  # 0.0 to 100.0
    posture_grade: str    # "A+", "A", "B", "C", "D", "F"
    propensity_tier: str  # "Low", "Moderate", "Elevated", "High", "Critical"
    component_scores: Dict[str, float] = field(default_factory=dict)
    key_deficiencies: List[str] = field(default_factory=list)
    positive_controls: List[str] = field(default_factory=list)
    methodology: str = "Empirical multi-factor perimeter hygiene index (inspired by Liu et al. 2015)"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def calculate_breach_propensity(
    target: str,
    email_score: float = 70.0,
    csp_score: float = 50.0,
    tls_valid: bool = True,
    tls_days_left: Optional[int] = 90,
    exposed_secrets_count: int = 0,
    dangling_takeovers_count: int = 0,
    open_ports: Optional[List[int]] = None,
    missing_headers_count: int = 2,
) -> BreachPropensityReport:
    """Calculate external breach propensity and overall security posture score.

    Inspired by Liu et al. 2015.
    """
    ports = open_ports or []
    deficiencies: List[str] = []
    positives: List[str] = []

    # 1. Email Security Dimension (Weight: 20%)
    email_dim = max(0.0, min(100.0, float(email_score)))
    if email_dim >= 80:
        positives.append(f"Strong email defense posture ({email_dim:.0f}/100) with active anti-spoofing enforcement.")
    else:
        deficiencies.append(f"Suboptimal email hygiene ({email_dim:.0f}/100): risks domain impersonation in spearphishing.")

    # 2. CSP Dimension (Weight: 15%)
    csp_dim = max(0.0, min(100.0, float(csp_score)))
    if csp_dim >= 80:
        positives.append(f"Hardened Content Security Policy ({csp_dim:.0f}/100) restricting XSS execution.")
    elif csp_dim == 0:
        deficiencies.append("Missing Content-Security-Policy (0/100): browser lacks defense-in-depth against client script injection.")
    else:
        deficiencies.append(f"Permissive CSP ({csp_dim:.0f}/100) containing bypassable directives.")

    # 3. TLS Hygiene Dimension (Weight: 20%)
    tls_dim = 100.0
    if not tls_valid:
        tls_dim = 20.0
        deficiencies.append("Invalid or untrusted TLS certificate: triggers browser security warnings.")
    elif tls_days_left is not None and tls_days_left < 15:
        tls_dim = 50.0
        deficiencies.append(f"TLS certificate nearing expiration ({tls_days_left} days remaining).")
    else:
        positives.append("Public TLS certificate is valid with sufficient operational validity.")

    # 4. Perimeter Port Exposure Dimension (Weight: 15%)
    # Penalize risky database and administrative ports (SSH, RDP, MySQL, Postgres, Redis, MongoDB, Docker)
    risky_ports = {22, 23, 3389, 3306, 5432, 6379, 27017, 2375, 9200}
    exposed_risky = [p for p in ports if p in risky_ports]
    if exposed_risky:
        port_dim = max(20.0, 100.0 - (len(exposed_risky) * 30.0))
        deficiencies.append(f"Sensitive administrative/database ports exposed to public Internet: {exposed_risky}.")
    else:
        port_dim = 95.0 if len(ports) <= 3 else max(60.0, 100.0 - len(ports) * 5.0)
        positives.append("No sensitive administrative or database ports exposed directly to public WAN.")

    # 5. HTTP Header Hygiene (Weight: 10%)
    header_dim = max(20.0, 100.0 - (missing_headers_count * 15.0))
    if missing_headers_count > 0:
        deficiencies.append(f"Missing {missing_headers_count} standard defensive HTTP security headers.")

    # Base Weighted Hygiene Score (before critical security penalties)
    base_score = (
        (email_dim * 0.20)
        + (csp_dim * 0.15)
        + (tls_dim * 0.20)
        + (port_dim * 0.15)
        + (header_dim * 0.10)
        + (20.0)  # Baseline operational credit
    )

    # 6. Critical Security Penalties (Exposed Secrets & Dangling Subdomain Takeovers)
    penalties = 0.0
    if exposed_secrets_count > 0:
        penalties += min(50.0, exposed_secrets_count * 30.0)
        deficiencies.append(f"CRITICAL: Found {exposed_secrets_count} exposed credentials or sensitive VCS/environment files.")

    if dangling_takeovers_count > 0:
        penalties += min(50.0, dangling_takeovers_count * 35.0)
        deficiencies.append(f"CRITICAL: Verified {dangling_takeovers_count} dangling DNS CNAME records vulnerable to subdomain takeover.")

    overall = max(0.0, min(100.0, base_score - penalties))
    overall = round(overall, 1)

    # Letter Grade & Propensity Tier Assignment
    if overall >= 90.0:
        grade = "A+" if overall >= 95.0 else "A"
        tier = "Low"
    elif overall >= 75.0:
        grade = "B"
        tier = "Moderate"
    elif overall >= 55.0:
        grade = "C"
        tier = "Elevated"
    elif overall >= 35.0:
        grade = "D"
        tier = "High"
    else:
        grade = "F"
        tier = "Critical"

    return BreachPropensityReport(
        target=target,
        overall_score=overall,
        posture_grade=grade,
        propensity_tier=tier,
        component_scores={
            "email_security": round(email_dim, 1),
            "csp_quality": round(csp_dim, 1),
            "tls_hygiene": round(tls_dim, 1),
            "network_exposure": round(port_dim, 1),
            "header_hygiene": round(header_dim, 1),
            "penalties_applied": round(penalties, 1),
        },
        key_deficiencies=deficiencies,
        positive_controls=positives,
    )
