"""
Email Transport Security & Anti-Spoofing Grader.

Inspired by:
    Durumeric, Z., et al. "Neither Snow Nor Rain Nor MITM... An Empirical Analysis
    of Email Delivery Security." In Proceedings of the 2015 Internet Measurement Conference (IMC), 2015.

Evaluates domain email hygiene across:
- SPF (Sender Policy Framework): hardfail (-all) vs softfail (~all) vs neutral/pass (?all/+all)
- DMARC (RFC 7489): reject vs quarantine vs none policies and aggregate reporting (rua)
- MTA-STS (RFC 8461): Mail Transfer Agent Strict Transport Security
- TLS-RPT (RFC 8460): SMTP TLS Reporting
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from discovery.safe_fetch import safe_fetch, SafeFetchError


@dataclass
class EmailSecurityResult:
    """Comprehensive email authentication and transport defense report."""

    domain: str
    grade: str  # "A+", "A", "B", "C", "D", "F"
    score: int  # 0 to 100
    spf_record: Optional[str] = None
    spf_qualifier: Optional[str] = None  # "-all", "~all", "?all", "+all"
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None   # "reject", "quarantine", "none", "missing"
    dmarc_percentage: int = 100
    mta_sts_enabled: bool = False
    mta_sts_mode: Optional[str] = None   # "enforce", "testing", "none"
    tls_rpt_enabled: bool = False
    weaknesses: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _query_txt_records(name: str) -> List[str]:
    """Query DNS TXT records using local nslookup tool."""
    txt_records: List[str] = []
    try:
        proc = subprocess.run(
            ["nslookup", "-type=TXT", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in proc.stdout.splitlines():
            line_s = line.strip()
            if "text =" in line_s:
                # Extract quoted or text string
                parts = line_s.split("text =", 1)
                clean_val = parts[1].strip().strip('"')
                txt_records.append(clean_val)
            elif line_s.startswith("v="):
                txt_records.append(line_s.strip('"'))
    except Exception:
        pass
    return txt_records


def parse_spf(spf_text: str) -> Tuple[Optional[str], List[str]]:
    """Parse SPF record and extract all mechanism qualifier."""
    qualifier = None
    issues = []
    tokens = spf_text.split()
    for tok in tokens:
        if tok.endswith("all"):
            qualifier = tok
            break

    if qualifier == "-all":
        pass  # Strict hardfail
    elif qualifier == "~all":
        issues.append("SPF uses '~all' (softfail): spoofed emails may still be accepted into recipient inboxes.")
    elif qualifier in ["?all", "+all"]:
        issues.append(f"SPF uses permissive '{qualifier}': allows any server to spoof emails from this domain.")
    else:
        issues.append("SPF record lacks an explicit 'all' termination mechanism.")

    return qualifier, issues


def parse_dmarc(dmarc_text: str) -> Tuple[Optional[str], int, bool, List[str]]:
    """Parse DMARC record and extract policy, percentage, and reporting."""
    policy = None
    pct = 100
    has_rua = False
    issues = []

    m_p = re.search(r"\bp=([a-zA-Z]+)", dmarc_text)
    if m_p:
        policy = m_p.group(1).lower()

    m_pct = re.search(r"\bpct=([0-9]+)", dmarc_text)
    if m_pct:
        try:
            pct = int(m_pct.group(1))
        except ValueError:
            pct = 100

    if "rua=" in dmarc_text:
        has_rua = True

    if policy == "reject":
        if pct < 100:
            issues.append(f"DMARC policy 'reject' is only enforced on {pct}% of messages.")
    elif policy == "quarantine":
        issues.append("DMARC policy is set to 'quarantine' rather than strict 'reject'.")
    elif policy == "none":
        issues.append("DMARC policy is set to 'none' (monitoring only; spoofed emails are not blocked).")
    else:
        issues.append("DMARC record lacks a valid 'p=' policy tag.")

    if not has_rua:
        issues.append("DMARC lacks 'rua=' aggregate reporting: administrators cannot monitor authentication failures.")

    return policy, pct, has_rua, issues


def grade_email_security(
    domain: str,
    spf_override: Optional[str] = None,
    dmarc_override: Optional[str] = None,
    mta_sts_override: Optional[str] = None,
    tls_rpt_override: Optional[bool] = None,
) -> EmailSecurityResult:
    """Evaluate full email defense posture and assign an evidence-grounded grade (0-100 / A-F).

    Inspired by Durumeric et al. 2015.
    """
    clean_domain = domain.strip().lower()
    score = 0
    weaknesses: List[str] = []
    strengths: List[str] = []
    recommendations: List[str] = []

    # 1. SPF Record Evaluation
    spf_record = spf_override
    if spf_record is None:
        txts = _query_txt_records(clean_domain)
        for t in txts:
            if t.startswith("v=spf1"):
                spf_record = t
                break

    spf_qualifier = None
    if spf_record:
        spf_qualifier, spf_issues = parse_spf(spf_record)
        if spf_qualifier == "-all":
            score += 30
            strengths.append(f"Strict SPF hardfail configured ({spf_record}).")
        elif spf_qualifier == "~all":
            score += 20
            strengths.append(f"SPF softfail configured ({spf_record}).")
            weaknesses.extend(spf_issues)
            recommendations.append("Upgrade SPF policy from '~all' to '-all' to enforce strict rejection of unauthorized senders.")
        else:
            score += 5
            weaknesses.extend(spf_issues)
            recommendations.append("Replace permissive SPF qualifier with '-all'.")
    else:
        weaknesses.append("Missing SPF (Sender Policy Framework) record: domain is vulnerable to direct address spoofing.")
        recommendations.append(f"Add DNS TXT record for {clean_domain}: 'v=spf1 mx -all'")

    # 2. DMARC Record Evaluation
    dmarc_record = dmarc_override
    if dmarc_record is None:
        dmarc_txts = _query_txt_records(f"_dmarc.{clean_domain}")
        for t in dmarc_txts:
            if "v=DMARC1" in t:
                dmarc_record = t
                break

    dmarc_policy = None
    dmarc_pct = 100
    if dmarc_record:
        dmarc_policy, dmarc_pct, has_rua, dmarc_issues = parse_dmarc(dmarc_record)
        if dmarc_policy == "reject":
            score += 40
            strengths.append(f"Enforcing DMARC 'reject' policy ({dmarc_record}).")
        elif dmarc_policy == "quarantine":
            score += 25
            strengths.append("DMARC 'quarantine' policy active.")
            weaknesses.extend(dmarc_issues)
            recommendations.append("Transition DMARC policy from 'quarantine' to 'reject' for maximum anti-phishing protection.")
        elif dmarc_policy == "none":
            score += 10
            weaknesses.extend(dmarc_issues)
            recommendations.append("Upgrade DMARC policy from 'none' (monitoring) to 'quarantine' or 'reject'.")
        else:
            score += 5
            weaknesses.extend(dmarc_issues)

        if has_rua:
            score += 5
            strengths.append("DMARC aggregate reporting (rua) enabled.")
    else:
        weaknesses.append("Missing DMARC record: recipient mail servers have no instructions on how to handle spoofed messages.")
        recommendations.append(f"Add DNS TXT record for _dmarc.{clean_domain}: 'v=DMARC1; p=reject; rua=mailto:dmarc@{clean_domain};'")

    # 3. MTA-STS Evaluation (RFC 8461)
    mta_sts_mode = None
    if mta_sts_override:
        if "mode: enforce" in mta_sts_override or mta_sts_override.lower() == "enforce":
            mta_sts_mode = "enforce"
        elif "mode: testing" in mta_sts_override or mta_sts_override.lower() == "testing":
            mta_sts_mode = "testing"
        else:
            mta_sts_mode = mta_sts_override
    else:
        mta_txts = _query_txt_records(f"_mta-sts.{clean_domain}")
        for t in mta_txts:
            if "v=STSv1" in t:
                mta_sts_mode = "enforce" if "mode: enforce" in t else "testing"
                break
        if mta_sts_mode is None:
            # Check HTTPS well-known endpoint
            try:
                mta_url = f"https://mta-sts.{clean_domain}/.well-known/mta-sts.txt"
                resp = safe_fetch(mta_url, timeout=3.0)
                if resp.status_code == 200 and "version: STSv1" in resp.text:
                    if "mode: enforce" in resp.text:
                        mta_sts_mode = "enforce"
                    elif "mode: testing" in resp.text:
                        mta_sts_mode = "testing"
            except Exception:
                pass

    if mta_sts_mode == "enforce":
        score += 15
        strengths.append("MTA-STS enforced: protects SMTP transport from man-in-the-middle TLS downgrade attacks.")
    elif mta_sts_mode == "testing":
        score += 8
        strengths.append("MTA-STS configured in testing mode.")
    else:
        weaknesses.append("MTA-STS not enabled: inbound SMTP connections risk cleartext TLS downgrade via STARTTLS stripping.")
        recommendations.append(f"Deploy MTA-STS policy at https://mta-sts.{clean_domain}/.well-known/mta-sts.txt with mode 'enforce'.")

    # 4. TLS-RPT Evaluation (RFC 8460)
    tls_rpt_enabled = tls_rpt_override
    if tls_rpt_enabled is None:
        rpt_txts = _query_txt_records(f"_smtp._tls.{clean_domain}")
        tls_rpt_enabled = any("v=TLSRPTv1" in t for t in rpt_txts)

    if tls_rpt_enabled:
        score += 10
        strengths.append("SMTP TLS Reporting (TLS-RPT) active.")
    else:
        recommendations.append(f"Add DNS TXT record for _smtp._tls.{clean_domain}: 'v=TLSRPTv1; rua=mailto:tls-rpt@{clean_domain};'")

    # Calculate final grade
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A+" if score >= 95 else "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return EmailSecurityResult(
        domain=clean_domain,
        grade=grade,
        score=score,
        spf_record=spf_record,
        spf_qualifier=spf_qualifier,
        dmarc_record=dmarc_record,
        dmarc_policy=dmarc_policy or "missing",
        dmarc_percentage=dmarc_pct,
        mta_sts_enabled=(mta_sts_mode in ["enforce", "testing"]),
        mta_sts_mode=mta_sts_mode or "none",
        tls_rpt_enabled=tls_rpt_enabled,
        weaknesses=weaknesses,
        strengths=strengths,
        recommendations=recommendations,
    )
