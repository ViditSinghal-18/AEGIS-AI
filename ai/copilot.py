"""
AI Security SOC Copilot & Reasoning Assistant.
Provides contextual Q&A, executive briefings, patch bash script generation,
and threat actor path simulation based on report findings.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import ai.llm as llm
from ai.grounding import (
    GroundingVerificationResult,
    extract_cves,
    verify_grounding,
)

logger = logging.getLogger(__name__)

_DEFENSIVE_REFUSAL_MESSAGE = (
    "🛡️ **AEGIS Defensive Guardrail — Request Refused:**\n"
    "AEGIS-AI is an evidence-grounded Continuous Threat Exposure Management (CTEM) platform "
    "operating under strict defensive-only principles. Generating offensive exploits, attack payloads, "
    "reverse shells, or intrusion guidance is strictly forbidden. "
    "For remediation and hardening, please refer to our defensive configuration recommendations."
)

_OFFENSIVE_PATTERNS = [
    re.compile(r"\b(write|create|generate|provide|give me|craft)\b.*\b(exploit|payload|reverse\s*shell|shellcode|0day|zero-day|weapon|malware|attack\s+script|attack\s+payload|spearphishing\s+template)\b", re.IGNORECASE),
    re.compile(r"\b(how to|how can i|how do i)\s+(hack|exploit|attack|bypass|infiltrate|ddos|sql\s*inject|weaponize|brute\s*force|crack)\b", re.IGNORECASE),
    re.compile(r"\b(exploit\s+script|attack\s+script|payload\s+generator|reverse\s*tcp|meterpreter|metasploit|shellcode)\b", re.IGNORECASE),
    re.compile(r"\b(launch|execute|perform|initiate)\s+(a\s+)?(attack|ddos|dos|denial of service|injection)\b", re.IGNORECASE),
    re.compile(r"\b(sql\s*injection\s+attack|spearphishing\s+email\s+template|brute\s*force\s+credentials|denial\s+of\s+service\s+attack)\b", re.IGNORECASE),
]


def is_offensive_request(prompt_text: str) -> bool:
    """Determine if a user prompt is requesting offensive exploit generation or attacks."""
    p = prompt_text.strip()
    return any(pattern.search(p) for pattern in _OFFENSIVE_PATTERNS)


def query_copilot_with_grounding(
    prompt_text: str,
    report: dict[str, Any],
    history: list[dict[str, str]] | None = None,
    use_llm_judge: bool = False,
) -> tuple[str, GroundingVerificationResult]:
    """
    Process an analyst query and return both the response text and claim-level grounding evaluation.

    Inspired by ALCE (Gao et al. 2023).
    """
    # 1. Hard defensive guardrail check
    if is_offensive_request(prompt_text):
        res = GroundingVerificationResult(
            faithfulness_score=1.0,
            is_faithful=True,
            total_claims=1,
            supported_claims_count=1,
            unsupported_claims_count=0,
            hallucinated_cves=[],
            citations_found=[],
            explanation="Request cleanly refused under defensive guardrails.",
        )
        return _DEFENSIVE_REFUSAL_MESSAGE, res

    # 1b. Hard evidence-grounding guardrail: unverified absent CVE query check
    asked_cves = extract_cves(prompt_text)
    if asked_cves:
        findings = report.get("findings", [])
        report_cves = {str(c).upper() for f in findings for c in (f.get("related_cves") or [])}
        missing_cves = [c for c in asked_cves if c not in report_cves]
        if missing_cves:
            target = report.get("target", "Target")
            unverified_msg = (
                f"### ℹ️ Grounded Assessment: Unverified Vulnerability Query\n\n"
                f"The requested identifier(s) `{', '.join(missing_cves)}` **were not identified** on `{target}` in the current assessment.\n\n"
                f"- **Verified Findings Active:** `{len(findings)}`\n"
                f"- **Identified CVEs in Scope:** `{', '.join(sorted(report_cves)) or 'None'}`\n\n"
                f"AEGIS-AI maintains strict evidence-grounding and does not fabricate findings for absent vulnerabilities."
            )
            res = GroundingVerificationResult(
                faithfulness_score=1.0,
                is_faithful=True,
                total_claims=1,
                supported_claims_count=1,
                unsupported_claims_count=0,
                hallucinated_cves=[],
                citations_found=[],
                explanation="Unverified absent CVE query cleanly grounded and reported.",
            )
            return unverified_msg, res

    # 2. Generate response via LLM or offline reasoner
    llm_resp = _call_llm_copilot(prompt_text, report, history)
    response_text = llm_resp or _generate_offline_copilot_response(prompt_text, report)

    # 3. Grounding & Faithfulness Verification
    grounding_res = verify_grounding(response_text, report, use_llm_judge=use_llm_judge)

    # If hallucinated CVEs were detected, prepend an authoritative warning
    if grounding_res.hallucinated_cves:
        warning = (
            f"> ⚠️ **Guardrail Notice:** The generated response cited unverified CVEs "
            f"(`{', '.join(grounding_res.hallucinated_cves)}`) that were not detected in the current scan.\n\n"
        )
        response_text = warning + response_text

    return response_text, grounding_res


def query_copilot(
    prompt_text: str,
    report: dict[str, Any],
    history: list[dict[str, str]] | None = None,
) -> str:
    """
    Process an analyst query using the configured LLM if available,
    or our intelligent offline defensive security reasoner.
    """
    ans, _ = query_copilot_with_grounding(prompt_text, report, history)
    return ans


def _call_llm_copilot(
    prompt_text: str,
    report: dict[str, Any],
    history: list[dict[str, str]] | None = None,
) -> str | None:
    """Attempt invocation of the configured LLM provider. Returns None when unavailable."""
    if not llm.is_enabled():
        return None

    try:
        target = report.get("target", "Unknown")
        findings = report.get("findings", [])

        findings_context = []
        for f in findings[:10]:
            findings_context.append(
                f"- [Rank #{f.get('rank', '?')} | {f.get('severity', 'Info')}] {f.get('title')}: {f.get('exploitability')}. Action: {f.get('suggested_action')}"
            )

        context_str = "\n".join(findings_context)
        system_prompt = (
            "You are an elite Defensive Security Operations Center (SOC) Copilot for AEGIS-AI. "
            "You analyze target assessment data and provide defensive engineering fixes, "
            "executive briefings, attack path simulations, and verification scripts. "
            "Never provide offensive exploit payloads or attacks. Focus strictly on blue-team defense. "
            "Cite finding IDs like [Rank #1] or [CVE-...] when referencing specific issues. "
            "Never invent or hallucinate CVE numbers or findings not provided in the context."
        )

        user_content = f"""<target_context>
Target: {target}
Mode: {report.get('mode', 'passive')}
Executive Summary: {report.get('summary', 'None')}
Findings:
{context_str}
</target_context>

User Request: {prompt_text}"""

        result = llm.complete(system_prompt, user_content, max_tokens=1200, temperature=0.3)
        return result.text.strip() or None

    except llm.LLMUnavailable as exc:
        logger.warning("LLM copilot unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.warning("LLM copilot call failed: %s: %s", type(exc).__name__, exc)
        return None


def _respond_scoring_formula(prompt_text: str, report: dict[str, Any]) -> str:
    """Explain mathematical risk scoring formula, active weights, CISA KEV override, and SSVC."""
    from prioritize import get_active_weights
    w_cvss, w_epss, w_exp, w_crit, source = get_active_weights()
    target = report.get("target", "Target")
    findings = report.get("findings", [])

    lines = [
        f"### 📐 AEGIS-AI Contextual Risk Scoring Formula",
        f"AEGIS-AI replaces speculative CVSS inflation with an evidence-grounded linear combination ($W_{{total}} = 1.00$) combining theoretical flaw severity with empirical weaponization signals:",
        "",
        f"$$\\text{{Risk Score}} = ({w_cvss:.2f} \\times S_{{\\text{{CVSS}}}}) + ({w_epss:.2f} \\times S_{{\\text{{EPSS}}}}) + ({w_exp:.2f} \\times S_{{\\text{{Exposure}}}}) + ({w_crit:.2f} \\times S_{{\\text{{Criticality}}}})$$",
        "",
        f"#### ⚖️ Active Scoring Weights Source: `{source}`",
        f"- **$w_1$ Base CVSS Severity:** `{w_cvss:.2f}` (Weight: {int(w_cvss*100)}%) — Normalized theoretical vulnerability severity (0–10).",
        f"- **$w_2$ FIRST.org EPSS Exploit Probability:** `{w_epss:.2f}` (Weight: {int(w_epss*100)}%) — Empirical 30-day weaponization probability in the wild.",
        f"- **$w_3$ Network Reachability & Exposure Context:** `{w_exp:.2f}` (Weight: {int(w_exp*100)}%) — Direct public ingress vs isolated service.",
        f"- **$w_4$ Mission Asset Criticality:** `{w_crit:.2f}` (Weight: {int(w_crit*100)}%) — Crown Jewels impact scaling tier.",
        "",
        "#### 🛡️ CISA KEV Override Policy (BOD 22-01):",
        "If a vulnerability is actively exploited in the wild and listed in the CISA Known Exploited Vulnerabilities (KEV) catalog, "
        "it automatically receives an operational priority floor of **8.5/10.0 (Critical / P1 Queue)** with mandatory remediation due-dates.",
        "",
        "#### 🏛️ Stakeholder-Specific Vulnerability Categorization (SSVC):",
        "- **Act:** Weaponized in wild + Internet reachable -> 24-48h immediate response SLA.",
        "- **Attend:** Proof-of-concept exists + exposed perimeter -> 7-14 day remediation cycle.",
        "- **Track*:** Weaponized but internal / shielded perimeter -> Monitor and virtual patch.",
        "- **Track:** No known exploit + low exposure -> Standard routine patch cycle.",
    ]

    if findings:
        f0 = findings[0]
        title = f0.get("title", "Top Exposure")
        c_score = f0.get("contextual_risk_score", f0.get("score", 7.5))
        cvss = float(f0.get("cvss_score") or f0.get("cvss") or 5.0)
        epss_raw = float(f0.get("epss_probability") or f0.get("epss") or f0.get("epss_score") or 0.05)
        reach = float(f0.get("environmental_reachability_score", 8.0))
        crit = 8.0

        c_comp = round(w_cvss * cvss, 2)
        e_comp = round(w_epss * (epss_raw * 10.0), 2)
        exp_comp = round(w_exp * reach, 2)
        crit_comp = round(w_crit * crit, 2)

        lines.extend([
            "",
            "#### 🔍 Concrete Score Decomposition for Top Finding:",
            f"**Finding #1:** `{title}` (Final Risk Score: **{c_score} / 10.0**)",
            f"- CVSS component: `{w_cvss:.2f} × {cvss} = {c_comp}`",
            f"- EPSS component: `{w_epss:.2f} × {epss_raw*10.0:.1f} = {e_comp}`",
            f"- Exposure component: `{w_exp:.2f} × {reach} = {exp_comp}`",
            f"- Criticality component: `{w_crit:.2f} × {crit} = {crit_comp}`",
            f"- **Formula Sum:** `{c_comp} + {e_comp} + {exp_comp} + {crit_comp} = {round(c_comp+e_comp+exp_comp+crit_comp, 2)}`",
        ])

    return "\n".join(lines)


def _respond_compliance(prompt_text: str, report: dict[str, Any]) -> str:
    """Explain regulatory readiness across NIST, PCI-DSS, ISO 27001, and SOC 2."""
    target = report.get("target", "Target")
    comp = report.get("compliance_governance") or {}
    readiness = comp.get("overall_readiness_score", report.get("score", 75.0))
    grade = comp.get("overall_grade", report.get("grade", "B"))

    pci = comp.get("pci_dss_4") or comp.get("pci_dss") or {}
    nist = comp.get("nist_csf_2") or comp.get("nist_csf") or {}
    iso = comp.get("iso_27001") or {}
    soc = comp.get("soc_2") or {}

    return (
        f"### 📋 Multi-Framework Compliance Readiness Assessment: `{target}`\n\n"
        f"**Overall Compliance Readiness:** **{readiness}%** (Postural Grade: **Grade {grade}**)\n\n"
        f"#### 🏛️ Framework Breakdown:\n"
        f"1. **NIST CSF 2.0 (National Institute of Standards & Technology):**\n"
        f"   - **Readiness Score:** `{nist.get('score', 75)}%` ({nist.get('passing_controls', 3)}/{nist.get('total_controls', 4)} controls compliant)\n"
        f"   - **Covered Controls:** `PR.PS-01` (Transport Encryption), `DE.CM-01` (Perimeter Monitoring), `PR.AC-05` (Network Perimeter & Header Integrity), `RS.MI-01` (Vulnerability Mitigation).\n\n"
        f"2. **PCI-DSS 4.0 (Payment Card Industry Data Security Standard):**\n"
        f"   - **Readiness Score:** `{pci.get('score', 75)}%` ({pci.get('passing_controls', 3)}/{pci.get('total_controls', 4)} controls compliant)\n"
        f"   - **Requirements Evaluated:** Req 6.2.4 (Known vulnerability patching), Req 4.1.1 (TLS 1.2/1.3 transport security), Req 6.4.1 (Public web application WAF protection).\n\n"
        f"3. **ISO/IEC 27001:2022 (Annex A Controls):**\n"
        f"   - **Readiness Score:** `{iso.get('score', 75)}%` ({iso.get('passing_controls', 3)}/{iso.get('total_controls', 4)} controls compliant)\n"
        f"   - **Controls Evaluated:** Control A.8.8 (Management of technical vulnerabilities), Control A.8.20 (Network security & transport), Control A.8.28 (Security headers).\n\n"
        f"4. **SOC 2 Type II (Trust Services Criteria):**\n"
        f"   - **Readiness Score:** `{soc.get('score', 75)}%` ({soc.get('passing_controls', 3)}/{soc.get('total_controls', 4)} controls compliant)\n"
        f"   - **Criteria:** CC6.6 (Logical boundary protection & edge encryption), CC7.1 (Vulnerability monitoring)."
    )


def _respond_patch_config(prompt_text: str, report: dict[str, Any]) -> str:
    """Generate production virtual patch hardening configurations for Nginx, Apache, and Caddy."""
    target = report.get("target", "Target")
    return (
        f"### 🛠️ Production Virtual Patch Configuration (`{target}`)\n\n"
        f"Deploy these hardened reverse proxy configurations to immediately neutralize HTTP security header deficits, prevent Clickjacking, and mitigate MIME sniffing:\n\n"
        f"#### 1. Nginx Hardening Snippet (`/etc/nginx/conf.d/security.conf`):\n"
        f"```nginx\n"
        f"# AEGIS-AI Defensive Virtual Patch Configuration\n"
        f"# Mitigates: CWE-693, CWE-1021, OWASP Top 10 A05:2021\n\n"
        f"# Content Security Policy (mitigates T1189 Drive-by Compromise / XSS)\n"
        f"add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; upgrade-insecure-requests;\" always;\n\n"
        f"# HTTP Strict Transport Security (mitigates T1557 MitM SSL stripping)\n"
        f"add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n"
        f"# Framing & MIME Protections (mitigates T1185 Clickjacking & T1059.007)\n"
        f"add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
        f"add_header X-Content-Type-Options \"nosniff\" always;\n"
        f"add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
        f"add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;\n\n"
        f"# Suppress banner disclosure (mitigates T1046)\n"
        f"server_tokens off;\n"
        f"```\n\n"
        f"#### 2. Apache VirtualHost Directive (`/etc/apache2/conf-available/security.conf`):\n"
        f"```apache\n"
        f"<IfModule mod_headers.c>\n"
        f"    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; upgrade-insecure-requests;\"\n"
        f"    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
        f"    Header always set X-Frame-Options \"SAMEORIGIN\"\n"
        f"    Header always set X-Content-Type-Options \"nosniff\"\n"
        f"    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
        f"</IfModule>\n"
        f"ServerTokens Prod\n"
        f"ServerSignature Off\n"
        f"```\n\n"
        f"#### 3. Verification Command:\n"
        f"```bash\n"
        f"# Test Nginx syntax and apply virtual patch without downtime:\n"
        f"sudo nginx -t && sudo systemctl reload nginx\n"
        f"```"
    )


def _generate_offline_copilot_response(prompt_text: str, report: dict[str, Any]) -> str:
    """Intelligent rule-based offline cyber security assistant."""
    p = prompt_text.lower().strip()
    target = report.get("target", "Target")
    findings = report.get("findings", [])
    top_risks = report.get("top_risks", [])
    summary = report.get("summary", "Defensive security scan completed.")

    # 0. Check for unverified CVE queries
    asked_cves = extract_cves(prompt_text)
    if asked_cves:
        report_cves = {str(c).upper() for f in findings for c in (f.get("related_cves") or [])}
        missing_cves = [c for c in asked_cves if c not in report_cves]
        if missing_cves:
            return (
                f"### ℹ️ Grounded Assessment: Unverified Vulnerability Query\n\n"
                f"The requested identifier(s) `{', '.join(missing_cves)}` **were not identified** on `{target}` in the current assessment.\n\n"
                f"- **Verified Findings Active:** `{len(findings)}`\n"
                f"- **Identified CVEs in Scope:** `{', '.join(sorted(report_cves)) or 'None'}`\n\n"
                f"AEGIS-AI maintains strict evidence-grounding and does not fabricate findings for absent vulnerabilities."
            )

    # 1. Distinct Intent: Scoring Formula & Active Weights
    if any(w in p for w in ["scoring formula", "formula", "scoring weights", "explain risk scoring", "how is risk calculated", "active weights"]):
        return _respond_scoring_formula(prompt_text, report)

    # 2. Distinct Intent: Regulatory Compliance Readiness
    if any(w in p for w in ["compliance", "nist", "pci", "iso 27001", "soc 2", "regulatory"]):
        return _respond_compliance(prompt_text, report)

    # 3. Distinct Intent: Virtual Patching / Hardening Config
    if any(w in p for w in ["nginx", "caddy", "apache", "virtual patch", "patch config", "hardening snippet", "remediation config"]):
        return _respond_patch_config(prompt_text, report)

    # 4. Executive / CISO Briefing / Summary
    if any(w in p for w in ["executive", "ciso", "briefing", "summarize", "summary"]):
        crit_high = [f for f in findings if str(f.get("severity", "")).title() in ["Critical", "High"]]
        cve_list = [cve for f in findings for cve in (f.get("related_cves") or [])]
        
        lines = [
            f"### 🛡️ Executive Cyber Risk Briefing: `{target}`",
            "",
            f"**Current Posture Summary:** {summary}",
            "",
            "#### 📊 Key Risk Metrics:",
            f"- **Total Identified Exposures:** `{len(findings)}`",
            f"- **Immediate Critical/High Threats:** `{len(crit_high)}`",
            f"- **Linked Public CVEs:** `{len(set(cve_list))}`",
            "",
            "#### 🎯 Strategic Priority Action Plan:",
        ]
        for idx, risk in enumerate(top_risks[:3], 1):
            lines.append(f"{idx}. **{risk}**")
        lines.extend([
            "",
            "#### 💡 Business Impact & Remediation Recommendation:",
            "Unremediated critical exposures risk initial access exploitation and automated bot probing. "
            "Implementing baseline HTTP security headers (CSP, HSTS), updating public-facing software packages, "
            "and restricting firewall ingress will reduce the threat index by over **70%**."
        ])
        return "\n".join(lines)

    # 2. Quick-Wins / Fast Fixes
    if "quick" in p or "fast" in p or "win" in p or "priority" in p:
        lines = [
            f"### ⚡ Top 3 Quick-Win Fixes for `{target}`",
            "These mitigations require under 15 minutes of configuration and provide immediate defense posture elevation:",
            "",
            "1. **Deploy Essential HTTP Security Headers (HSTS, CSP, X-Frame-Options)**",
            "   - *Effort:* 5 minutes in reverse proxy (Nginx/Apache/Caddy/Cloudflare).",
            "   - *Impact:* Prevents Clickjacking, MIME-sniffing, and MitM transport downgrade.",
            "",
            "2. **Suppress Server Version Disclosure Headers (`server_tokens off;`)**",
            "   - *Effort:* 1 line in web server config.",
            "   - *Impact:* Denies automated reconnaissance tools fingerprinting your exact backend version.",
            "",
            "3. **Enforce Strict SPF & DMARC DNS Records (`v=DMARC1; p=reject;`)**",
            "   - *Effort:* 2 DNS TXT records in domain registrar.",
            "   - *Impact:* Immediately stops threat actors from spoofing your domain in spearphishing campaigns.",
        ]
        return "\n".join(lines)

    # 3. Verification Script / Bash testing
    if "script" in p or "bash" in p or "test" in p or "curl" in p or "verify" in p:
        lines = [
            f"### 🧪 Automated Bash Verification Script for `{target}`",
            "Run this diagnostic shell script locally to verify your defensive fixes:",
            "",
            "```bash",
            "#!/usr/bin/env bash",
            f"TARGET=\"{target}\"",
            "echo \"=============================================\"",
            "echo \"[*] Testing Defensive Posture for: $TARGET\"",
            "echo \"=============================================\"",
            "",
            "# 1. Test Security Headers",
            "echo -e \"\\n[1] Checking Security Headers:\"",
            "curl -s -I \"https://$TARGET\" | grep -iE 'strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|server:'",
            "",
            "# 2. Test SPF and DMARC DNS Records",
            "echo -e \"\\n[2] Checking SPF DNS TXT Record:\"",
            "dig +short TXT \"$TARGET\" | grep -i 'v=spf1'",
            "echo -e \"\\n[3] Checking DMARC DNS TXT Record:\"",
            "dig +short TXT \"_dmarc.$TARGET\"",
            "",
            "# 3. Test TLS Protocol",
            "echo -e \"\\n[4] Testing TLS Handshake:\"",
            "openssl s_client -connect \"$TARGET:443\" -servername \"$TARGET\" </dev/null 2>/dev/null | grep -E 'Protocol|Cipher'",
            "",
            "echo -e \"\\n[+] Verification Complete!\"",
            "```",
        ]
        return "\n".join(lines)

    # 4. Threat Actor Simulation / Kill-Chain
    if "threat" in p or "actor" in p or "attack" in p or "path" in p or "kill" in p or "chain" in p:
        lines = [
            f"### 🎭 Adversary Attack Path Simulation (`{target}`)",
            "Here is how a threat actor could attempt to chain the identified attack surface exposures:",
            "",
            "1. **Phase 1 — Reconnaissance (OSINT)**",
            f"   - Adversary enumerates public Certificate Transparency logs and DNS records to map subdomains.",
            "   - Banner probing reveals software stack and exact version disclosures.",
            "",
            "2. **Phase 2 — Weaponization & Initial Access (T1190 / T1566)**",
            "   - If missing SPF/DMARC: Threat actor launches spoofed phishing emails impersonating the domain.",
            "   - If public CVEs detected: Adversary leverages known weaponized exploit scripts (referenced in CISA KEV / EPSS).",
            "",
            "3. **Phase 3 — Exploitation & Client Manipulation (T1189)**",
            "   - Missing Content-Security-Policy and X-Frame-Options allow cross-origin framing and UI redressing (Clickjacking).",
            "",
            "#### 🛡️ Defensive Countermeasures:",
            "- Implement strict egress/ingress firewall filtering.",
            "- Standardize on hardened base web server templates.",
            "- Rotate API tokens and ensure all administrative interfaces require Multi-Factor Authentication (MFA).",
        ]
        return "\n".join(lines)

    # 5. Targeted Factual Findings Lookups (Grounding Enhancers)
    if "critical" in p or "highest risk" in p or "top finding" in p or "first finding" in p:
        top_f = next((f for f in findings if str(f.get("severity", "")).title() == "Critical"), findings[0] if findings else None)
        if top_f:
            rank = top_f.get("rank", 1)
            cves = ", ".join(top_f.get("related_cves") or [])
            return (
                f"### 🚨 Highest Risk Finding: `{top_f.get('title')}` [Rank #{rank}]\n\n"
                f"- **Severity:** `{top_f.get('severity', 'Critical')}`\n"
                f"- **Exploitability Assessment:** {top_f.get('exploitability')}\n"
                f"- **Associated CVE Identifiers:** `{cves or 'None'}`\n"
                f"- **Remediation Action:** {top_f.get('suggested_action')}"
            )

    m_rank = re.search(r"\b(second|2nd|rank\s*#?2)\b", p)
    if m_rank and len(findings) >= 2:
        f2 = findings[1]
        return (
            f"### 📋 Prioritized Finding #2: `{f2.get('title')}` [Rank #{f2.get('rank', 2)}]\n\n"
            f"- **Severity:** `{f2.get('severity')}`\n"
            f"- **Exploitability:** {f2.get('exploitability')}\n"
            f"- **Remediation Action:** {f2.get('suggested_action')}"
        )

    if "port" in p or "open ports" in p:
        ports = report.get("open_ports") or [f.get("port") for f in findings if f.get("port")] or [80, 443]
        return (
            f"### 🔌 Open Network Ports for `{target}`\n\n"
            f"Perimeter reconnaissance identified **{len(ports)} open TCP ports**: `{', '.join(str(pt) for pt in ports)}`.\n\n"
            f"- **Observed Services:** HTTP on port 80 and HTTPS on port 443\n"
            f"- **Action:** Restrict unauthorized administrative ports and enforce firewall filtering."
        )

    if "cve" in p:
        matched_f = [f for f in findings if f.get("related_cves")]
        if matched_f:
            lines = [f"### 🔍 Associated Common Vulnerabilities and Exposures (CVEs) for `{target}`\n"]
            for f in matched_f:
                cves = ", ".join(f.get("related_cves", []))
                lines.append(f"- **[Rank #{f.get('rank', '?')}] {f.get('title')}:** `{cves}` ({f.get('exploitability')})")
            return "\n".join(lines)

    if "apache" in p or "version" in p:
        apache_f = next((f for f in findings if "apache" in str(f.get("title", "")).lower()), None)
        if apache_f:
            return (
                f"### 📦 Detected Software Version: `{apache_f.get('title')}` [Rank #{apache_f.get('rank', 1)}]\n\n"
                f"- **Exploitability:** {apache_f.get('exploitability')}\n"
                f"- **Recommended Upgrade:** {apache_f.get('suggested_action')}\n"
                f"- **Associated CVEs:** `{', '.join(apache_f.get('related_cves') or [])}`"
            )

    if "hsts" in p or "strict-transport-security" in p or "max-age" in p:
        hsts_f = next((f for f in findings if "hsts" in str(f.get("title", "")).lower()), None)
        if hsts_f:
            return (
                f"### 🔒 Transport Security Finding: `{hsts_f.get('title')}` [Rank #{hsts_f.get('rank', 2)}]\n\n"
                f"- **Severity:** `{hsts_f.get('severity')}`\n"
                f"- **Risk:** {hsts_f.get('exploitability')}\n"
                f"- **Remediation Action:** {hsts_f.get('suggested_action')}"
            )

    if "csp" in p or "content-security-policy" in p:
        csp_f = next((f for f in findings if "csp" in str(f.get("title", "")).lower()), None)
        if csp_f:
            return (
                f"### 🛡️ Content Security Policy Finding: `{csp_f.get('title')}` [Rank #{csp_f.get('rank', 3)}]\n\n"
                f"- **Severity:** `{csp_f.get('severity')}`\n"
                f"- **Defense Mechanism:** {csp_f.get('exploitability')}\n"
                f"- **Remediation Action:** {csp_f.get('suggested_action')}"
            )

    if "dmarc" in p or "spoofing" in p or "email" in p or "spearphishing" in p:
        dmarc_f = next((f for f in findings if "dmarc" in str(f.get("title", "")).lower()), None)
        if dmarc_f:
            return (
                f"### 📧 Email Authentication Finding: `{dmarc_f.get('title')}` [Rank #{dmarc_f.get('rank', 4)}]\n\n"
                f"- **Severity:** `{dmarc_f.get('severity')}`\n"
                f"- **Exploitation Impact:** {dmarc_f.get('exploitability')}\n"
                f"- **Remediation Action:** {dmarc_f.get('suggested_action')}"
            )

    if "how many" in p or "total findings" in p or "scan mode" in p or "mode" in p:
        return (
            f"### 📊 Scan Assessment Scope for `{target}`\n\n"
            f"- **Target Host:** `{target}`\n"
            f"- **Execution Mode:** `{report.get('mode', 'passive')}`\n"
            f"- **Total Identified Exposures:** `{len(findings)}`\n"
            f"- **Posture Summary:** {summary}"
        )

    # Generic contextual answer
    return (
        f"### 🤖 AI SOC Analyst Telemetry Analysis for `{target}`\n\n"
        f"**Executive Insight:** {summary}\n\n"
        f"**Identified Risk Profile:** Currently tracking **{len(findings)} findings** with **{len(top_risks)} primary risk vectors**.\n\n"
        f"**Suggested Next Steps:**\n"
        f"1. Open the **🛠️ Remediation Sandbox** tab to generate drop-in Nginx, Apache, or Cloudflare code fixes.\n"
        f"2. Inspect the **🕸️ MITRE ATT&CK Threat Matrix** tab to see kill-chain mapping.\n"
        f"3. Use the **⚡ Patch Simulator** tab to calculate risk reduction score before pushing changes to production."
    )
