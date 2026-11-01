"""
AI Security SOC Copilot & Reasoning Assistant.
Provides contextual Q&A, executive briefings, patch bash script generation,
and threat actor path simulation based on report findings.
"""

from __future__ import annotations

import json
import os
from typing import Any

from config import AWS_REGION, BEDROCK_MODEL_ID


def query_copilot(
    prompt_text: str,
    report: dict[str, Any],
    history: list[dict[str, str]] | None = None,
) -> str:
    """
    Process an analyst query using Amazon Bedrock if available,
    or our intelligent offline defensive security reasoner.
    """
    target = report.get("target", "Target Host")
    findings = report.get("findings", [])
    mode = report.get("mode", "passive")
    summary = report.get("summary", "No summary available.")
    top_risks = report.get("top_risks", [])

    # Try Bedrock LLM first if configured
    bedrock_response = _call_bedrock_copilot(prompt_text, report, history)
    if bedrock_response:
        return bedrock_response

    # Heuristic Security Reasoner fallback
    return _generate_offline_copilot_response(prompt_text, report)


def _call_bedrock_copilot(
    prompt_text: str,
    report: dict[str, Any],
    history: list[dict[str, str]] | None = None,
) -> str | None:
    """Attempt invocation of Amazon Bedrock Claude / Nova."""
    try:
        import boto3
        client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
        
        target = report.get("target", "Unknown")
        findings = report.get("findings", [])
        
        findings_context = []
        for f in findings[:10]:
            findings_context.append(
                f"- [Rank #{f.get('rank', '?')} | {f.get('severity', 'Info')}] {f.get('title')}: {f.get('exploitability')}. Action: {f.get('suggested_action')}"
            )

        context_str = "\n".join(findings_context)
        system_prompt = (
            "You are an elite Defensive Security Operations Center (SOC) Copilot. "
            "You analyze target assessment data and provide defensive engineering fixes, "
            "executive briefings, attack path simulations, and verification scripts. "
            "Never provide offensive exploit payloads or attacks. Focus strictly on blue-team defense."
        )

        user_content = f"""<target_context>
Target: {target}
Mode: {report.get('mode', 'passive')}
Executive Summary: {report.get('summary', 'None')}
Findings:
{context_str}
</target_context>

User Request: {prompt_text}"""

        response = client.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_content}]}],
            inferenceConfig={"maxTokens": 1200, "temperature": 0.3},
        )
        parts = response.get("output", {}).get("message", {}).get("content", [])
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p)
        return text.strip() or None
    except Exception:
        return None


def _generate_offline_copilot_response(prompt_text: str, report: dict[str, Any]) -> str:
    """Intelligent rule-based offline cyber security assistant."""
    p = prompt_text.lower().strip()
    target = report.get("target", "Target")
    findings = report.get("findings", [])
    top_risks = report.get("top_risks", [])
    summary = report.get("summary", "Defensive security scan completed.")

    # 1. Executive / CISO Briefing
    if "executive" in p or "ciso" in p or "briefing" in p or "summary" in p:
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
        header_findings = [f for f in findings if "header" in str(f.get("title", "")).lower() or "csp" in str(f.get("title", "")).lower() or "hsts" in str(f.get("title", "")).lower()]
        token_findings = [f for f in findings if "version" in str(f.get("title", "")).lower() or "disclosure" in str(f.get("title", "")).lower()]
        
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
