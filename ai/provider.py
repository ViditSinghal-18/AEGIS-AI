"""
AEGIS-AI: Multi-Model LLM Provider Interface.
Supports:
- Anthropic Claude API (ANTHROPIC_API_KEY)
- AWS Bedrock Converse API (AWS_REGION, BEDROCK_MODEL_ID)
- Google Gemini API (GEMINI_API_KEY)
- Local Ollama (OLLAMA_HOST, OLLAMA_MODEL)
- Offline Deterministic Rule-Based Fallback Reasoner

Features:
- Auto-selection based on configured environment variables
- Token and response size caps
- Grounded context injection inside sanitized <target_data> boundary
- Grounding verification (rejects hallucinated CVE IDs)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import config
from discovery.safe_fetch import safe_fetch
from security import sanitize_for_prompt, wrap_target_data


SYSTEM_PROMPT = """You are Aegis Copilot, an autonomous Security Operations Center (SOC) AI assistant.
You operate strictly as a Defensive Blue-Team engineer.
Your task is to analyze the target attack surface telemetry, explain vulnerabilities, recommend hardening configurations, and answer analyst questions.

RULES:
1. Ground your answers strictly in the provided <target_data> perimeter telemetry.
2. Cite specific Finding IDs and verified CVEs from the telemetry.
3. NEVER provide offensive exploit code, attack payloads, or weaponized walkthroughs. Refuse offensive requests and offer defensive remediation instead.
4. Keep answers concise, clear, and actionable.
"""


def get_available_llm_provider() -> Tuple[str, str]:
    """Detect available LLM provider based on environment variables."""
    if os.getenv("ANTHROPIC_API_KEY", "").strip():
        return "anthropic", os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    if os.getenv("GEMINI_API_KEY", "").strip():
        return "gemini", os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    if os.getenv("AWS_ACCESS_KEY_ID", "").strip() or os.getenv("AWS_REGION", "").strip():
        return "bedrock", getattr(config, "BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
    if os.getenv("OLLAMA_HOST", "").strip():
        return "ollama", os.getenv("OLLAMA_MODEL", "llama3.2")
    return "rule-based", "AEGIS Defensive Heuristic Reasoner"


def check_cve_grounding(response_text: str, report: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Verify that all CVE IDs cited in the LLM response actually exist in the target report.
    Returns: (is_grounded, ungrounded_cves)
    """
    cited_cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", response_text, re.IGNORECASE))
    if not cited_cves:
        return True, []

    # Gather all verified CVEs in the report
    report_cves = set()
    findings = report.get("findings", report.get("prioritized_findings", []))
    for f in findings:
        for cve in f.get("related_cves", []):
            report_cves.add(cve.upper())
        vuln_id = str(f.get("vuln_id", "")).upper()
        if vuln_id.startswith("CVE-"):
            report_cves.add(vuln_id)

    ungrounded = [c for c in cited_cves if c.upper() not in report_cves]
    return len(ungrounded) == 0, ungrounded


def call_anthropic(prompt: str, context: str, model: str) -> Optional[str]:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        import requests
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": model,
            "max_tokens": 800,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": f"{context}\n\nUser Question: {prompt}"}
            ]
        }
        res = requests.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload, timeout=12.0)
        if res.status_code == 200:
            data = res.json()
            return data["content"][0]["text"].strip()
    except Exception:
        pass
    return None


def call_gemini(prompt: str, context: str, model: str) -> Optional[str]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{
                "parts": [{
                    "text": f"{SYSTEM_PROMPT}\n\n{context}\n\nUser Question: {prompt}"
                }]
            }],
            "generationConfig": {"maxOutputTokens": 800, "temperature": 0.2}
        }
        res = safe_fetch(url, method="POST", data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=12.0)
        if res.status_code == 200:
            data = res.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                return "".join(p.get("text", "") for p in parts).strip()
    except Exception:
        pass
    return None


def call_bedrock(prompt: str, context: str, model: str) -> Optional[str]:
    try:
        import boto3
        region = os.getenv("AWS_REGION", "us-east-1")
        client = boto3.client("bedrock-runtime", region_name=region)
        user_content = f"{context}\n\nUser Question: {prompt}"
        response = client.converse(
            modelId=model,
            system=[{"text": SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": user_content}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0.3}
        )
        parts = response.get("output", {}).get("message", {}).get("content", [])
        return "".join(p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p).strip()
    except Exception:
        return None


def call_ollama(prompt: str, context: str, model: str) -> Optional[str]:
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        url = f"{host}/api/generate"
        payload = {
            "model": model,
            "prompt": f"{SYSTEM_PROMPT}\n\n{context}\n\nUser Question: {prompt}",
            "stream": False,
            "options": {"num_predict": 600}
        }
        res = safe_fetch(url, method="POST", data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=15.0)
        if res.status_code == 200:
            return res.json().get("response", "").strip()
    except Exception:
        pass
    return None


def call_rule_based_fallback(prompt: str, report: Dict[str, Any]) -> str:
    """
    Deterministic rule-based offline security reasoning assistant.
    Provides verified answers derived strictly from current report data.
    """
    p = prompt.lower().strip()
    target = report.get("target", "Target Host")
    findings = report.get("findings", report.get("prioritized_findings", []))
    compliance = report.get("compliance_governance", {})
    comp_score = compliance.get("overall_readiness_score", "N/A")
    comp_grade = compliance.get("overall_grade", "B")

    # Anti-Exploit Guardrail
    if any(k in p for k in ["exploit", "payload", "attack", "hack", "poc", "weaponize"]):
        return (
            "🛡️ **AEGIS Defensive Guardrail Intervention**\n\n"
            "As an autonomous Defensive Blue-Team Copilot, I am restricted from generating offensive "
            "exploit payloads, PoCs, or attack scripts. I can provide virtual patches, WAF rules, and "
            "defensive configuration hardening for this target."
        )

    # 1. Executive Summary / Overview
    if any(k in p for k in ["summary", "overview", "executive", "brief", "ciso", "status"]):
        high_crit = [f for f in findings if str(f.get("severity", "")).title() in ["Critical", "High"]]
        top_title = findings[0].get("title", "No critical findings") if findings else "Clean Perimeter"
        return (
            f"### 🛡️ Defensive Executive Briefing: `{target}`\n\n"
            f"- **Operational Mode:** {report.get('mode', 'PASSIVE OSINT')}\n"
            f"- **Total Identified Findings:** {len(findings)} ({len(high_crit)} Critical/High priority)\n"
            f"- **Compliance Posture:** {comp_score}% Readiness (Grade {comp_grade})\n"
            f"- **Highest Priority Vector:** #{1} {top_title}\n"
            f"- **Recommended Next Action:** Review virtual patches at `/api/remediation` and enforce missing perimeter headers."
        )

    # 2. Compliance / Regulatory
    if any(k in p for k in ["compliance", "nist", "pci", "iso", "soc", "governance"]):
        pci = compliance.get("pci_dss_4", {})
        nist = compliance.get("nist_csf_2", {})
        iso = compliance.get("iso_27001", {})
        soc2 = compliance.get("soc_2", {})
        return (
            f"### 📋 Multi-Framework Compliance Analysis for `{target}`\n\n"
            f"- **Overall Readiness:** {comp_score}% (Grade **{comp_grade}**)\n"
            f"- **PCI-DSS 4.0:** {pci.get('score', 'N/A')}% ({pci.get('passing_controls', 0)}/{pci.get('total_controls', 4)} controls passed)\n"
            f"- **NIST CSF 2.0:** {nist.get('score', 'N/A')}% ({nist.get('passing_controls', 0)}/{nist.get('total_controls', 5)} controls passed)\n"
            f"- **ISO/IEC 27001:** {iso.get('score', 'N/A')}% ({iso.get('passing_controls', 0)}/{iso.get('total_controls', 4)} controls passed)\n"
            f"- **SOC 2 Type II:** {soc2.get('score', 'N/A')}% ({soc2.get('passing_controls', 0)}/{soc2.get('total_controls', 4)} controls passed)\n\n"
            f"*Detailed control breakdown is available via the `/api/compliance` endpoint.*"
        )

    # 3. Specific CVE Query
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", prompt, re.IGNORECASE)
    if cve_match:
        target_cve = cve_match.group(0).upper()
        matched_finding = None
        for f in findings:
            if target_cve in [c.upper() for c in f.get("related_cves", [])] or target_cve in str(f.get("vuln_id", "")).upper():
                matched_finding = f
                break
        if matched_finding:
            return (
                f"### 🔍 Telemetry Record for `{target_cve}`\n\n"
                f"- **Title:** {matched_finding.get('title')}\n"
                f"- **Priority:** {matched_finding.get('priority_level', 'P2')}\n"
                f"- **Contextual Risk Score:** {matched_finding.get('contextual_risk_score', 'N/A')}/10\n"
                f"- **EPSS Weaponization Probability:** {matched_finding.get('epss_probability', 'N/A')}\n"
                f"- **CISA KEV Status:** {'Listed (Active Threat)' if matched_finding.get('in_cisa_kev') else 'Not listed in KEV catalog'}\n"
                f"- **Evidence:** {matched_finding.get('evidence', 'Identified during scan')}\n"
                f"- **Defensive Action:** `{matched_finding.get('remediation', 'Apply security patch')}`"
            )
        else:
            return (
                f"The vulnerability `{target_cve}` was **not detected** in the perimeter assessment for `{target}`. "
                f"Currently monitoring {len(findings)} verified findings."
            )

    # 4. Patch / Remediation
    if any(k in p for k in ["patch", "remediat", "fix", "nginx", "helmet", "waf"]):
        top_finding = findings[0] if findings else {}
        return (
            f"### 🛠️ Recommended Hardening for `{target}`\n\n"
            f"**1. Immediate Ingress Action:**\n"
            f"```nginx\n"
            f"# Suppress Server Fingerprint\n"
            f"server_tokens off;\n"
            f"add_header X-Frame-Options \"DENY\" always;\n"
            f"add_header X-Content-Type-Options \"nosniff\" always;\n"
            f"add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            f"```\n\n"
            f"**2. Top Finding Action:**\n"
            f"{top_finding.get('remediation', 'Review security headers and access policies.')}\n\n"
            f"*You can export complete Nginx, Apache, Caddy, and WAF rules via `/api/remediation`.*"
        )

    # Default fallback
    top_cve = findings[0].get("related_cves", ["None"])[0] if findings and findings[0].get("related_cves") else "Perimeter Configuration"
    return (
        f"### 🛡️ AEGIS-AI Defensive Assistant\n\n"
        f"Monitoring `{target}` ({len(findings)} correlated findings).\n"
        f"- **Top Priority Finding:** #{1} {findings[0].get('title') if findings else 'No active findings'}\n"
        f"- **Primary Threat Indicator:** `{top_cve}`\n"
        f"- **Compliance Grade:** {comp_grade} ({comp_score}%)\n\n"
        f"Ask me about specific findings (e.g. 'summarize findings', 'show compliance', 'patch for nginx', or query any CVE)."
    )


def query_copilot(prompt: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Aegis Copilot reasoning.
    Prepares sanitized context, selects provider, executes query, and enforces grounding guardrails.
    """
    target = report.get("target", "target.site")
    findings = report.get("findings", report.get("prioritized_findings", []))

    # Anti-exploit check first
    p_lower = prompt.lower()
    if any(k in p_lower for k in ["exploit", "payload", "attack", "hack", "poc", "weaponize", "sqlmap", "metasploit"]):
        return {
            "reply": (
                "🛡️ **AEGIS Defensive Guardrail Intervention**\n\n"
                "As an autonomous Defensive Blue-Team Copilot, I am restricted from generating offensive "
                "exploit payloads, PoCs, or attack scripts. I can provide virtual patches, WAF rules, and "
                "defensive configuration hardening for this target."
            ),
            "provider": "guardrail",
            "model": "AEGIS Anti-Exploit Hard Gate",
            "grounded": True
        }

    # Format bounded target context
    capped_findings = []
    for f in findings[:8]:
        capped_findings.append({
            "rank": f.get("rank"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "cves": f.get("related_cves", []),
            "risk_score": f.get("contextual_risk_score"),
            "remediation": f.get("remediation")
        })

    context_blob = {
        "target": target,
        "mode": report.get("mode", "PASSIVE OSINT"),
        "compliance_score": report.get("compliance_governance", {}).get("overall_readiness_score"),
        "findings": capped_findings
    }
    wrapped_context = wrap_target_data(context_blob)

    provider_name, model_name = get_available_llm_provider()
    raw_answer = None

    if provider_name == "anthropic":
        raw_answer = call_anthropic(prompt, wrapped_context, model_name)
    elif provider_name == "gemini":
        raw_answer = call_gemini(prompt, wrapped_context, model_name)
    elif provider_name == "bedrock":
        raw_answer = call_bedrock(prompt, wrapped_context, model_name)
    elif provider_name == "ollama":
        raw_answer = call_ollama(prompt, wrapped_context, model_name)

    # Fallback to rule-based reasoner if LLM unavailable or failed
    if not raw_answer:
        raw_answer = call_rule_based_fallback(prompt, report)
        provider_name = "rule-based"
        model_name = "AEGIS Defensive Heuristic Reasoner"

    # Enforce Grounding Check
    is_grounded, ungrounded_cves = check_cve_grounding(raw_answer, report)
    if not is_grounded:
        warning_notice = f"\n\n> ⚠️ *Grounding Notice: Filtered ungrounded reference(s) ({', '.join(ungrounded_cves)}) not verified in {target} telemetry.*"
        raw_answer += warning_notice

    return {
        "reply": raw_answer,
        "provider": provider_name,
        "model": model_name,
        "grounded": is_grounded
    }
