"""
MITRE ATT&CK Matrix & Cyber Kill-Chain Correlation Engine.
Maps attack surface findings, open ports, missing headers, and CVEs into MITRE ATT&CK tactics and techniques.
"""

from __future__ import annotations

import os
import re
from typing import Any


TACTIC_DEFINITIONS = {
    "TA0043": {"name": "Reconnaissance", "icon": "🛰️", "color": "#38bdf8", "description": "Adversary is trying to gather information to plan future adversary operations."},
    "TA0001": {"name": "Initial Access", "icon": "🚪", "color": "#ef4444", "description": "Adversary is trying to get into your network through public-facing applications or spearphishing."},
    "TA0002": {"name": "Execution", "icon": "⚡", "color": "#fb923c", "description": "Adversary is trying to run malicious code or scripts."},
    "TA0007": {"name": "Discovery", "icon": "🔍", "color": "#f59e0b", "description": "Adversary is trying to observe the system and network environment."},
    "TA0005": {"name": "Defense Evasion", "icon": "🛡️", "color": "#a855f7", "description": "Techniques used to avoid detection and bypass security controls."},
    "TA0006": {"name": "Credential Access", "icon": "🔑", "color": "#ec4899", "description": "Adversary is attempting to steal account credentials or session tokens."},
    "TA0040": {"name": "Impact", "icon": "💥", "color": "#dc2626", "description": "Adversary is trying to manipulate, interrupt, or destroy your systems and data."},
}


TECHNIQUE_RULES = [
    {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise: Script Injection / CSP Absence",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1189/",
        "match_condition": lambda f: any(k in str(f.get("title", "")).lower() or k in str(f.get("vuln_id", "")).lower() for k in ["content-security-policy", "content_security_policy", "hdr-content_security_policy", "hdr-csp"]),
        "relevance": "High",
        "mitigation": "Deploy Content-Security-Policy (CSP) headers with strict object-src and script nonces.",
    },
    {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle (MitM Transport Downgrade / HSTS Absence)",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1557/",
        "match_condition": lambda f: any(k in str(f.get("title", "")).lower() or k in str(f.get("vuln_id", "")).lower() for k in ["strict-transport-security", "strict_transport_security", "hsts", "hdr-strict_transport_security", "hdr-hsts"]),
        "relevance": "High",
        "mitigation": "Enforce HTTP Strict Transport Security (HSTS) with max-age=31536000 and includeSubDomains.",
    },
    {
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking: Clickjacking / Framing Absence",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1185/",
        "match_condition": lambda f: any(k in str(f.get("title", "")).lower() or k in str(f.get("vuln_id", "")).lower() for k in ["x-frame-options", "x_frame_options", "clickjacking", "hdr-x_frame_options", "hdr-xfo"]),
        "relevance": "High",
        "mitigation": "Send X-Frame-Options: SAMEORIGIN or DENY to prevent UI redressing.",
    },
    {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript (MIME Sniffing)",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "match_condition": lambda f: any(k in str(f.get("title", "")).lower() or k in str(f.get("vuln_id", "")).lower() for k in ["x-content-type-options", "x_content_type_options", "mime-sniffing", "hdr-x_content_type_options", "hdr-xcto"]),
        "relevance": "Medium",
        "mitigation": "Enforce X-Content-Type-Options: nosniff on all HTTP responses.",
    },
    {
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information: Referer Path Leakage",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1592/",
        "match_condition": lambda f: any(k in str(f.get("title", "")).lower() or k in str(f.get("vuln_id", "")).lower() for k in ["referrer-policy", "referrer_policy", "hdr-referrer_policy", "hdr-referrer"]),
        "relevance": "Low",
        "mitigation": "Configure Referrer-Policy: strict-origin-when-cross-origin to avoid URL query leaks.",
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "match_condition": lambda f: bool(f.get("related_cves")) or "port_scan" in str(f.get("source", "")),
        "relevance": "High",
        "mitigation": "Apply vendor security patches, isolate vulnerable services behind a reverse proxy, and deploy WAF rules.",
    },
    {
        "technique_id": "T1596",
        "technique_name": "Search Open Technical Databases",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1596/",
        "match_condition": lambda f: "certificate_transparency" in str(f.get("source", "")).lower() or "crt.sh" in str(f.get("title", "")).lower() or "shodan" in str(f.get("source", "")).lower(),
        "relevance": "Medium",
        "mitigation": "Audit public Certificate Transparency logs and decommission dangling DNS records for subdomains.",
    },
    {
        "technique_id": "T1595",
        "technique_name": "Active Scanning: Port Scanning & Probing",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "match_condition": lambda f: bool(re.search(r"\bports?\b", str(f.get("title", "")).lower())) or "port_scan" in str(f.get("source", "")),
        "relevance": "High",
        "mitigation": "Restrict open inbound firewall ports (UFW/Security Groups) to authorized IP ranges.",
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "match_condition": lambda f: "service" in str(f.get("title", "")).lower() or "version disclosure" in str(f.get("title", "")).lower() or "server_tokens" in str(f.get("suggested_action", "")).lower(),
        "relevance": "Medium",
        "mitigation": "Disable HTTP Server banner disclosure (e.g. `server_tokens off;` or `ServerTokens Prod`).",
    },
    {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link / Spoofing",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "match_condition": lambda f: "spf" in str(f.get("title", "")).lower() or "dmarc" in str(f.get("title", "")).lower(),
        "relevance": "High",
        "mitigation": "Publish strict SPF DNS records (`-all`) and enforce a DMARC policy (`p=reject` or `p=quarantine`).",
    },
    {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle (MitM) / Weak Cryptography",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1557/",
        "match_condition": lambda f: "tls" in str(f.get("title", "")).lower() or "ssl" in str(f.get("title", "")).lower() or "hsts" in str(f.get("title", "")).lower() or "cookie" in str(f.get("title", "")).lower(),
        "relevance": "High",
        "mitigation": "Enforce HTTP Strict Transport Security (HSTS) with `preload`, secure cookies (`Secure; HttpOnly; SameSite=Strict`), and modern TLS 1.3.",
    },
    {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise / Clickjacking / XSS Exposure",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1189/",
        "match_condition": lambda f: "csp" in str(f.get("title", "")).lower() or "content-security-policy" in str(f.get("title", "")).lower() or "x-frame-options" in str(f.get("title", "")).lower() or "cors" in str(f.get("title", "")).lower(),
        "relevance": "High",
        "mitigation": "Configure strict Content-Security-Policy (CSP) headers and set `X-Frame-Options: DENY`.",
    },
    {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service (Exposed Insecure Endpoints)",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "match_condition": lambda f: str(f.get("severity", "")).lower() == "critical" and bool(f.get("related_cves")),
        "relevance": "Critical",
        "mitigation": "Implement rate limiting, perimeter DDoS shields (Cloudflare/AWS Shield), and patch critical remote vulnerabilities.",
    },
]


def map_findings_to_mitre(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Map an array of prioritized findings to MITRE ATT&CK tactics, techniques, and kill-chain paths.
    """
    technique_findings_map: dict[str, list[dict[str, Any]]] = {}
    tactics_summary: dict[str, dict[str, Any]] = {}

    for tactic_id, t_info in TACTIC_DEFINITIONS.items():
        tactics_summary[tactic_id] = {
            "name": t_info["name"],
            "icon": t_info["icon"],
            "color": t_info["color"],
            "description": t_info["description"],
            "matched_techniques": [],
            "finding_count": 0,
        }

    for finding in findings:
        matched_any = False
        for rule in TECHNIQUE_RULES:
            if rule["match_condition"](finding):
                tech_id = rule["technique_id"]
                if tech_id not in technique_findings_map:
                    technique_findings_map[tech_id] = []
                technique_findings_map[tech_id].append(finding)
                matched_any = True

                t_id = rule["tactic_id"]
                if t_id in tactics_summary:
                    if tech_id not in [t["id"] for t in tactics_summary[t_id]["matched_techniques"]]:
                        tactics_summary[t_id]["matched_techniques"].append({
                            "id": tech_id,
                            "name": rule["technique_name"],
                            "url": rule["url"],
                            "mitigation": rule["mitigation"],
                            "relevance": rule["relevance"],
                        })
                    tactics_summary[t_id]["finding_count"] += 1

        # Fallback if unmapped
        if not matched_any:
            tech_id = "T1596"
            if tech_id not in technique_findings_map:
                technique_findings_map[tech_id] = []
            technique_findings_map[tech_id].append(finding)
            tactics_summary["TA0043"]["finding_count"] += 1

    # Kill chain stages in logical execution order
    kill_chain_order = ["TA0043", "TA0001", "TA0002", "TA0007", "TA0006", "TA0005", "TA0040"]
    kill_chain = []
    for t_id in kill_chain_order:
        data = tactics_summary.get(t_id)
        if data:
            kill_chain.append({
                "tactic_id": t_id,
                "name": data["name"],
                "icon": data["icon"],
                "color": data["color"],
                "count": data["finding_count"],
                "techniques": data["matched_techniques"],
            })

    return {
        "tactics": tactics_summary,
        "kill_chain": kill_chain,
        "technique_findings": technique_findings_map,
        "total_techniques_flagged": sum(len(d["matched_techniques"]) for d in tactics_summary.values()),
    }


def map_finding_to_mitre(finding: dict[str, Any], mapper_mode: str | None = None) -> dict[str, Any]:
    """Map an individual finding to MITRE ATT&CK techniques.

    Supports rule-based mapping (default) and learned TF-IDF+Linear classifier (Kuppa et al. 2021).
    """
    mode = mapper_mode or os.getenv("AEGIS_MITRE_MAPPER", "rule").lower()
    
    # 1. Check if learned mapper mode is requested
    if mode == "learned":
        try:
            from correlation.learned_attack_mapper import get_learned_attack_mapper
            learned_pred = get_learned_attack_mapper().predict(finding)
            t_id = learned_pred.technique_id
            
            matching_rule = next((r for r in TECHNIQUE_RULES if r["technique_id"] == t_id), None)
            if matching_rule:
                primary = {
                    "technique_id": matching_rule["technique_id"],
                    "technique_name": matching_rule["technique_name"],
                    "tactic_id": matching_rule["tactic_id"],
                    "tactic_name": matching_rule["tactic_name"],
                    "url": matching_rule["url"],
                    "mitigation": matching_rule["mitigation"],
                    "confidence": learned_pred.confidence,
                    "mapping_source": "learned_classifier",
                }
                return {
                    "technique_id": t_id,
                    "technique_name": matching_rule["technique_name"],
                    "techniques": [primary],
                    "primary": primary,
                    "confidence": learned_pred.confidence,
                    "mapping_source": "learned_classifier",
                }
        except Exception:
            pass  # Fallback to rule-based mapper

    title = str(finding.get("title", "")).lower()
    source = str(finding.get("source", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()
    blob = f"{title} {source} {evidence}"

    matched = []
    for rule in TECHNIQUE_RULES:
        if rule["match_condition"](finding):
            matched.append({
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic_id": rule["tactic_id"],
                "tactic_name": rule["tactic_name"],
                "url": rule["url"],
                "mitigation": rule["mitigation"],
            })

    import re
    has_port = bool(re.search(r"\bports?\b", blob) or "port_scan" in source)
    has_active_scan = bool(re.search(r"\b(active\s*scan|port_scan|nmap)\b", blob))

    if matched:
        primary_id = matched[0]["technique_id"]
        primary_name = matched[0]["technique_name"]
    elif has_port:
        primary_id = "T1595" if has_active_scan else "T1190"
        primary_name = "Active Scanning (Port / Ingress)" if primary_id == "T1595" else "Exploit Public-Facing Application"
    else:
        primary_id = "T1190"
        primary_name = "Exploit Public-Facing Application"

    return {
        "technique_id": primary_id,
        "technique_name": primary_name,
        "techniques": matched,
        "primary": matched[0] if matched else {
            "technique_id": primary_id,
            "technique_name": primary_name,
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "url": f"https://attack.mitre.org/techniques/{primary_id}/",
            "mitigation": "Patch vulnerable public software and apply WAF filtering."
        }
    }


def generate_attack_walkthrough(finding: dict[str, Any], target: str = "example.com") -> dict[str, Any]:
    """Generate illustrative 4-phase attack simulation walkthrough for UI."""
    title = finding.get("title", "Finding")
    phases = [
        {"phase": "Phase 1: Reconnaissance", "action": f"Adversary queries public perimeter of {target} and observes {title}."},
        {"phase": "Phase 2: Weaponization", "action": "Adversary correlates publicly known exploit vectors or missing defense controls."},
        {"phase": "Phase 3: Delivery & Exploitation", "action": "Adversary issues crafted requests targeting exposed configuration or unpatched endpoint."},
        {"phase": "Phase 4: Mitigation & Hardening", "action": finding.get("suggested_action", "Apply defensive configuration patch.")}
    ]
    return {
        "target": target,
        "finding": title,
        "phases": phases,
        "simulation_disclaimer": "ILLUSTRATIVE ONLY: This walkthrough models a theoretical adversary kill chain based on MITRE ATT&CK techniques. No exploit was executed against the target."
    }


