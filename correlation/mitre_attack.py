"""
AEGIS-AI: MITRE ATT&CK Matrix Correlation & Adversary Technique Mapping.
Maps observed defensive findings to real MITRE Enterprise ATT&CK tactics, techniques, and IDs.
Generates an illustrative defense-oriented attack walkthrough (never claimed as live exploit execution).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


MITRE_TECHNIQUES = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing service or application."
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "description": "Adversaries may execute active reconnaissance scans against the perimeter to identify open network sockets."
    },
    "T1592": {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1592/",
        "description": "Adversaries may inspect HTTP Server banners and TLS certificates to enumerate target software runtimes."
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing / Email Spoofing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "description": "Missing SPF or DMARC records allow adversaries to send spoofed emails impersonating the target organization."
    },
    "T1195": {
        "id": "T1195",
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1195/",
        "description": "Adversaries exploit vulnerabilities in upstream open-source packages or third-party dependencies."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Vulnerabilities allowing code injection or command execution on the host runtime."
    },
    "T1539": {
        "id": "T1539",
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1539/",
        "description": "Cookies missing HttpOnly or Secure flags permit JavaScript reading or transmission in plaintext."
    }
}


def map_finding_to_mitre(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Map an individual finding to its primary MITRE ATT&CK technique."""
    title = str(finding.get("title", "")).lower()
    desc = str(finding.get("description", "")).lower()
    source = str(finding.get("source", "")).lower()
    cves = finding.get("related_cves", [])

    blob = f"{title} {desc} {source}"

    if "spf" in blob or "dmarc" in blob or "email" in blob:
        tech = MITRE_TECHNIQUES["T1566"]
    elif "cookie" in blob:
        tech = MITRE_TECHNIQUES["T1539"]
    elif "banner" in blob or "server header" in blob or "tls" in blob or "version" in blob:
        tech = MITRE_TECHNIQUES["T1592"]
    elif "port" in blob or "active" in source:
        tech = MITRE_TECHNIQUES["T1595"]
    elif cves or "cve" in blob or "component" in blob or "dependency" in blob:
        if "injection" in blob or "rce" in blob or "exec" in blob:
            tech = MITRE_TECHNIQUES["T1059"]
        elif "package" in blob or "library" in blob or "osv" in blob:
            tech = MITRE_TECHNIQUES["T1195"]
        else:
            tech = MITRE_TECHNIQUES["T1190"]
    else:
        tech = MITRE_TECHNIQUES["T1190"]

    return {
        "technique_id": tech["id"],
        "technique_name": tech["name"],
        "tactic": tech["tactic"],
        "url": tech["url"],
        "summary": tech["description"]
    }


def generate_attack_walkthrough(finding: Dict[str, Any], target: str) -> Dict[str, Any]:
    """
    Generate an illustrative 4-phase attack simulation and defense walkthrough.
    Explicitly labeled as an illustrative conceptual model; does NOT execute real attacks.
    """
    mitre_info = map_finding_to_mitre(finding)
    title = finding.get("title", "Perimeter Weakness")
    tech_id = mitre_info["technique_id"]
    tech_name = mitre_info["technique_name"]

    phases = [
        {
            "phase": "Phase 1: Reconnaissance & Discovery",
            "tactic": "Reconnaissance (TA0043)",
            "technique": f"{tech_id}: {tech_name}",
            "description": f"Adversary queries public DNS and HTTP banners for {target}, identifying the exposure ({title}).",
            "evidence": finding.get("evidence", f"Detected on {target} perimeter.")
        },
        {
            "phase": "Phase 2: Weaponization & Ingress Trigger",
            "tactic": mitre_info["tactic"],
            "technique": f"{tech_id}: {tech_name}",
            "description": f"Adversary constructs malicious payload targeting {tech_id} to test ingress responsiveness.",
            "evidence": f"Target endpoint responds without active WAF drop or filtering."
        },
        {
            "phase": "Phase 3: Impact & Post-Access Consequence",
            "tactic": "Impact (TA0040) / Lateral Movement (TA0008)",
            "technique": "T1499 / T1021",
            "description": f"Unmitigated exploitation allows session compromise, service disruption, or unauthorized pivoting.",
            "evidence": f"Severity: {finding.get('severity', 'Medium')}, EPSS Probability: {finding.get('epss_probability', 0.005)}"
        },
        {
            "phase": "Phase 4: Defensive Remediation & Hardening",
            "tactic": "Mitigation (M1038 / M1050)",
            "technique": "Defensive Virtual Patching",
            "description": f"Apply AEGIS defensive rule to neutralize the attack vector immediately.",
            "evidence": finding.get("remediation", "Deploy security header or WAF drop rule.")
        }
    ]

    return {
        "finding_title": title,
        "target": target,
        "mitre_technique": mitre_info,
        "simulation_disclaimer": "ILLUSTRATIVE CONCEPTUAL MODEL ONLY: No offensive payloads were transmitted against the target.",
        "phases": phases
    }
