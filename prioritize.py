"""
AEGIS-AI: Honest Mathematical Risk Prioritisation Engine.
Ranks security findings based on mathematically grounded transparent scoring:
Exposure Score = (S_CVSS * w1) + (S_EPSS * w2) + (S_Exposure * w3) + (S_Crit * w4)

STRICT HONESTY & DEFENSE PRINCIPLES:
- Zero fake APT groups or fabricated Russian/Chinese threat pins.
- True EPSS probability from FIRST.org API.
- True CISA KEV catalog match.
- Reachability explicitly flagged as 'unknown (no source provided)' unless local repository is analyzed.
- Real compliance evaluation across NIST CSF 2.0, OWASP Top 10, PCI-DSS, ISO 27001, and SOC 2.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import config
from correlation.enrich import enrich_findings
from correlation.mitre_attack import map_finding_to_mitre, generate_attack_walkthrough
from correlation.compliance import calculate_compliance
from storage import generate_cyclonedx_sbom, write_json, save_run_history
from ast_analyzer import analyze_source_tree, evaluate_component_reachability


# Mathematical Weights for Contextual Blending (Sum = 1.0)
W_CVSS = 0.35
W_EPSS = 0.30
W_EXPOSURE = 0.25
W_CRIT = 0.10


def prioritize_findings(
    findings: List[Dict[str, Any]],
    discovery_data: Dict[str, Any],
    source_path: Optional[str] = None,
    business_criticality: float = 1.0
) -> Dict[str, Any]:
    """
    Apply mathematically honest contextual risk scoring across all correlated findings.
    """
    target = discovery_data.get("target", "unknown")
    start_time = time.time()

    # 1. Enrich with real-world exploitability (CISA KEV + FIRST EPSS)
    enriched = enrich_findings(findings)

    # 2. Check network exposure & WAF status from discovery
    waf_data = discovery_data.get("waf", discovery_data.get("http", {}).get("waf_detection", {}))
    is_behind_waf = bool(waf_data.get("detected", False))
    discovered_assets = discovery_data.get("discovered_assets", [])
    open_ports = [a.get("port") for a in discovered_assets if a.get("state") == "open"]
    has_open_ports = len(open_ports) > 0

    # Determine S_Exposure factor
    if has_open_ports and not is_behind_waf:
        s_exposure = 1.0  # Directly exposed perimeter socket
        exposure_desc = f"Directly Exposed (Open Ports: {open_ports}, No WAF)"
    elif is_behind_waf:
        s_exposure = 0.6  # Filtered by WAF/CDN layer
        exposure_desc = f"Perimeter Shielded by {', '.join(waf_data.get('providers', ['WAF/CDN']))}"
    else:
        s_exposure = 0.3  # Passive OSINT / Internal / Indirect
        exposure_desc = "Passive OSINT Discovery / Standard Web Ingress"

    # 3. Source code AST reachability analysis (if source provided)
    source_analysis = analyze_source_tree(source_path) if source_path else None

    # 4. Score each finding
    prioritized_list = []
    for item in enriched:
        f = dict(item)

        # S_CVSS: normalized 0.0 - 1.0
        cvss_raw = float(f.get("cvss_score", 5.0))
        s_cvss = max(0.0, min(1.0, cvss_raw / 10.0))

        # S_EPSS: raw probability 0.0 - 1.0
        s_epss = float(f.get("epss_probability", 0.005))
        # Boost for CISA KEV listing
        if f.get("in_cisa_kev"):
            s_epss = max(s_epss, 0.75)

        # S_Crit: normalized business criticality 0.0 - 1.0
        s_crit = max(0.1, min(1.0, float(business_criticality)))

        # S_Exposure
        s_exp = s_exposure

        # Calculate base blended exposure score (0.0 - 1.0)
        exposure_score = (s_cvss * W_CVSS) + (s_epss * W_EPSS) + (s_exp * W_EXPOSURE) + (s_crit * W_CRIT)

        # S_Code reachability modulation
        affected_comp = f.get("affected_component")
        if affected_comp:
            reach_info = evaluate_component_reachability(affected_comp, source_analysis)
            s_code = reach_info["reachability_factor"]
            f["reachability_verdict"] = reach_info["reachability_verdict"]
            f["reachability_evidence"] = reach_info["evidence"]
            exposure_score *= s_code
        else:
            f["reachability_verdict"] = "not applicable (perimeter configuration finding)"
            f["reachability_evidence"] = "Finding relates to network/protocol configuration rather than application code."

        # Scale final contextual risk score to 1.0 - 10.0
        risk_score = round(max(1.0, min(10.0, exposure_score * 10.0)), 1)
        f["contextual_risk_score"] = risk_score
        f["exposure_context"] = exposure_desc

        # Priority label
        if risk_score >= 8.5 or f.get("in_cisa_kev"):
            priority_label = "P1 - Critical"
        elif risk_score >= 6.5:
            priority_label = "P2 - High"
        elif risk_score >= 4.0:
            priority_label = "P3 - Medium"
        else:
            priority_label = "P4 - Low"

        f["priority_level"] = priority_label

        # Map MITRE ATT&CK technique
        f["mitre_attack"] = map_finding_to_mitre(f)

        # Transparent Explainable AI (XAI) Formula breakdown
        f["xai_formula"] = {
            "formula": "Score = ((S_CVSS * 0.35) + (S_EPSS * 0.30) + (S_Exposure * 0.25) + (S_Crit * 0.10)) * 10",
            "s_cvss": round(s_cvss, 3),
            "s_epss": round(s_epss, 4),
            "s_exposure": round(s_exp, 2),
            "s_crit": round(s_crit, 2),
            "final_score": risk_score
        }

        prioritized_list.append(f)

    # Sort descending by contextual risk score
    prioritized_list.sort(key=lambda x: x["contextual_risk_score"], reverse=True)

    # Assign rank numbers
    for idx, p in enumerate(prioritized_list, 1):
        p["rank"] = idx

    # 5. Calculate Real Governance & Compliance
    compliance_gov = calculate_compliance(prioritized_list, is_port_open=has_open_ports)

    # 6. Generate CycloneDX SBOM v1.5 JSON
    discovered_components = []
    seen_comps = set()
    for f in prioritized_list:
        comp = f.get("affected_component")
        if comp and comp not in seen_comps:
            seen_comps.add(comp)
            discovered_components.append({
                "name": comp,
                "version": "detected",
                "cve_aliases": f.get("related_cves", [])
            })
    cyclonedx_sbom = generate_cyclonedx_sbom(discovered_components, target=target)

    # 7. Generate Illustrative Attack Walkthrough for top finding
    top_walkthrough = None
    if prioritized_list:
        top_walkthrough = generate_attack_walkthrough(prioritized_list[0], target=target)

    duration = round(time.time() - start_time, 2)

    report = {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "mode": discovery_data.get("mode", "PASSIVE OSINT"),
        "total_findings": len(prioritized_list),
        "critical_count": sum(1 for f in prioritized_list if f["priority_level"] == "P1 - Critical"),
        "high_count": sum(1 for f in prioritized_list if f["priority_level"] == "P2 - High"),
        "medium_count": sum(1 for f in prioritized_list if f["priority_level"] == "P3 - Medium"),
        "low_count": sum(1 for f in prioritized_list if f["priority_level"] == "P4 - Low"),
        "findings": prioritized_list,
        "prioritized_findings": prioritized_list,  # Backwards compatibility
        "compliance_governance": compliance_gov,
        "cyclonedx_sbom": cyclonedx_sbom,
        "attack_simulator": top_walkthrough,
        "radar_comparison": {
            "cvss_average": round(sum(f.get("cvss_score", 5.0) for f in prioritized_list) / max(1, len(prioritized_list)), 1),
            "contextual_average": round(sum(f["contextual_risk_score"] for f in prioritized_list) / max(1, len(prioritized_list)), 1),
            "epss_max": round(max([f.get("epss_probability", 0.0) for f in prioritized_list] or [0.0]), 4),
            "cisa_kev_flagged_count": sum(1 for f in prioritized_list if f.get("in_cisa_kev"))
        }
    }

    # Save to storage & archive history
    try:
        write_json("prioritized_report.json", report, target=target)
        save_run_history(target, report)
    except Exception:
        pass

    return report
