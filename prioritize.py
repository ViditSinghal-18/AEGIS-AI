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
from ast_analyzer import (
    analyze_source_tree,
    evaluate_component_reachability,
    evaluate_cve_function_reachability,
)
from correlation.advisory_consistency import check_advisory_consistency
from correlation.backport_detector import detect_backport
from scoring.ssvc import evaluate_ssvc
from scoring.uncertainty import compute_risk_interval
from scoring.fair_loss import simulate_fair_loss, simulate_portfolio_fair_loss
from scoring.calibrate_weights import load_calibrated_weights


def get_active_weights() -> tuple[float, float, float, float, str]:
    """Retrieve scoring weights based on configured source (default vs calibrated)."""
    weights_source = getattr(config, "SCORING_WEIGHTS_SOURCE", "default").lower()
    if weights_source == "calibrated":
        cal_weights = load_calibrated_weights()
        return (
            cal_weights.get("cvss", 0.35),
            cal_weights.get("epss", 0.30),
            cal_weights.get("exposure", 0.20),
            cal_weights.get("criticality", 0.15),
            "calibrated",
        )
    return (
        getattr(config, "WEIGHT_CVSS", 0.35),
        getattr(config, "WEIGHT_EPSS", 0.30),
        getattr(config, "WEIGHT_EXPOSURE", 0.20),
        getattr(config, "WEIGHT_CRITICALITY", 0.15),
        "default",
    )


W_CVSS = getattr(config, "WEIGHT_CVSS", 0.35)
W_EPSS = getattr(config, "WEIGHT_EPSS", 0.30)
W_EXPOSURE = getattr(config, "WEIGHT_EXPOSURE", 0.20)
W_CRIT = getattr(config, "WEIGHT_CRITICALITY", 0.15)


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
    w_cvss, w_epss, w_exp, w_crit, weights_source = get_active_weights()
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
        s_exposure_val = s_exposure

        # Calculate base blended exposure score (0.0 - 1.0)
        exposure_score = (s_cvss * w_cvss) + (s_epss * w_epss) + (s_exposure_val * w_exp) + (s_crit * w_crit)

        # Phase 2: Function-Level Reachability (Ponta et al. 2018 / Eclipse Steady)
        cve_list = f.get("related_cves") or []
        primary_cve = cve_list[0] if cve_list else None
        affected_comp = f.get("affected_component") or f.get("product")

        if primary_cve and source_analysis and source_analysis.get("source_provided"):
            reach_info = evaluate_cve_function_reachability(
                cve_id=primary_cve,
                package_name=affected_comp or "",
                source_analysis=source_analysis,
            )
            s_code = reach_info["reachability_factor"]
            f["reachability_verdict"] = reach_info["verdict"]
            f["reachability_factor"] = s_code
            f["reachability_evidence"] = reach_info["evidence"]
            f["vulnerable_symbols"] = reach_info.get("vulnerable_symbols", [])
            f["matched_symbols"] = reach_info.get("matched_symbols", [])
            exposure_score *= s_code
        elif affected_comp and source_analysis and source_analysis.get("source_provided"):
            reach_info = evaluate_component_reachability(affected_comp, source_analysis)
            s_code = reach_info["reachability_factor"]
            f["reachability_verdict"] = reach_info["reachability_verdict"]
            f["reachability_factor"] = s_code
            f["reachability_evidence"] = reach_info["evidence"]
            exposure_score *= s_code
        elif not source_analysis or not source_analysis.get("source_provided"):
            s_code = 1.0
            if affected_comp or primary_cve:
                f["reachability_verdict"] = "unknown (no source provided)"
                f["reachability_factor"] = 1.0
                f["reachability_evidence"] = "Remote target scanned without source code repository. Function-level execution path cannot be verified."
            else:
                f["reachability_verdict"] = "not applicable (perimeter configuration finding)"
                f["reachability_factor"] = 1.0
                f["reachability_evidence"] = "Finding relates to network/protocol configuration rather than application code."
        else:
            s_code = 1.0
            f["reachability_verdict"] = "not applicable (perimeter configuration finding)"
            f["reachability_factor"] = 1.0
            f["reachability_evidence"] = "Finding relates to network/protocol configuration rather than application code."

        # Phase 2: Backport-aware matching (Linux distros: Ubuntu, Debian, RHEL)
        version_str = str(f.get("version") or f.get("affected_version") or "")
        banner_str = str(f.get("banner") or discovery_data.get("http", {}).get("server_banner") or "")
        bp_verdict = detect_backport(product=affected_comp or "", version_string=version_str, banner=banner_str)
        if bp_verdict.possibly_backported:
            f["possibly_backported"] = True
            f["backport_verdict"] = bp_verdict.to_dict()
            f["confidence"] = "low"
            f["confidence_reason"] = bp_verdict.explanation
        else:
            f["possibly_backported"] = False
            f["backport_verdict"] = bp_verdict.to_dict()

        # Phase 2: Advisory consistency check (Dong et al. 2019)
        if primary_cve:
            adv_res = check_advisory_consistency(primary_cve)
            f["advisory_consistency"] = adv_res.to_dict()
            f["advisory_confidence"] = adv_res.confidence
            f["advisory_reason"] = adv_res.reason
            if adv_res.confidence == "low":
                f["confidence"] = "low"
                f["confidence_reason"] = adv_res.reason
                f["advisory_discrepancy"] = True
            elif adv_res.confidence == "high" and f.get("confidence") not in ["low", "medium"]:
                f["confidence"] = "high"

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

        # Scientifically Defensible Decision & Uncertainty Additions (Phase 1)
        ssvc_eval = evaluate_ssvc(
            in_cisa_kev=bool(f.get("in_cisa_kev")),
            epss_prob=s_epss,
            exposure_factor=s_exposure_val,
            is_behind_waf=is_behind_waf,
            is_network_automatable=True,
            business_criticality=s_crit * 10.0,
            cvss_base_score=cvss_raw,
        )
        f["ssvc"] = ssvc_eval
        f["ssvc_decision"] = ssvc_eval["decision"]

        f["risk_interval_90"] = compute_risk_interval(
            point_score=risk_score,
            finding_context=f,
        )

        f["fair_expected_loss"] = simulate_fair_loss(
            epss_prob=s_epss,
            exposure_factor=s_exposure_val,
            business_criticality=s_crit * 10.0,
        )

        # Transparent Explainable AI (XAI) Formula breakdown
        f["xai_formula"] = {
            "formula": f"Score = (((S_CVSS * {w_cvss:.2f}) + (S_EPSS * {w_epss:.2f}) + (S_Exposure * {w_exp:.2f}) + (S_Crit * {w_crit:.2f})) * {s_code:.2f}) * 10",
            "weights_source": weights_source,
            "weights": {
                "cvss": round(w_cvss, 3),
                "epss": round(w_epss, 3),
                "exposure": round(w_exp, 3),
                "criticality": round(w_crit, 3),
            },
            "s_cvss": round(s_cvss, 3),
            "s_epss": round(s_epss, 4),
            "s_exposure": round(s_exposure_val, 2),
            "s_crit": round(s_crit, 2),
            "s_code": round(s_code, 2),
            "reachability_verdict": f.get("reachability_verdict"),
            "backport_status": "possibly_backported" if f.get("possibly_backported") else "standard",
            "advisory_confidence": f.get("advisory_confidence", "n/a"),
            "final_score": risk_score,
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
        },
        "portfolio_fair_loss": simulate_portfolio_fair_loss(prioritized_list),
        "ssvc_summary": {
            "Act": sum(1 for f in prioritized_list if f.get("ssvc_decision") == "Act"),
            "Attend": sum(1 for f in prioritized_list if f.get("ssvc_decision") == "Attend"),
            "Track*": sum(1 for f in prioritized_list if f.get("ssvc_decision") == "Track*"),
            "Track": sum(1 for f in prioritized_list if f.get("ssvc_decision") == "Track"),
        },
        "scoring_metadata": {
            "weights_source": weights_source,
            "active_weights": {
                "cvss": round(w_cvss, 3),
                "epss": round(w_epss, 3),
                "exposure": round(w_exp, 3),
                "criticality": round(w_crit, 3),
            },
        }
    }

    # Save to storage & archive history
    try:
        write_json("prioritized_report.json", report, target=target)
        save_run_history(target, report)
    except Exception:
        pass

    return report


if __name__ == "__main__":
    import sys
    from storage import read_json
    target_arg = sys.argv[1].strip() if len(sys.argv) > 1 and sys.argv[1].strip() else "localhost"
    try:
        disc = read_json("discovery_report.json", target=target_arg)
    except Exception:
        disc = {"target": target_arg, "discovered_assets": []}
    try:
        corr = read_json("correlated_findings.json", target=target_arg)
        findings = corr.get("findings", []) if isinstance(corr, dict) else (corr if isinstance(corr, list) else [])
    except Exception:
        findings = []
    rep = prioritize_findings(findings, disc)
    print(f"[+] Prioritized {len(rep.get('findings', []))} findings for {target_arg}")

