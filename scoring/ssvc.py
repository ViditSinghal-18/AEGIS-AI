"""
AEGIS-AI: Stakeholder-Specific Vulnerability Categorization (SSVC).

Inspired by:
- Spring, Hatlebrekke, & Houle (2019), "Prioritizing Vulnerability Response with a
  Stakeholder-Specific Vulnerability Categorization", CMU/SEI-2019-TR-005.
  (Flag: verify before publishing)
- CISA SSVC v2.0 Decision Guide for Deployer Organizations.

Outputs one of four operational decisions:
- Track: Standard maintenance cycle remediation.
- Track*: Elevated monitoring; watch for weaponization or exposure changes.
- Attend: Out-of-band or expedited patch schedule (< 14 days).
- Act: Immediate emergency out-of-band response (< 24-48 hours).
"""

from __future__ import annotations

from typing import Any, Dict


def evaluate_ssvc(
    in_cisa_kev: bool,
    epss_prob: float,
    exposure_factor: float,
    is_behind_waf: bool = False,
    is_network_automatable: bool = True,
    business_criticality: float = 7.5,
    cvss_base_score: float = 5.0,
) -> Dict[str, Any]:
    """
    Evaluate Stakeholder-Specific Vulnerability Categorization (SSVC) decision.

    Args:
        in_cisa_kev: Whether vulnerability is cataloged in CISA KEV (BOD 22-01).
        epss_prob: FIRST.org EPSS exploit weaponization probability [0.0, 1.0].
        exposure_factor: Environmental network reachability factor [0.0, 1.0].
        is_behind_waf: Whether perimeter is protected by WAF/CDN layer.
        is_network_automatable: Whether flaw can be triggered remotely without authentication.
        business_criticality: Asset importance rating [1.0, 10.0].
        cvss_base_score: Base severity score [0.0, 10.0].

    Returns:
        Structured decision object with decision, decision_path, rationale, urgency.
    """
    # 1. Determine Exploitation Dimension
    if in_cisa_kev or epss_prob >= 0.50:
        exploitation = "Active"
    elif epss_prob >= 0.15:
        exploitation = "PoC"
    else:
        exploitation = "None"

    # 2. Determine Exposure Dimension
    if exposure_factor >= 0.8 and not is_behind_waf:
        exposure = "Open"
    elif exposure_factor >= 0.4 or is_behind_waf:
        exposure = "Controlled"
    else:
        exposure = "Small"

    # 3. Determine Automatable Dimension
    automatable = "Yes" if is_network_automatable else "No"

    # 4. Determine Mission Impact Dimension
    if business_criticality >= 8.0 or cvss_base_score >= 8.5:
        mission_impact = "Critical"
    elif business_criticality >= 5.0 or cvss_base_score >= 6.5:
        mission_impact = "High"
    else:
        mission_impact = "Low"

    # 5. Evaluate Decision Tree
    if exploitation == "Active":
        if exposure == "Open":
            decision = "Act"
            urgency = "Immediate emergency response (< 24-48 hours)"
            rationale = "Actively weaponized threat directly exposed on public ingress."
        elif exposure == "Controlled":
            if automatable == "Yes" and mission_impact in ["Critical", "High"]:
                decision = "Act"
                urgency = "Immediate emergency response (< 48 hours)"
                rationale = "Actively weaponized threat with automatable ingress path through perimeter controls."
            else:
                decision = "Attend"
                urgency = "Expedited patching (< 7 days)"
                rationale = "Active exploitation observed in the wild; shielded by controls or requires interaction."
        else:  # Small / Internal
            decision = "Attend" if mission_impact == "Critical" else "Track*"
            urgency = "Expedited review (< 14 days)" if decision == "Attend" else "Monitor for exposure drift"
            rationale = "Active threat exists in wild, but affected asset is internal or secondary."

    elif exploitation == "PoC":
        if exposure == "Open":
            if automatable == "Yes" or mission_impact in ["Critical", "High"]:
                decision = "Attend"
                urgency = "Expedited patching (< 14 days)"
                rationale = "Public weaponized PoC with direct perimeter ingress exposure."
            else:
                decision = "Track*"
                urgency = "Monitored standard cycle"
                rationale = "Public PoC available; requires non-automatable prerequisite."
        elif exposure == "Controlled":
            decision = "Attend" if mission_impact == "Critical" else "Track*"
            urgency = "Expedited patching (< 14 days)" if decision == "Attend" else "Monitor for weaponization escalation"
            rationale = "Public PoC exists; perimeter is fronted by WAF/CDN shield."
        else:
            decision = "Track"
            urgency = "Standard maintenance patch cycle"
            rationale = "Public PoC available, but target is internal or dead code."

    else:  # Exploitation == "None"
        if exposure == "Open" and automatable == "Yes" and mission_impact == "Critical":
            decision = "Track*"
            urgency = "Scheduled priority review"
            rationale = "No active exploit, but critical asset is directly exposed to untrusted traffic."
        elif exposure == "Small":
            decision = "Track"
            urgency = "Standard maintenance patch cycle"
            rationale = "No active exploit and minimal/internal network footprint."
        else:
            decision = "Track"
            urgency = "Standard maintenance patch cycle"
            rationale = "Standard vulnerability hygiene; no weaponization evidence detected."

    decision_path = (
        f"Exploitation={exploitation} -> Exposure={exposure} -> "
        f"Automatable={automatable} -> MissionImpact={mission_impact} -> {decision}"
    )

    return {
        "decision": decision,
        "ssvc_decision": decision,
        "decision_path": decision_path,
        "ssvc_path": decision_path,
        "rationale": rationale,
        "ssvc_rationale": rationale,
        "action_urgency": urgency,
        "ssvc_action_urgency": urgency,
        "exploitation": exploitation,
        "exposure": exposure,
        "automatable": automatable,
        "mission_impact": mission_impact,
        "ssvc_dimensions": {
            "exploitation": exploitation,
            "exposure": exposure,
            "automatable": automatable,
            "mission_impact": mission_impact,
        },
    }
