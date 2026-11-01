"""
AEGIS-AI Vulnerability Correlation & Intelligence Package.
"""
from __future__ import annotations

from correlation.correlate import correlate
from correlation.compliance import map_compliance, calculate_compliance
from correlation.mitre_attack import (
    map_findings_to_mitre,
    map_finding_to_mitre,
    generate_attack_walkthrough,
)
from correlation.enrich import enrich_findings, enrich_cves
from correlation.nvd_lookup import (
    lookup_cves,
    query_nvd_by_cve,
    query_osv_package,
)
from correlation.siem_export import (
    generate_cef_export,
    generate_ecs_export,
    send_webhook_alert,
)

__all__ = [
    "correlate",
    "map_compliance",
    "calculate_compliance",
    "map_findings_to_mitre",
    "map_finding_to_mitre",
    "generate_attack_walkthrough",
    "enrich_findings",
    "enrich_cves",
    "lookup_cves",
    "query_nvd_by_cve",
    "query_osv_package",
    "generate_cef_export",
    "generate_ecs_export",
    "send_webhook_alert",
]
