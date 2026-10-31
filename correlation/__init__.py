"""
AEGIS-AI Correlation Package.
Provides vulnerability lookup, threat enrichment (CISA KEV / EPSS),
MITRE ATT&CK mapping, evidence-based compliance evaluation, and SIEM exports.
"""

from correlation.nvd_lookup import query_nvd_by_cve, query_osv_package
from correlation.enrich import load_cisa_kev_catalog, fetch_epss_scores, enrich_findings
from correlation.mitre_attack import map_finding_to_mitre, generate_attack_walkthrough
from correlation.compliance import calculate_compliance
from correlation.siem_export import generate_cef_export, generate_ecs_export, send_webhook_alert

__all__ = [
    "query_nvd_by_cve",
    "query_osv_package",
    "load_cisa_kev_catalog",
    "fetch_epss_scores",
    "enrich_findings",
    "map_finding_to_mitre",
    "generate_attack_walkthrough",
    "calculate_compliance",
    "generate_cef_export",
    "generate_ecs_export",
    "send_webhook_alert"
]
