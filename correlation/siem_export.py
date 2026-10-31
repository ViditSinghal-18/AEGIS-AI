"""
AEGIS-AI: SIEM Exporter & Webhook Alert Dispatcher.
Formats scan reports into:
- Common Event Format (CEF) for Splunk / ArcSight / QRadar
- Elastic Common Schema (ECS) JSON Lines for Elasticsearch / Logstash
- Outbound Webhook Alerts (Slack / Discord / Teams / Generic) with strict SSRF protection.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from discovery.safe_fetch import safe_fetch, SafeFetchError


def generate_cef_export(report: Dict[str, Any]) -> str:
    """Generate HP ArcSight / Splunk Common Event Format (CEF) string."""
    target = report.get("target", "unknown")
    findings = report.get("findings", [])
    now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    cef_lines = []
    for idx, f in enumerate(findings, 1):
        sev_str = str(f.get("severity", "Info")).lower()
        sev_num = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}.get(sev_str, 1)
        title = str(f.get("title", "Perimeter Finding")).replace("|", "\\|")
        cves = ",".join(f.get("related_cves", [])) or "None"
        risk_score = f.get("contextual_risk_score", f.get("risk_score", 0.0))

        line = (
            f"CEF:0|AEGIS-AI|AttackSurfaceDefense|1.0|FINDING-{idx}|{title}|{sev_num}|"
            f"dst={target} cs1Label=CVEs cs1={cves} cn1Label=RiskScore cn1={risk_score} "
            f"msg={str(f.get('description', f.get('why_it_matters', ''))[:120])}"
        )
        cef_lines.append(line)

    return "\n".join(cef_lines)


def generate_ecs_export(report: Dict[str, Any]) -> str:
    """Generate Elastic Common Schema (ECS) compatible JSON Lines."""
    target = report.get("target", "unknown")
    findings = report.get("findings", [])
    now_iso = datetime.now(timezone.utc).isoformat()

    ecs_events = []
    for idx, f in enumerate(findings, 1):
        event = {
            "@timestamp": now_iso,
            "event": {
                "kind": "alert",
                "category": ["vulnerability", "threat"],
                "type": ["info"],
                "severity": str(f.get("severity", "Info")).upper(),
            },
            "host": {
                "name": target,
                "ip": report.get("resolved_ip")
            },
            "vulnerability": {
                "id": f"AEGIS-{idx}",
                "category": f.get("source", "perimeter_recon"),
                "description": f.get("description", f.get("why_it_matters", "")),
                "recommendation": f.get("remediation", f.get("suggested_action", "")),
                "cve": f.get("related_cves", []),
            },
            "risk": {
                "score": f.get("contextual_risk_score", f.get("risk_score", 0.0)),
                "epss_probability": f.get("epss_probability", 0.0)
            }
        }
        ecs_events.append(json.dumps(event))

    return "\n".join(ecs_events)


def send_webhook_alert(webhook_url: str, report: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Dispatch a security alert payload to a remote webhook URL (Slack / Teams / Discord).
    Enforces HTTPS and uses safe_fetch to prevent internal SSRF.
    """
    url_clean = webhook_url.strip()
    parsed = urlparse(url_clean)
    if parsed.scheme.lower() != "https":
        return False, "Webhook URL must strictly use HTTPS."
    if not parsed.hostname:
        return False, "Invalid webhook URL: missing hostname."

    target = report.get("target", "Unknown")
    findings = report.get("findings", [])
    high_crit = [f for f in findings if str(f.get("severity", "")).title() in ["Critical", "High"]]

    payload = {
        "text": f"🛡️ *AEGIS-AI Attack Surface Alert: `{target}`*",
        "attachments": [
            {
                "color": "#ef4444" if high_crit else "#3b82f6",
                "title": f"Security Assessment Summary: {len(findings)} Total Findings ({len(high_crit)} Critical/High)",
                "fields": [
                    {"title": "Target", "value": target, "short": True},
                    {"title": "Scan Mode", "value": report.get("mode", "PASSIVE OSINT"), "short": True},
                    {"title": "Compliance Readiness", "value": f"{report.get('compliance_score', 'N/A')}%", "short": True},
                    {"title": "Top Finding", "value": (findings[0].get("title") if findings else "None"), "short": False}
                ],
                "footer": "AEGIS-AI Autonomous Defense Platform",
                "ts": int(datetime.now(timezone.utc).timestamp())
            }
        ]
    }

    try:
        resp = safe_fetch(
            url_clean,
            method="POST",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5.0
        )
        if resp.status_code in [200, 201, 204]:
            return True, f"Webhook delivered successfully (HTTP {resp.status_code})."
        return False, f"Webhook delivery returned HTTP {resp.status_code}."
    except SafeFetchError as exc:
        return False, f"Webhook blocked by security policy: {exc}"
    except Exception as exc:
        return False, f"Webhook error: {exc}"
