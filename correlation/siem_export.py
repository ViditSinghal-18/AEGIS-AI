"""
SIEM Exporter & Webhook Alert Dispatcher.
Formats reports into Common Event Format (CEF), Elastic Common Schema (ECS),
and dispatches webhook payloads (Slack / Discord / Teams).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from discovery.safe_fetch import SafeFetchError, safe_fetch


def generate_cef_export(report: dict[str, Any]) -> str:
    """Generate HP ArcSight / Splunk Common Event Format (CEF) string."""
    target = report.get("target", "unknown")
    findings = report.get("findings", [])
    now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    cef_lines = []
    for f in findings:
        sev = str(f.get("severity", "Info")).lower()
        sev_num = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}.get(sev, 1)
        rank = f.get("rank", 99)
        title = f.get("title", "Finding").replace("|", "\\|")
        cves = ",".join(f.get("related_cves", [])) or "None"
        exploit = f.get("exploitability", "-").replace("=", "\\=")

        line = (
            f"CEF:0|AttackSurfaceSOC|DefenseScanner|1.0|FINDING-{rank}|{title}|{sev_num}|"
            f"dst={target} cs1Label=CVEs cs1={cves} cs2Label=Exploitability cs2={exploit} "
            f"msg={f.get('why_it_matters', '')[:100]}"
        )
        cef_lines.append(line)
    return "\n".join(cef_lines)


def generate_ecs_export(report: dict[str, Any]) -> str:
    """Generate Elastic Common Schema (ECS) compatible JSON Lines."""
    target = report.get("target", "unknown")
    findings = report.get("findings", [])
    now_iso = datetime.now(timezone.utc).isoformat()

    ecs_events = []
    for f in findings:
        event = {
            "@timestamp": now_iso,
            "event": {
                "kind": "vulnerability",
                "category": ["threat"],
                "type": ["info"],
                "severity": str(f.get("severity", "Info")).upper(),
            },
            "host": {
                "name": target,
            },
            "vulnerability": {
                "id": f"FINDING-{f.get('rank', 99)}",
                "category": f.get("source", "configuration"),
                "description": f.get("why_it_matters", ""),
                "recommendation": f.get("suggested_action", ""),
                "cve": f.get("related_cves", []),
            },
            "labels": {
                "exploitability": f.get("exploitability", ""),
            }
        }
        ecs_events.append(json.dumps(event))
    return "\n".join(ecs_events)


def send_webhook_alert(webhook_url: str, report: dict[str, Any]) -> tuple[bool, str]:
    """Dispatch a formatted webhook alert to Slack / Discord / Generic endpoint."""
    parsed = urlparse(webhook_url.strip())
    if parsed.scheme.lower() != "https":
        return False, "Webhook URL must use HTTPS."
    if not parsed.hostname:
        return False, "Webhook URL is missing a hostname."

    target = report.get("target", "Unknown")
    findings = report.get("findings", [])
    high_crit = [f for f in findings if str(f.get("severity", "")).title() in ["Critical", "High"]]

    payload = {
        "text": f"🚨 *Defensive SOC Alert: Attack Surface Assessment for `{target}`*",
        "attachments": [
            {
                "color": "#ef4444" if high_crit else "#3b82f6",
                "title": f"Security Assessment Summary — {len(findings)} Total Findings",
                "fields": [
                    {"title": "Target", "value": target, "short": True},
                    {"title": "Critical / High Risks", "value": str(len(high_crit)), "short": True},
                    {"title": "Top Risk", "value": (report.get("top_risks") or ["None"])[0], "short": False},
                ],
                "footer": "AI Attack Surface Correlation & SOC Engine",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        response = safe_fetch(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "AttackSurfaceSOC/1.0"},
            method="POST",
            max_bytes=64 * 1024,
            timeout=8,
        )
        if 200 <= response.status_code < 300:
            return True, f"Successfully delivered alert payload (HTTP {response.status_code})"
        return False, f"Server responded with HTTP {response.status_code}"
    except SafeFetchError as ex:
        return False, f"Webhook URL blocked by outbound safety policy: {ex}"
    except Exception as ex:
        return False, f"Webhook delivery failed: {str(ex)}"
