"""
AEGIS-AI: Persistent Storage, History Diffing & Multi-Format Exporter.
Handles:
- Storage abstraction: file backend in config.DATA_DIR (/tmp on Vercel) + memory fallback
- Per-target run history archiving and retrieval
- Historical report diffing (new, resolved, persisting findings)
- CSV export with CSV injection protection
- Standalone HTML CISO executive report
- CycloneDX v1.5 Software Bill of Materials (SBOM) generator
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
import re
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config
from correlation.siem_export import generate_cef_export, generate_ecs_export

_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_IN_MEMORY_STORE: Dict[str, Any] = {}


def target_data_dir(target: str) -> Path:
    """Return sanitized per-target data directory: data/<target>/."""
    safe = _UNSAFE_CHARS.sub("_", target).strip("._") or "unknown"
    d = config.DATA_DIR / safe
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def write_json(name: str, payload: Any, target: Optional[str] = None) -> Path:
    """Serialise payload to JSON with in-memory fallback on read-only environments."""
    base = target_data_dir(target) if target else config.DATA_DIR
    try:
        base.mkdir(parents=True, exist_ok=True)
        path = base / name
        if hasattr(payload, "to_dict"):
            data = payload.to_dict()
        elif hasattr(payload, "__dataclass_fields__"):
            data = asdict(payload)
        else:
            data = payload
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path
    except (OSError, Exception):
        # Fallback to in-memory store
        key = f"{target or 'root'}:{name}"
        _IN_MEMORY_STORE[key] = payload
        return Path(f"/memory/{key}")


def read_json(name: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Read a JSON file from target or root directory, with in-memory fallback."""
    key = f"{target or 'root'}:{name}"
    if key in _IN_MEMORY_STORE:
        return _IN_MEMORY_STORE[key]

    if target:
        path = target_data_dir(target) / name
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass

    path = config.DATA_DIR / name
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass

    raise FileNotFoundError(f"Missing {name} in {target or 'root'} storage.")


def save_run_history(target: str, report_data: Dict[str, Any]) -> str:
    """Save timestamped copy of scan report under data/<target>/history/."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"run_{ts}.json"
    h_dir = target_data_dir(target) / "history"
    try:
        h_dir.mkdir(parents=True, exist_ok=True)
        (h_dir / filename).write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    except OSError:
        _IN_MEMORY_STORE[f"{target}:history:{filename}"] = report_data
    return filename


def list_run_history(target: str) -> List[Dict[str, Any]]:
    """List historical scan reports for a target, newest to oldest."""
    h_dir = target_data_dir(target) / "history"
    results = []
    if h_dir.exists():
        try:
            for p in sorted(h_dir.glob("run_*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
                data = json.loads(p.read_text(encoding="utf-8"))
                results.append({
                    "filename": p.name,
                    "target": target,
                    "timestamp": data.get("scanned_at", data.get("timestamp", p.stem.replace("run_", ""))),
                    "findings_count": len(data.get("findings", data.get("prioritized_findings", []))),
                    "compliance_score": data.get("compliance_governance", {}).get("overall_readiness_score", "N/A"),
                })
        except Exception:
            pass

    # Check memory fallback
    mem_prefix = f"{target}:history:"
    for k, v in _IN_MEMORY_STORE.items():
        if k.startswith(mem_prefix):
            fname = k[len(mem_prefix):]
            if not any(r["filename"] == fname for r in results):
                results.append({
                    "filename": fname,
                    "target": target,
                    "timestamp": v.get("scanned_at", "in-memory"),
                    "findings_count": len(v.get("findings", [])),
                    "compliance_score": v.get("compliance_governance", {}).get("overall_readiness_score", "N/A"),
                })

    return results


def diff_reports(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare current scan findings against a previous scan on the same target.
    Returns: {"new": [...], "resolved": [...], "persisting": [...]}
    """
    def _key(f: Dict[str, Any]) -> str:
        t = str(f.get("title", "")).strip().lower()
        c = ",".join(sorted(f.get("related_cves", [])))
        return f"{t}::{c}"

    curr_list = current.get("findings", current.get("prioritized_findings", []))
    prev_list = previous.get("findings", previous.get("prioritized_findings", []))

    curr_map = {_key(f): f for f in curr_list}
    prev_map = {_key(f): f for f in prev_list}

    new_items = [f for k, f in curr_map.items() if k not in prev_map]
    resolved_items = [f for k, f in prev_map.items() if k not in curr_map]
    persisting_items = [f for k, f in curr_map.items() if k in prev_map]

    return {
        "new": new_items,
        "resolved": resolved_items,
        "persisting": persisting_items,
        "summary": {
            "new_count": len(new_items),
            "resolved_count": len(resolved_items),
            "persisting_count": len(persisting_items)
        }
    }


def _sanitize_csv_cell(val: Any) -> str:
    """Neutralize formula injection by prefixing '=', '+', '-', '@', '\\t', '\\r'."""
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def generate_csv_report(report: Dict[str, Any]) -> str:
    """Generate CSV export with strict CSV formula injection mitigation."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Priority", "Severity", "Finding Title", "Risk Score", "EPSS Prob", "Related CVEs",
        "Source", "Exposure Context", "Description", "Remediation"
    ])

    findings = report.get("findings", report.get("prioritized_findings", []))
    for f in findings:
        cves_str = ", ".join(f.get("related_cves", []))
        writer.writerow([
            _sanitize_csv_cell(f.get("priority_level", f.get("rank", ""))),
            _sanitize_csv_cell(f.get("severity", "")),
            _sanitize_csv_cell(f.get("title", "")),
            _sanitize_csv_cell(f.get("contextual_risk_score", f.get("risk_score", ""))),
            _sanitize_csv_cell(f.get("epss_probability", "")),
            _sanitize_csv_cell(cves_str),
            _sanitize_csv_cell(f.get("source", "")),
            _sanitize_csv_cell(f.get("exposure_context", "")),
            _sanitize_csv_cell(f.get("description", f.get("why_it_matters", ""))),
            _sanitize_csv_cell(f.get("remediation", f.get("suggested_action", ""))),
        ])

    return output.getvalue()


def generate_cyclonedx_sbom(
    components: Optional[List[Dict[str, Any]]] = None,
    target: str = "example.com"
) -> Dict[str, Any]:
    """
    Generate an honest CycloneDX v1.5 JSON Bill of Materials.
    If components are detected, includes purls, licenses, and CVEs.
    If no components are detected, outputs a valid CycloneDX v1.5 schema with empty component list
    and explanatory metadata (no fabricated express packages!).
    """
    bom_uuid = f"urn:uuid:{uuid.uuid4()}"
    ts = datetime.now(timezone.utc).isoformat()

    c_list = []
    dependencies = []

    if components:
        for c in components:
            name = c.get("name", "unknown")
            version = c.get("version", "unknown")
            ecosystem = c.get("ecosystem", "generic")
            purl = c.get("purl") or f"pkg:{ecosystem}/{name}@{version}"

            c_obj: Dict[str, Any] = {
                "type": c.get("type", "library"),
                "name": name,
                "version": version,
                "purl": purl,
            }
            if c.get("licenses"):
                c_obj["licenses"] = [{"license": {"id": lic}} for lic in c["licenses"]]
            if c.get("cve_aliases"):
                c_obj["vulnerabilities"] = c["cve_aliases"]

            c_list.append(c_obj)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_uuid,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [
                {
                    "vendor": "AEGIS-AI",
                    "name": "Autonomous Attack Surface Defense & SBOM Analyzer",
                    "version": "2.0"
                }
            ],
            "component": {
                "type": "application",
                "name": target,
                "version": "latest",
                "description": f"Attack surface target application: {target}"
            },
            "properties": [
                {
                    "name": "aegis:discovery_mode",
                    "value": "passive_osint" if not components else "source_analysis"
                },
                {
                    "name": "aegis:components_detected",
                    "value": str(len(c_list))
                }
            ]
        },
        "components": c_list,
        "dependencies": dependencies
    }


def generate_html_report(report: Dict[str, Any]) -> str:
    """Generate standalone printable CISO Executive Security Report."""
    target = html.escape(str(report.get("target") or "Unknown"), quote=True)
    scan_date = html.escape(str(report.get("scanned_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")), quote=True)
    mode = html.escape(str(report.get("mode") or "PASSIVE OSINT"), quote=True)
    findings = report.get("findings", report.get("prioritized_findings", []))
    compliance = report.get("compliance_governance", {})
    comp_score = compliance.get("overall_readiness_score", "N/A")
    comp_grade = compliance.get("overall_grade", "B")

    findings_rows = ""
    for idx, f in enumerate(findings, 1):
        sev = html.escape(str(f.get("severity", "Medium")), quote=True)
        sev_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#4b5563"
        }.get(sev, "#4b5563")

        title = html.escape(str(f.get("title", "Finding")), quote=True)
        risk = html.escape(str(f.get("contextual_risk_score", f.get("risk_score", "0.0"))), quote=True)
        epss = html.escape(str(f.get("epss_probability", "0.005")), quote=True)
        desc = html.escape(str(f.get("description", f.get("why_it_matters", ""))), quote=True)
        action = html.escape(str(f.get("remediation", f.get("suggested_action", ""))), quote=True)

        cves = [html.escape(c, quote=True) for c in f.get("related_cves", [])]
        cve_html = " ".join(f'<span class="badge badge-cve">{c}</span>' for c in cves) if cves else '<span class="text-muted">None</span>'

        findings_rows += f"""
        <div class="finding-card" style="border-left: 5px solid {sev_color};">
            <div class="finding-header">
                <div>
                    <span class="badge" style="background:{sev_color};color:#fff;">{sev}</span>
                    <strong style="margin-left:8px;font-size:16px;">#{idx} {title}</strong>
                </div>
                <div class="finding-meta">
                    <span>Risk Score: <strong>{risk}</strong></span> &bull; 
                    <span>EPSS Prob: <strong>{epss}</strong></span>
                </div>
            </div>
            <div style="margin: 8px 0 6px 0;">CVEs: {cve_html}</div>
            <p style="color:#4b5563;font-size:14px;margin: 6px 0;">{desc}</p>
            <div class="action-box">
                <strong>🛡️ Recommended Defense:</strong><br>
                <code>{action}</code>
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AEGIS-AI CISO Executive Report - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 24px; color: #1e293b; }}
        .container {{ max-width: 960px; margin: 0 auto; background: #fff; padding: 36px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
        .stat-card {{ background: #f1f5f9; padding: 16px; border-radius: 6px; border: 1px solid #cbd5e1; }}
        .stat-label {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: bold; }}
        .stat-value {{ font-size: 22px; font-weight: bold; color: #0f172a; margin-top: 4px; }}
        .finding-card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 18px; margin-bottom: 16px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-cve {{ background: #fee2e2; color: #991b1b; }}
        .action-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 10px; margin-top: 10px; font-size: 13px; }}
        code {{ font-family: Consolas, monospace; background: #f1f5f9; padding: 2px 5px; border-radius: 3px; font-size: 12px; }}
        .text-muted {{ color: #94a3b8; font-size: 13px; }}
        .footer {{ text-align: center; margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 16px; font-size: 12px; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0;color:#0f172a;font-size:24px;">AEGIS-AI Executive Security Assessment</h1>
                <div style="color:#64748b;font-size:14px;margin-top:4px;">Target: <strong>{target}</strong> | Mode: <strong>{mode}</strong></div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:12px;color:#64748b;">Report Generated: {scan_date}</div>
            </div>
        </div>

        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{len(findings)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical / High</div>
                <div class="stat-value">{sum(1 for f in findings if str(f.get("severity", "")).title() in ["Critical", "High"])}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Compliance Readiness</div>
                <div class="stat-value">{comp_score}% (Grade {comp_grade})</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Discovery Mode</div>
                <div class="stat-value" style="font-size:16px;">{mode}</div>
            </div>
        </div>

        <h2>Perimeter Findings & Remediation</h2>
        {findings_rows if findings_rows else '<p class="text-muted">No perimeter vulnerabilities identified.</p>'}

        <div class="footer">
            Generated autonomously by AEGIS-AI Attack Surface Intelligence Platform.
        </div>
    </div>
</body>
</html>
"""
