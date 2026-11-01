"""Tools exposed to the Strands Agent for attack surface correlation.

All tools invoke existing defensive backend logic from `backend/service.py`,
`storage.py`, and `ai/copilot.py` without duplicating scanning code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from strands import tool
except ImportError:
    # Graceful fallback decorator if strands is not yet installed in a test runner
    def tool(func: Any) -> Any:
        return func

from backend.service import build_scan_request, run_scan
from storage import list_run_history, read_json


@tool
def passive_scan(domain: str) -> dict[str, Any]:
    """Execute a passive OSINT reconnaissance scan on a public domain.

    This performs read-only discovery (DNS records, Certificate Transparency
    logs, HTTP response headers, and TLS grading) without sending probe
    packets to unauthorized ports.

    Args:
        domain: The domain name or hostname to inspect (e.g. 'example.com').

    Returns:
        A dictionary containing scan results, finding counts, and report paths.
    """
    request = build_scan_request(
        target=domain,
        force_passive=True,
        requested_by="strands-agent-passive",
    )
    result = run_scan(request)
    return {
        "status": "success",
        "target": result.target,
        "mode": result.mode,
        "scan_method": result.scan_method,
        "finding_count": result.finding_count,
        "report_path": result.report_path,
        "notes": result.notes,
    }


@tool
def active_scan(target: str, ports: list[int] | str = "80,443,3000,8000,8080") -> dict[str, Any]:
    """Execute an active port and service scan on an authorized target.

    Active scanning probes TCP ports and correlates discovered banners against
    vulnerability databases (NVD, CISA KEV, FIRST EPSS).

    NOTE: The target MUST be explicitly verified or in `targets.allowlist`.

    Args:
        target: Authorized hostname or IP address (e.g. 'localhost', '127.0.0.1').
        ports: Comma-separated port string (e.g. '80,443') or list of integer ports.

    Returns:
        A dictionary containing scan results, discovered findings, and output paths.
    """
    request = build_scan_request(
        target=target,
        ports=ports,
        force_passive=False,
        requested_by="strands-agent-active",
    )
    result = run_scan(request)
    return {
        "status": "success",
        "target": result.target,
        "mode": result.mode,
        "scan_method": result.scan_method,
        "finding_count": result.finding_count,
        "used_llm": result.used_llm,
        "report_path": result.report_path,
        "notes": result.notes,
    }


@tool
def correlate(scan_id: str | None = None, target: str | None = None) -> dict[str, Any]:
    """Retrieve correlated CVE and attack-surface findings for a previous scan.

    Reads the correlated findings report from storage for the specified target
    or latest historical scan ID.

    Args:
        scan_id: Optional filename or timestamp ID of a historical scan (e.g. 'run_20261021_120000.json').
        target: Optional hostname/domain of the target to retrieve findings for.

    Returns:
        Correlated findings containing exposed assets, software versions, and CVE records.
    """
    resolved_target = (target or "").strip()

    # If scan_id is provided, check if it references a historical file
    if scan_id and not resolved_target:
        # Check if scan_id matches a target or history file
        history_files = list_run_history()
        for h_path in history_files:
            if scan_id in h_path.name:
                try:
                    data = json.loads(h_path.read_text(encoding="utf-8"))
                    resolved_target = data.get("target", "")
                    break
                except Exception:
                    pass

    try:
        report = read_json("prioritized_report.json", target=resolved_target or None)
        correlated = read_json("correlated_findings.json", target=resolved_target or None)
        return {
            "status": "success",
            "target": resolved_target or report.get("target", "unknown"),
            "summary": report.get("summary", ""),
            "top_risks": report.get("top_risks", []),
            "finding_count": len(report.get("findings", [])),
            "findings": report.get("findings", [])[:10],
            "asset_count": len(correlated.get("assets", [])),
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Could not retrieve correlation data for target '{resolved_target}': {exc}",
        }


@tool
def explain(finding: dict[str, Any] | str, target: str | None = None) -> str:
    """Generate an actionable, defensive security explanation for a finding.

    Translates complex vulnerability details (CVEs, EPSS probabilities, KEV status,
    or missing HTTP security headers) into plain-language business impact and
    defensive configuration patches (e.g., Nginx, Express, or firewall fixes).

    Args:
        finding: Finding details dictionary or query string (e.g., 'Explain CVE-2023-38606'
                 or 'Why is missing Content-Security-Policy a risk?').
        target: Optional target name for context.

    Returns:
        Plain-language defensive analysis and remediation guidance.
    """
    from ai.copilot import query_copilot

    finding_str = finding if isinstance(finding, str) else json.dumps(finding)

    # Attempt to load recent prioritized report for context
    mock_report: dict[str, Any] = {
        "target": target or "target-system",
        "summary": "Target security assessment findings",
        "top_risks": ["Vulnerability exposure", "Missing security headers"],
        "findings": [finding] if isinstance(finding, dict) else [],
    }

    if target:
        try:
            stored_report = read_json("prioritized_report.json", target=target)
            if stored_report:
                mock_report = stored_report
        except Exception:
            pass

    explanation = query_copilot(
        prompt_text=f"Explain this security finding and provide defensive remediation: {finding_str}",
        report=mock_report,
    )
    return explanation
