import json
import os
import webbrowser
from pathlib import Path

INPUT_FILE = "prioritized_report.json"
OUTPUT_HTML = "dashboard.html"

def load_report(filepath=INPUT_FILE):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Missing file: {filepath}. Run prioritize.py first.")
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def get_badge_class(priority):
    if "P1" in priority:
        return "badge-critical"
    elif "P2" in priority:
        return "badge-high"
    elif "P3" in priority:
        return "badge-medium"
    return "badge-low"

def build_html(data):
    target = data.get("target", "127.0.0.1:3000")
    timestamp = data.get("evaluation_timestamp", "N/A")
    framework = data.get("environment_context", {}).get("web_framework", "Unknown")
    ports = ", ".join(map(str, data.get("environment_context", {}).get("scanned_ports", [])))
    
    breakdown = data.get("priority_breakdown", {})
    findings = data.get("prioritized_findings", [])

    rows_html = ""
    for item in findings:
        badge = get_badge_class(item["priority_level"])
        cves = ", ".join(item["cve_aliases"]) if item["cve_aliases"] else item["vuln_id"]
        
        rows_html += f"""
        <tr>
            <td><span class="badge {badge}">{item['priority_level']}</span></td>
            <td><strong>{item['contextual_risk_score']}</strong> / 10</td>
            <td><code>{cves}</code></td>
            <td>{item['summary']}</td>
            <td><span class="exposure-tag">{item['exposure_context']}</span></td>
            <td class="action-cell">{item['recommended_remediation']}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface & AI Prioritization Dashboard</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #10b981;
            --accent: #38bdf8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg-primary); color: var(--text-primary); padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border-color); padding-bottom: 1.5rem; }}
        h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
        .sub-header {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.4rem; }}
        
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem; text-align: center; }}
        .card-number {{ font-size: 2rem; font-weight: bold; margin-top: 0.25rem; }}
        
        .context-banner {{ background: var(--bg-secondary); border-left: 4px solid var(--accent); padding: 1rem 1.25rem; border-radius: 4px; margin-bottom: 2rem; font-size: 0.92rem; }}
        .context-banner strong {{ color: var(--accent); }}

        table {{ width: 100%; border-collapse: collapse; background: var(--bg-secondary); border-radius: 8px; overflow: hidden; border: 1px solid var(--border-color); }}
        th, td {{ padding: 0.85rem 1rem; text-align: left; font-size: 0.88rem; border-bottom: 1px solid var(--border-color); }}
        th {{ background: #162032; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        tr:hover {{ background: #243248; }}
        
        .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 9999px; font-weight: 600; font-size: 0.75rem; text-align: center; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(16, 185, 129, 0.2); color: var(--low); border: 1px solid var(--low); }}
        
        .exposure-tag {{ background: #0f172a; border: 1px solid var(--border-color); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; color: #cbd5e1; }}
        .action-cell {{ color: #a5f3fc; }}
        code {{ color: #f472b6; background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AI Vulnerability Detection & Attack-Surface Assessment</h1>
            <p class="sub-header">Target: <strong>{target}</strong> | Scan Timestamp: <strong>{timestamp}</strong></p>
        </header>

        <div class="context-banner">
            <strong>Environmental Telemetry:</strong> Detected Framework: <code>{framework}</code> | Exposed Open Ports: <code>{ports}</code> | Target Instance: <code>OWASP Juice Shop (Containerized)</code>
        </div>

        <div class="metrics-grid">
            <div class="card">
                <div style="color: var(--text-muted); font-size: 0.85rem;">Total Findings</div>
                <div class="card-number" style="color: var(--accent);">{data.get('total_analyzed', 0)}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted); font-size: 0.85rem;">Critical (P1)</div>
                <div class="card-number" style="color: var(--critical);">{breakdown.get('critical_p1', 0)}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted); font-size: 0.85rem;">High (P2)</div>
                <div class="card-number" style="color: var(--high);">{breakdown.get('high_p2', 0)}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted); font-size: 0.85rem;">Medium (P3)</div>
                <div class="card-number" style="color: var(--medium);">{breakdown.get('medium_p3', 0)}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-muted); font-size: 0.85rem;">Low (P4)</div>
                <div class="card-number" style="color: var(--low);">{breakdown.get('low_p4', 0)}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Risk Score</th>
                    <th>Advisory / CVE</th>
                    <th>Vulnerability Description</th>
                    <th>Attack Context</th>
                    <th>Recommended Fix</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    return html_content

def main():
    print(f"[*] Reading prioritized findings from {INPUT_FILE}...")
    report_data = load_report()

    print("[*] Generating HTML dashboard...")
    html_output = build_html(report_data)

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_output)

    abs_path = Path(OUTPUT_HTML).resolve()
    print(f"[+] Dashboard generated: {abs_path}")
    
    # Automatically open in default browser
    webbrowser.open(f"file://{abs_path}")

if __name__ == "__main__":
    main()