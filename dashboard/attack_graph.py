"""
Interactive Cyber Attack Surface Network Graph Component.
Renders an animated, high-tech visual node graph of target infrastructure,
subdomains, open ports, and correlated vulnerability nodes.
"""

from __future__ import annotations

import html
import json
from typing import Any


def render_attack_surface_graph_html(
    target: str,
    findings: list[dict[str, Any]],
    ports: list[Any] | None = None,
    subdomains: list[str] | None = None,
    ips: list[str] | None = None,
) -> str:
    """Generate standalone interactive HTML5 / SVG Cyber Network Graph."""
    nodes = []
    links = []

    def _safe(text: Any) -> str:
        return html.escape(str(text or ""), quote=True)

    # 1. Central Target Node
    nodes.append({
        "id": "target_root",
        "name": _safe(target),
        "type": "target",
        "color": "#38bdf8",
        "radius": 28,
        "icon": "🎯",
        "desc": _safe(f"Primary Target Workspace: {target}"),
    })

    # 2. DNS IP Nodes
    for idx, ip in enumerate((ips or [])[:4]):
        node_id = f"ip_{idx}"
        nodes.append({
            "id": node_id,
            "name": _safe(ip),
            "type": "ip",
            "color": "#3b82f6",
            "radius": 18,
            "icon": "🌐",
            "desc": _safe(f"Resolved IP Endpoint: {ip}"),
        })
        links.append({"source": "target_root", "target": node_id, "color": "rgba(59,130,246,0.4)"})

    # 3. Subdomain Nodes
    for idx, sub in enumerate((subdomains or [])[:6]):
        node_id = f"sub_{idx}"
        nodes.append({
            "id": node_id,
            "name": _safe(sub[:22] + ("..." if len(sub) > 22 else "")),
            "type": "subdomain",
            "color": "#a855f7",
            "radius": 16,
            "icon": "📜",
            "desc": _safe(f"CT Log Subdomain: {sub}"),
        })
        links.append({"source": "target_root", "target": node_id, "color": "rgba(168,85,247,0.35)"})

    # 4. Port Nodes
    for idx, p in enumerate((ports or [])[:6]):
        port_num = p.get("port") if isinstance(p, dict) else p
        service = p.get("service", "tcp") if isinstance(p, dict) else "open"
        node_id = f"port_{idx}"
        nodes.append({
            "id": node_id,
            "name": _safe(f":{port_num} ({service})"),
            "type": "port",
            "color": "#f59e0b",
            "radius": 16,
            "icon": "🔌",
            "desc": _safe(f"Open Port {port_num} ({service})"),
        })
        links.append({"source": "target_root", "target": node_id, "color": "rgba(245,158,11,0.4)"})

    # 5. Finding / CVE Nodes
    for idx, f in enumerate(findings[:8]):
        sev = str(f.get("severity", "Info")).title()
        color = "#ef4444" if sev == "Critical" else "#f97316" if sev == "High" else "#eab308" if sev == "Medium" else "#3b82f6"
        node_id = f"finding_{idx}"
        title = str(f.get("title", f"Finding #{idx+1}"))
        nodes.append({
            "id": node_id,
            "name": _safe(f"[{sev[:4].upper()}] " + (title[:18] + ("..." if len(title) > 18 else ""))),
            "type": "finding",
            "color": color,
            "radius": 20 if sev in ["Critical", "High"] else 15,
            "icon": "🚨" if sev in ["Critical", "High"] else "⚠️",
            "desc": _safe(f"{title} ({sev}) — {f.get('exploitability', '')}"),
        })
        # Link finding to target or port
        links.append({"source": "target_root", "target": node_id, "color": f"{color}55"})

    nodes_json = json.dumps(nodes)
    links_json = json.dumps(links)

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <style>
        body {{
            margin: 0;
            background: #090d16;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            overflow: hidden;
        }}
        #graph-container {{
            width: 100%;
            height: 480px;
            position: relative;
            background: radial-gradient(circle at center, #0f172a 0%, #060911 100%);
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: inset 0 0 40px rgba(0,0,0,0.8);
        }}
        .grid-overlay {{
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background-image: 
                linear-gradient(rgba(56, 189, 248, 0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(56, 189, 248, 0.04) 1px, transparent 1px);
            background-size: 30px 30px;
            pointer-events: none;
        }}
        #tooltip {{
            position: absolute;
            display: none;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid #38bdf8;
            border-radius: 8px;
            padding: 8px 12px;
            font-size: 12px;
            color: #f8fafc;
            pointer-events: none;
            box-shadow: 0 4px 20px rgba(0, 242, 254, 0.25);
            z-index: 100;
            max-width: 260px;
            backdrop-filter: blur(8px);
        }}
        .legend {{
            position: absolute;
            bottom: 12px;
            left: 14px;
            display: flex;
            gap: 12px;
            background: rgba(15, 23, 42, 0.85);
            padding: 6px 14px;
            border-radius: 20px;
            border: 1px solid rgba(148, 163, 184, 0.2);
            font-size: 11px;
            color: #94a3b8;
            backdrop-filter: blur(8px);
        }}
        .legend-item {{ display: flex; align-items: center; gap: 5px; }}
        .legend-dot {{ width: 8px; height: 8px; border-radius: 50%; }}
        .radar-sweep {{
            position: absolute;
            top: 50%; left: 50%;
            width: 400px; height: 400px;
            margin-top: -200px; margin-left: -200px;
            border-radius: 50%;
            border: 1px solid rgba(56, 189, 248, 0.1);
            pointer-events: none;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
    </head>
    <body>
    <div id="graph-container">
        <div class="grid-overlay"></div>
        <div class="radar-sweep"></div>
        <div id="tooltip"></div>
        <div class="legend">
            <div class="legend-item"><span class="legend-dot" style="background:#38bdf8;"></span> Target</div>
            <div class="legend-item"><span class="legend-dot" style="background:#ef4444;"></span> Critical Risk</div>
            <div class="legend-item"><span class="legend-dot" style="background:#f97316;"></span> High Risk</div>
            <div class="legend-item"><span class="legend-dot" style="background:#f59e0b;"></span> Port / Service</div>
            <div class="legend-item"><span class="legend-dot" style="background:#a855f7;"></span> Subdomain</div>
            <div class="legend-item"><span class="legend-dot" style="background:#3b82f6;"></span> IP Node</div>
        </div>
        <svg id="network-svg" width="100%" height="100%" style="min-height:460px;"></svg>
    </div>

    <script>
    const nodes = {nodes_json};
    const links = {links_json};

    const container = document.getElementById('graph-container');
    const width = Math.max(window.innerWidth || 0, container.clientWidth || 0, 900);
    const height = 480;

    const svg = d3.select("#network-svg")
        .attr("viewBox", [0, 0, width, height]);

    const g = svg.append("g");

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(110))
        .force("charge", d3.forceManyBody().strength(-240))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(d => d.radius + 14));

    // Links
    const link = g.append("g")
        .selectAll("line")
        .data(links)
        .join("line")
        .attr("stroke", d => d.color || "rgba(56, 189, 248, 0.3)")
        .attr("stroke-width", 1.5)
        .attr("stroke-dasharray", "3,3");

    // Node groups
    const node = g.append("g")
        .selectAll(".node")
        .data(nodes)
        .join("g")
        .attr("class", "node")
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    // Glow Circles
    node.append("circle")
        .attr("r", d => d.radius + 4)
        .attr("fill", d => d.color)
        .attr("opacity", 0.18);

    node.append("circle")
        .attr("r", d => d.radius)
        .attr("fill", "#0f172a")
        .attr("stroke", d => d.color)
        .attr("stroke-width", 2.2);

    // Labels
    node.append("text")
        .text(d => d.name)
        .attr("x", 0)
        .attr("y", d => d.radius + 14)
        .attr("text-anchor", "middle")
        .attr("fill", "#cbd5e1")
        .attr("font-size", "11px")
        .attr("font-weight", "600")
        .attr("pointer-events", "none");

    // Icons
    node.append("text")
        .text(d => d.icon)
        .attr("x", 0)
        .attr("y", 4)
        .attr("text-anchor", "middle")
        .attr("font-size", d => d.radius > 20 ? "14px" : "11px")
        .attr("pointer-events", "none");

    // Tooltip
    const tooltip = document.getElementById("tooltip");
    node.on("mouseover", (event, d) => {{
        tooltip.style.display = "block";
        tooltip.innerHTML = `<div style="font-weight:700;color:${{d.color}};margin-bottom:2px;">${{d.icon}} ${{d.name}}</div><div style="font-size:11px;color:#94a3b8;">${{d.desc}}</div>`;
    }})
    .on("mousemove", (event) => {{
        const rect = container.getBoundingClientRect();
        tooltip.style.left = (event.clientX - rect.left + 15) + "px";
        tooltip.style.top = (event.clientY - rect.top + 10) + "px";
    }})
    .on("mouseout", () => {{
        tooltip.style.display = "none";
    }});

    simulation.on("tick", () => {{
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node
            .attr("transform", d => `translate(${{d.x}},${{d.y}})`);
    }});

    function dragstarted(event, d) {{
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }}
    function dragged(event, d) {{
        d.fx = event.x;
        d.fy = event.y;
    }}
    function dragended(event, d) {{
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }}
    </script>
    </body>
    </html>
    """
    return html_code
