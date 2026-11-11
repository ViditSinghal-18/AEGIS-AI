"""
Interactive Bayesian Attack Graph & Exploit Path Component.

Inspired by:
- Poolsappasit et al. 2012 (Dynamic Security Risk Management Using Bayesian Attack Graphs)
- Jha, Sheyner, & Wing 2002 (Formal Analyses of Attack Graphs / Minimal Critical Chokepoints)

Renders an animated, high-tech D3.js visual graph highlighting:
- Bayesian node compromise probabilities P(compromise) via Noisy-OR.
- The mathematically most probable attack path via Dijkstra (-ln p).
- Minimum critical chokepoints / cut-set needed to sever attacker paths.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List, Optional

from dashboard.bayesian_attack_graph import (
    BayesianAttackGraph,
    build_attack_graph_from_findings,
)


def render_attack_surface_graph_html(
    target: str,
    findings: list[dict[str, Any]],
    ports: list[Any] | None = None,
    subdomains: list[str] | None = None,
    ips: list[str] | None = None,
    patched_node_id: Optional[str] = None,
) -> str:
    """Generate interactive HTML5 / SVG Bayesian Network Attack Graph."""
    def _safe(text: Any) -> str:
        return html.escape(str(text or ""), quote=True)

    # 1. Build and evaluate empirical Bayesian Attack Graph
    bag = build_attack_graph_from_findings(
        target=target,
        findings=findings,
        ports=ports,
        subdomains=subdomains,
    )

    # Re-evaluate with optional patched node if interactive simulation active
    patches = {patched_node_id} if patched_node_id else set()
    node_probs = bag.evaluate_bayesian_probabilities(patched_nodes=patches)

    # 2. Compute Dijkstra most-probable path (-ln p) and minimal chokepoints
    most_probable_path = bag.find_most_probable_path(source="attacker_root", goal="crown_jewels", patched_nodes=patches)
    chokepoints = bag.compute_minimal_chokepoints(source="attacker_root", goal="crown_jewels")

    critical_path_nodes = set(most_probable_path.path_nodes) if most_probable_path else set()
    critical_edges_pairs = set()
    if most_probable_path and len(most_probable_path.path_nodes) > 1:
        for u, v in zip(most_probable_path.path_nodes[:-1], most_probable_path.path_nodes[1:]):
            critical_edges_pairs.add((u, v))

    chokepoint_ids = set(chokepoints.chokepoint_nodes)

    # 3. Assemble visualization nodes
    nodes = []
    for nid, node in bag.nodes.items():
        prob = node_probs.get(nid, 0.0)
        prob_pct = f"{round(prob * 100, 1)}%"

        is_crit = nid in critical_path_nodes
        is_choke = nid in chokepoint_ids

        # Visual styling by node type
        if node.node_type == "attacker":
            color = "#ef4444"
            radius = 26
            icon = "👤"
        elif node.node_type == "ingress":
            color = "#38bdf8"
            radius = 24
            icon = "🎯"
        elif node.node_type == "port":
            color = "#f59e0b"
            radius = 18
            icon = "🔌"
        elif node.node_type == "vulnerability":
            color = "#ef4444" if prob >= 0.50 else ("#f97316" if prob >= 0.20 else "#eab308")
            radius = 20 if is_crit else 16
            icon = "🚨" if is_crit else "⚠️"
        elif node.node_type == "privilege":
            color = "#a855f7"
            radius = 22
            icon = "🔑"
        elif node.node_type == "goal":
            color = "#dc2626"
            radius = 28
            icon = "🏆"
        else:
            color = "#94a3b8"
            radius = 16
            icon = "🌐"

        desc = f"{node.description} | P(Compromise): {prob_pct}"
        if is_choke:
            desc += " [STRATEGIC CHOKEPOINT - Remediating breaks attack path]"
        if is_crit:
            desc += " [ON MOST PROBABLE ATTACK PATH]"

        nodes.append({
            "id": nid,
            "name": _safe(f"{node.name} ({prob_pct})"),
            "raw_name": _safe(node.name),
            "prob_pct": prob_pct,
            "prob_val": prob,
            "type": node.node_type,
            "color": "#f59e0b" if is_choke else color,
            "radius": radius,
            "icon": icon,
            "is_critical": is_crit,
            "is_chokepoint": is_choke,
            "desc": _safe(desc),
        })

    # 4. Assemble visualization links
    links = []
    for edge in bag.edges:
        is_crit_edge = (edge.source, edge.target) in critical_edges_pairs
        color = "#ef4444" if is_crit_edge else "rgba(56, 189, 248, 0.35)"
        width = 3.0 if is_crit_edge else 1.4

        links.append({
            "source": edge.source,
            "target": edge.target,
            "prob": edge.exploit_probability,
            "label": _safe(f"{edge.label or ''} (p={edge.exploit_probability:.0%})"),
            "color": color,
            "width": width,
            "is_critical": is_crit_edge,
        })

    crown_jewels_prob = node_probs.get("crown_jewels", 0.0)
    most_prob_p_str = f"{most_probable_path.path_probability:.1%}" if most_probable_path else "0.0% (Severed)"
    choke_count = len(chokepoints.chokepoint_nodes)

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
            height: 520px;
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
        .telemetry-banner {{
            position: absolute;
            top: 10px;
            left: 14px;
            right: 14px;
            display: flex;
            justify-content: space-between;
            background: rgba(15, 23, 42, 0.90);
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 8px;
            padding: 8px 16px;
            font-size: 11px;
            color: #94a3b8;
            backdrop-filter: blur(10px);
            z-index: 10;
        }}
        .stat-badge {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .stat-value {{
            font-weight: 700;
            color: #38bdf8;
            font-family: monospace;
            font-size: 12px;
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
            max-width: 290px;
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
    </style>
    <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
    </head>
    <body>
    <div id="graph-container">
        <div class="grid-overlay"></div>
        <div class="telemetry-banner">
            <div class="stat-badge">
                <span>🎯 Crown Jewels Compromise Risk:</span>
                <span class="stat-value" style="color:{'#ef4444' if crown_jewels_prob >= 0.50 else '#f59e0b'};">{crown_jewels_prob:.1%}</span>
            </div>
            <div class="stat-badge">
                <span>⚡ Most-Probable Exploit Path:</span>
                <span class="stat-value" style="color:#ef4444;">{most_prob_p_str}</span>
            </div>
            <div class="stat-badge">
                <span>🛡️ Minimal Chokepoint Fixes:</span>
                <span class="stat-value" style="color:#10b981;">{choke_count} strategic patch(es)</span>
            </div>
        </div>

        <div id="tooltip"></div>

        <div class="legend">
            <div class="legend-item"><span class="legend-dot" style="background:#ef4444;"></span> Critical Path</div>
            <div class="legend-item"><span class="legend-dot" style="background:#f59e0b;"></span> Chokepoint Fix</div>
            <div class="legend-item"><span class="legend-dot" style="background:#a855f7;"></span> Internal Pivot</div>
            <div class="legend-item"><span class="legend-dot" style="background:#dc2626;"></span> Crown Jewels</div>
            <div class="legend-item"><span class="legend-dot" style="background:#38bdf8;"></span> Ingress Gateway</div>
        </div>

        <svg id="network-svg" width="100%" height="100%" style="min-height:500px;"></svg>
    </div>

    <script>
    const nodes = {nodes_json};
    const links = {links_json};

    const container = document.getElementById('graph-container');
    const width = Math.max(window.innerWidth || 0, container.clientWidth || 0, 900);
    const height = 520;

    const svg = d3.select("#network-svg")
        .attr("viewBox", [0, 0, width, height]);

    const g = svg.append("g");

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(120))
        .force("charge", d3.forceManyBody().strength(-280))
        .force("center", d3.forceCenter(width / 2, height / 2 + 10))
        .force("collision", d3.forceCollide().radius(d => d.radius + 16));

    // Links
    const link = g.append("g")
        .selectAll("line")
        .data(links)
        .join("line")
        .attr("stroke", d => d.color)
        .attr("stroke-width", d => d.width)
        .attr("stroke-dasharray", d => d.is_critical ? "none" : "3,3");

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

    // Outer Aura for Chokepoints and Critical Path
    node.filter(d => d.is_chokepoint || d.is_critical)
        .append("circle")
        .attr("r", d => d.radius + 6)
        .attr("fill", "none")
        .attr("stroke", d => d.is_chokepoint ? "#f59e0b" : "#ef4444")
        .attr("stroke-width", 2)
        .attr("stroke-dasharray", d => d.is_chokepoint ? "4,2" : "none")
        .attr("opacity", 0.85);

    // Glow Circles
    node.append("circle")
        .attr("r", d => d.radius + 3)
        .attr("fill", d => d.color)
        .attr("opacity", 0.22);

    // Node body
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
        .attr("fill", d => d.is_critical ? "#f87171" : "#cbd5e1")
        .attr("font-size", "11px")
        .attr("font-weight", d => d.is_critical ? "700" : "600")
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
        tooltip.innerHTML = `<div style="font-weight:700;color:${{d.color}};margin-bottom:2px;">${{d.icon}} ${{d.raw_name}}</div>
                             <div style="font-size:11px;color:#38bdf8;margin-bottom:4px;">Compromise Probability: <b>${{d.prob_pct}}</b></div>
                             <div style="font-size:11px;color:#94a3b8;">${{d.desc}}</div>`;
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
