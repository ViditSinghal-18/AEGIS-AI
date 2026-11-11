"""
Unit tests for Phase 3: Bayesian Attack Graph, Dijkstra Path, and Minimal Chokepoints.

Covers:
1. Exact Bayesian forward inference with hand-computed Noisy-OR probabilities (Poolsappasit et al. 2012).
2. Dijkstra most-probable path via negative log-likelihood minimization (Jha et al. 2002).
3. Minimal Critical Chokepoint Cut-Set via greedy path disruption (Jha et al. 2002).
4. Counterfactual 'What-If I Patch X?' simulation and risk reduction metrics.
5. End-to-end attack graph generation from target findings.
"""

from __future__ import annotations

import math
import pytest

from dashboard.bayesian_attack_graph import (
    AttackEdge,
    AttackNode,
    BayesianAttackGraph,
    build_attack_graph_from_findings,
)
from dashboard.attack_graph import render_attack_surface_graph_html


# ==============================================================================
# 1. Hand-Computed Closed-Form Bayesian Noisy-OR Test
# ==============================================================================

def test_bayesian_noisy_or_hand_computed():
    """Verify exact Noisy-OR probability against manual closed-form calculation.

    Graph Topology:
        Attacker (P=1.0)
          ├──(p=0.6)──> N1
          └──(p=0.4)──> N2
        N1 ──(p=0.5)──> Goal
        N2 ──(p=0.5)──> Goal

    Hand Computation:
        P(Attacker) = 1.0
        P(N1) = 1.0 * 0.6 = 0.6
        P(N2) = 1.0 * 0.4 = 0.4
        
        Failure via N1: 1 - (P(N1) * 0.5) = 1 - (0.6 * 0.5) = 1 - 0.30 = 0.70
        Failure via N2: 1 - (P(N2) * 0.5) = 1 - (0.4 * 0.5) = 1 - 0.20 = 0.80
        Joint Failure at Goal: 0.70 * 0.80 = 0.56
        P(Goal) = 1 - 0.56 = 0.44 (44.0%)
    """
    bag = BayesianAttackGraph(target_name="Test Lab")
    bag.add_node("attacker", "Attacker Root", "attacker", base_probability=1.0)
    bag.add_node("n1", "Vulnerability 1", "vulnerability")
    bag.add_node("n2", "Vulnerability 2", "vulnerability")
    bag.add_node("goal", "Target Goal", "goal")

    bag.add_edge("attacker", "n1", exploit_probability=0.6)
    bag.add_edge("attacker", "n2", exploit_probability=0.4)
    bag.add_edge("n1", "goal", exploit_probability=0.5)
    bag.add_edge("n2", "goal", exploit_probability=0.5)

    probs = bag.evaluate_bayesian_probabilities()

    assert math.isclose(probs["attacker"], 1.0, abs_tol=1e-4)
    assert math.isclose(probs["n1"], 0.6, abs_tol=1e-4)
    assert math.isclose(probs["n2"], 0.4, abs_tol=1e-4)
    assert math.isclose(probs["goal"], 0.44, abs_tol=1e-4)


# ==============================================================================
# 2. Dijkstra Most Probable Path Test
# ==============================================================================

def test_dijkstra_most_probable_path():
    """Verify that Dijkstra on -ln(p) selects the path with maximum product probability.

    Path 1: attacker -> n1 -> goal: P = 0.6 * 0.5 = 0.30
    Path 2: attacker -> n2 -> goal: P = 0.4 * 0.5 = 0.20

    Dijkstra must select Path 1 because 0.30 > 0.20.
    """
    bag = BayesianAttackGraph(target_name="Test Lab")
    bag.add_node("attacker", "Attacker", "attacker", base_probability=1.0)
    bag.add_node("n1", "Vuln High Prob", "vulnerability")
    bag.add_node("n2", "Vuln Low Prob", "vulnerability")
    bag.add_node("goal", "Goal", "goal")

    bag.add_edge("attacker", "n1", exploit_probability=0.6, vulnerability_id="CVE-HIGH")
    bag.add_edge("attacker", "n2", exploit_probability=0.4, vulnerability_id="CVE-LOW")
    bag.add_edge("n1", "goal", exploit_probability=0.5)
    bag.add_edge("n2", "goal", exploit_probability=0.5)

    res = bag.find_most_probable_path(source="attacker", goal="goal")
    assert res is not None
    assert res.path_nodes == ["attacker", "n1", "goal"]
    assert math.isclose(res.path_probability, 0.30, abs_tol=1e-4)
    assert "CVE-HIGH" in res.vulnerabilities_on_path


# ==============================================================================
# 3. Minimal Critical Chokepoint Cut-Set Test
# ==============================================================================

def test_minimal_chokepoints_single_bottleneck():
    """When all attack paths funnel through a single pivot node, it must be the chokepoint.

    Topology:
        Attacker -> Ingress -> [Chokepoint Pivot] -> Vuln1 -> Goal
                                                -> Vuln2 -> Goal
    """
    bag = BayesianAttackGraph(target_name="Test Lab")
    bag.add_node("attacker", "Attacker", "attacker", base_probability=1.0)
    bag.add_node("ingress", "Ingress", "ingress")
    bag.add_node("pivot", "Strategic Chokepoint Pivot", "privilege", cve_id="CVE-PIVOT")
    bag.add_node("v1", "Service A", "vulnerability")
    bag.add_node("v2", "Service B", "vulnerability")
    bag.add_node("goal", "Crown Jewels", "goal")

    bag.add_edge("attacker", "ingress", exploit_probability=1.0)
    bag.add_edge("ingress", "pivot", exploit_probability=0.8)
    bag.add_edge("pivot", "v1", exploit_probability=0.7)
    bag.add_edge("pivot", "v2", exploit_probability=0.5)
    bag.add_edge("v1", "goal", exploit_probability=0.9)
    bag.add_edge("v2", "goal", exploit_probability=0.6)

    cutset = bag.compute_minimal_chokepoints(source="attacker", goal="goal")

    assert "pivot" in cutset.chokepoint_nodes
    assert "CVE-PIVOT" in cutset.chokepoint_vulnerabilities
    assert cutset.paths_blocked_count == 2
    assert cutset.total_paths_count == 2
    assert cutset.residual_compromise_probability == 0.0


# ==============================================================================
# 4. What-If Counterfactual Simulation Test
# ==============================================================================

def test_simulate_what_if_patch():
    """Verify counterfactual probability reduction when patching finding N1.

    Baseline P(goal) = 0.44
    With N1 patched: P(N2->goal) = 1 - (1 - 0.4 * 0.5) = 0.20
    Absolute Reduction = 0.44 - 0.20 = 0.24 (54.5% reduction).
    """
    bag = BayesianAttackGraph(target_name="Test Lab")
    bag.add_node("attacker", "Attacker Root", "attacker", base_probability=1.0)
    bag.add_node("n1", "Vuln 1", "vulnerability")
    bag.add_node("n2", "Vuln 2", "vulnerability")
    bag.add_node("goal", "Crown Jewels", "goal")

    bag.add_edge("attacker", "n1", exploit_probability=0.6)
    bag.add_edge("attacker", "n2", exploit_probability=0.4)
    bag.add_edge("n1", "goal", exploit_probability=0.5)
    bag.add_edge("n2", "goal", exploit_probability=0.5)

    sim = bag.simulate_what_if_patch(patched_node_id="n1", goal="goal")

    assert math.isclose(sim["baseline_probability"], 0.44, abs_tol=1e-3)
    assert math.isclose(sim["counterfactual_probability"], 0.20, abs_tol=1e-3)
    assert math.isclose(sim["absolute_reduction"], 0.24, abs_tol=1e-3)
    assert math.isclose(sim["percentage_risk_reduction"], 54.5, abs_tol=0.2)
    assert sim["is_effective"] is True


# ==============================================================================
# 5. End-to-End Build and Render Test
# ==============================================================================

def test_build_attack_graph_from_findings():
    findings = [
        {"title": "Remote Code Execution in Nginx", "severity": "Critical", "epss_probability": 0.85, "related_cves": ["CVE-2021-23017"]},
        {"title": "Weak HSTS Header", "severity": "Medium", "epss_probability": 0.02, "related_cves": []},
    ]
    ports = [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]

    bag = build_attack_graph_from_findings("api.enterprise.corp", findings=findings, ports=ports)
    assert "attacker_root" in bag.nodes
    assert "crown_jewels" in bag.nodes
    assert len(bag.edges) >= 4

    p_crown = bag.nodes["crown_jewels"].compromise_probability
    assert 0.0 < p_crown <= 1.0

    html = render_attack_surface_graph_html("api.enterprise.corp", findings=findings, ports=ports)
    assert "Crown Jewels Compromise Risk:" in html
    assert "Most-Probable Exploit Path:" in html
    assert "Minimal Chokepoint Fixes:" in html
