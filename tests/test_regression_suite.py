"""
AEGIS-AI Comprehensive Regression Suite.

Verifies all critical fixes across:
1. Attack Surface Graph API payload validity (nodes, edges, chokepoints).
2. AI Copilot prompt routing (distinct intents, zero &mdash;, zero stale google.com).
3. CISO HTML Report grounding (non-generic executive summary & header remediations).
4. MITRE ATT&CK mappings for HTTP defensive headers (CSP -> T1189, HSTS -> T1557).
5. 1-Click Demo Scan loading endpoint (/api/demo/load).
6. JavaScript AST reachability parsing and honesty rule.
7. Unified scoring weights source of truth and summation.
8. Reachability benchmark execution and metric generation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from app import app
from ast_analyzer import (
    JsAstAnalyzer,
    analyze_source_tree,
    evaluate_cve_function_reachability,
)
from correlation.mitre_attack import map_findings_to_mitre
from prioritize import get_active_weights
from storage import generate_html_report


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ------------------------------------------------------------------------------
# 1. Attack Graph Modal & Payload
# ------------------------------------------------------------------------------

def test_attack_graph_payload_for_demo_target(client):
    # First ensure demo scan is loaded
    load_resp = client.post("/api/demo/load")
    assert load_resp.status_code == 200

    resp = client.get("/api/attack-graph?target=juice.shop&format=json")
    assert resp.status_code == 200
    data = resp.get_json()

    assert "nodes" in data and len(data["nodes"]) > 0
    assert "edges" in data and len(data["edges"]) > 0
    assert "chokepoints" in data or "minimal_cut_chokepoints" in data
    assert "compromise_probability" in data or "crown_jewels_probability" in data
    assert any(n.get("type") == "attacker" for n in data["nodes"])
    assert any(n.get("type") == "goal" for n in data["nodes"])


def test_attack_graph_payload_unassessed_target(client):
    # Even if target has no prior scan on disk, API must not 404 or return empty
    resp = client.get("/api/attack-graph?target=fresh-target.example.org&format=json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "nodes" in data and len(data["nodes"]) >= 2
    assert "edges" in data and len(data["edges"]) >= 1


# ------------------------------------------------------------------------------
# 2. AI Copilot Prompt Routing & Stale State Cleanup
# ------------------------------------------------------------------------------

def test_copilot_quick_prompts_are_distinct(client):
    # Ensure demo scan is loaded for juice.shop
    client.post("/api/demo/load")

    prompts = [
        "Summarize top findings",
        "Check compliance status against PCI-DSS and OWASP Top 10",
        "Generate patch configuration",
        "Explain risk scoring formula",
    ]
    responses = []
    for p in prompts:
        resp = client.post("/api/agent-chat", json={"target": "juice.shop", "prompt": p})
        assert resp.status_code == 200
        reply = resp.get_json().get("reply", "")
        assert reply, f"Empty reply for prompt: {p}"
        # Assert no &mdash; literal HTML entity leaks
        assert "&mdash;" not in reply, f"Literal &mdash; leaked in reply: {reply[:100]}"
        responses.append(reply)

    # All 4 responses must be distinct
    assert len(set(responses)) == 4, "Quick-prompts returned duplicate responses!"

    # Scoring formula response must mention active weights and CISA KEV
    scoring_reply = responses[3]
    assert "0.35" in scoring_reply or "CVSS" in scoring_reply
    assert "CISA KEV" in scoring_reply or "EPSS" in scoring_reply


def test_copilot_no_stale_google_state_on_initial_load(client):
    # Query without target
    resp = client.post("/api/agent-chat", json={"target": "", "prompt": "Hello"})
    assert resp.status_code == 200
    reply = resp.get_json().get("reply", "")
    assert "google.com" not in reply.lower()
    assert any(w in reply.lower() for w in ["no active scan", "no target scan", "run audit", "load verified demo", "not currently loaded"])


def test_copilot_js_file_has_no_literal_emdash():
    copilot_js = Path(__file__).resolve().parent.parent / "static" / "js" / "copilot.js"
    assert copilot_js.exists()
    content = copilot_js.read_text(encoding="utf-8")
    assert "&mdash;" not in content, "Found literal &mdash; in static/js/copilot.js"


# ------------------------------------------------------------------------------
# 3. CISO HTML Report Non-Generic Summaries & Remediations
# ------------------------------------------------------------------------------

def test_ciso_html_report_grounded():
    report_fixture = {
        "target": "demo-portal.example.com",
        "scan_time": "2026-11-23T12:00:00Z",
        "mode": "passive",
        "grade": "D",
        "summary": "Perimeter evaluation identified 3 high-priority security defects.",
        "findings": [
            {
                "id": "missing-csp",
                "title": "Missing Content-Security-Policy (CSP)",
                "severity": "HIGH",
                "priority_score": 7.8,
                "remediation": "Deploy Content-Security-Policy header with strict-dynamic directives.",
                "cvss_score": 7.5,
                "epss_probability": 0.05,
            },
            {
                "id": "missing-hsts",
                "title": "Missing Strict-Transport-Security (HSTS)",
                "severity": "HIGH",
                "priority_score": 7.2,
                "remediation": "Deploy Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "cvss_score": 7.0,
                "epss_probability": 0.03,
            },
        ],
    }

    html = generate_html_report(report_fixture)
    assert "Executive Summary: No summary available." not in html
    assert "Suggested Defensive Action: Apply defensive hardening" not in html
    assert "Content-Security-Policy" in html
    assert "Strict-Transport-Security" in html


# ------------------------------------------------------------------------------
# 4. MITRE ATT&CK Mappings for HTTP Security Headers
# ------------------------------------------------------------------------------

def test_mitre_mapping_http_security_headers():
    findings = [
        {"id": "missing-csp", "title": "Missing Content-Security-Policy header"},
        {"id": "missing-hsts", "title": "Missing Strict-Transport-Security header"},
        {"id": "missing-xfo", "title": "Missing X-Frame-Options header"},
        {"id": "missing-xcto", "title": "Missing X-Content-Type-Options header"},
        {"id": "missing-referrer-policy", "title": "Missing Referrer-Policy header"},
    ]

    mapped = map_findings_to_mitre(findings)
    tech_findings = mapped.get("technique_findings", {})

    # Verify CSP -> T1189
    assert any(f.get("id") == "missing-csp" for f in tech_findings.get("T1189", [])), "CSP not mapped to T1189!"

    # Verify HSTS -> T1557
    assert any(f.get("id") == "missing-hsts" for f in tech_findings.get("T1557", [])), "HSTS not mapped to T1557!"

    # Verify XFO -> T1185
    assert any(f.get("id") == "missing-xfo" for f in tech_findings.get("T1185", [])), "XFO not mapped to T1185!"

    # Verify XCTO -> T1059.007
    assert any(f.get("id") == "missing-xcto" for f in tech_findings.get("T1059.007", [])), "XCTO not mapped to T1059.007!"

    # Verify Referrer-Policy -> T1592
    assert any(f.get("id") == "missing-referrer-policy" for f in tech_findings.get("T1592", [])), "Referrer-Policy not mapped to T1592!"

    # Verify NONE are mapped to generic T1596
    assert "T1596" not in tech_findings, f"Security headers incorrectly mapped to T1596: {tech_findings.get('T1596')}"


# ------------------------------------------------------------------------------
# 5. 1-Click Demo Scan Loading Endpoint
# ------------------------------------------------------------------------------

def test_demo_load_endpoint(client):
    resp = client.post("/api/demo/load")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("success") is True
    assert data.get("target") == "juice.shop"
    assert data.get("demo_fixture") is True

    findings = data.get("findings") or data.get("report", {}).get("findings", [])
    assert len(findings) > 0
    # Must contain enriched signals
    assert any("priority_score" in f for f in findings)
    assert any("ssvc_decision" in f for f in findings)


# ------------------------------------------------------------------------------
# 6. Unified Scoring Weights Source of Truth
# ------------------------------------------------------------------------------

def test_scoring_weights_endpoint_and_sum(client):
    resp = client.get("/api/scoring-weights")
    assert resp.status_code == 200
    data = resp.get_json()

    # Active weights sum to 1.0
    active = data.get("active_weights", {})
    assert round(active.get("sum", 0.0), 2) == 1.00

    # Default weights sum to 1.0
    defaults = data.get("default_weights", {})
    assert round(defaults.get("sum", 0.0), 2) == 1.00
    assert defaults.get("cvss") == 0.35
    assert defaults.get("epss") == 0.30
    assert defaults.get("exposure") == 0.20
    assert defaults.get("criticality") == 0.15

    # Calibrated weights sum to 1.0
    cal = data.get("calibrated_weights", {})
    assert round(cal.get("sum", 0.0), 2) == 1.00

    # Test direct python function get_active_weights
    w_cvss, w_epss, w_exp, w_crit, src = get_active_weights()
    assert round(w_cvss + w_epss + w_exp + w_crit, 2) == 1.00


# ------------------------------------------------------------------------------
# 7. JavaScript AST Reachability & Strict Honesty Guardrail
# ------------------------------------------------------------------------------

def test_js_ast_analyzer_reachability(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.21", "tough-cookie": "^2.5.0"}}),
        encoding="utf-8"
    )
    (tmp_path / "server.js").write_text("""
const express = require('express');
const _ = require('lodash');
const { parse } = require('tough-cookie');
const app = express();

app.get('/render', (req, res) => {
    const fn = _.template(req.query.t || '');
    res.send(fn({}));
});
""", encoding="utf-8")

    tree = analyze_source_tree(str(tmp_path))
    assert tree["source_provided"] is True
    assert "lodash" in tree["imported_packages"]

    # Reachable function
    r1 = evaluate_cve_function_reachability("CVE-2021-23337", "lodash", tree)
    assert r1["verdict"] == "reachable_function"
    assert r1["reachability_factor"] == 1.0

    # Imported only (parse is in import destructure, but not called)
    r2 = evaluate_cve_function_reachability("CVE-2023-26136", "tough-cookie", tree)
    assert r2["verdict"] == "imported_only"
    assert r2["reachability_factor"] == 0.3

    # Remote target without source repository: strict honesty rule
    r3 = evaluate_cve_function_reachability("CVE-2021-23337", "lodash", None)
    assert r3["verdict"] == "unknown (no source provided)"
    assert r3["reachability_factor"] == 1.0


# ------------------------------------------------------------------------------
# 8. Reachability Benchmark Execution
# ------------------------------------------------------------------------------

def test_benchmark_reachability_execution():
    from eval.benchmark_reachability import run_benchmark
    res = run_benchmark()
    assert res.get("scenarios_evaluated", 0) >= 2
    assert res.get("total_cves_evaluated", 0) >= 8

    agg = res.get("aggregated_metrics", {})
    assert "ranking_metrics" in agg
    assert "alert_noise_suppression_pct" in agg
    assert agg.get("average_bayesian_min_cut_risk_reduction_pct", 0) > 0
