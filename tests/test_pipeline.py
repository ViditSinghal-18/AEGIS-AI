"""
AEGIS-AI: Phase 2 Pipeline Unit & Integration Test Suite.
Tests:
- Passive OSINT discovery (DNS, TLS, HTTP, WAF, CT)
- Active scan permission enforcement
- NVD/OSV lookups, CISA KEV catalog, and FIRST EPSS enrichment
- AST Static Analysis and honest code reachability verdicts
- MITRE ATT&CK adversarial mapping & 4-phase simulation
- Evidence-based multi-framework compliance scoring (no fake fixed percentages)
- Storage abstraction, run history archiving, and report diffing
- Remediation configurations and WAF virtual patch generators
- Multi-format exports (CSV formula injection sanitization, CycloneDX v1.5 SBOM, CEF, ECS, HTML)
- Flask API stage endpoints and non-empty /api/sbom & /api/compliance
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import config
from app import app
from discovery.passive import (
    extract_html_title,
    detect_waf_and_cdn,
    probe_passive_dns,
    probe_passive_http,
    query_certificate_transparency
)
from discovery.port_scan import run_active_scan
from correlation.nvd_lookup import query_nvd_by_cve, query_osv_package
from correlation.enrich import load_cisa_kev_catalog, fetch_epss_scores, enrich_findings
from correlation.mitre_attack import map_finding_to_mitre, generate_attack_walkthrough
from correlation.compliance import calculate_compliance
from correlation.siem_export import generate_cef_export, generate_ecs_export, send_webhook_alert
from ast_analyzer import (
    analyze_python_source,
    analyze_javascript_source,
    evaluate_component_reachability,
    analyze_source_tree
)
from storage import (
    write_json,
    read_json,
    save_run_history,
    list_run_history,
    diff_reports,
    generate_csv_report,
    generate_html_report,
    generate_cyclonedx_sbom,
    _sanitize_csv_cell
)
from remediation import (
    generate_nginx_hardening,
    generate_express_helmet_hardening,
    generate_waf_rules,
    generate_remediation_bundle
)
from prioritize import prioritize_findings
from correlate import correlate_findings


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestPassiveDiscovery:
    def test_extract_html_title(self):
        html = "<html><head><title>Test Security Portal</title></head><body><h1>Hello</h1></body></html>"
        assert extract_html_title(html) == "Test Security Portal"

    def test_detect_waf_and_cdn(self):
        cf_headers = {"server": "cloudflare", "cf-ray": "8347dfbc98231"}
        waf_info = detect_waf_and_cdn(cf_headers)
        assert waf_info["detected"] is True
        assert "Cloudflare" in waf_info["providers"]
        assert waf_info["mitigation_factor"] == 0.6

        clean_headers = {"server": "nginx", "content-type": "text/html"}
        clean_waf = detect_waf_and_cdn(clean_headers)
        assert clean_waf["detected"] is False
        assert clean_waf["mitigation_factor"] == 1.0

    def test_passive_dns_structure(self):
        dns_res = probe_passive_dns("127.0.0.1")
        assert "domain" in dns_res
        assert "issues" in dns_res
        assert isinstance(dns_res["issues"], list)


class TestActiveScannerGate:
    def test_active_scan_refused_for_unverified_target(self):
        with pytest.raises(PermissionError) as exc_info:
            run_active_scan("unverified-adversary-domain.com")
        assert "rejected" in str(exc_info.value).lower() or "unauthorized" in str(exc_info.value).lower()

    def test_active_scan_refused_on_vercel(self, monkeypatch):
        monkeypatch.setattr(config, "IS_VERCEL", True)
        with pytest.raises(PermissionError) as exc_info:
            run_active_scan("127.0.0.1")
        assert "vercel" in str(exc_info.value).lower()


class TestThreatEnrichment:
    def test_cisa_kev_catalog_contains_known_cves(self):
        kev = load_cisa_kev_catalog()
        assert isinstance(kev, set)
        assert "CVE-2021-44228" in kev or len(kev) > 0

    def test_epss_enrichment(self):
        sample_findings = [
            {"title": "Sample Flaw", "related_cves": ["CVE-2021-44228"], "cvss_score": 10.0}
        ]
        enriched = enrich_findings(sample_findings)
        assert len(enriched) == 1
        assert "epss_probability" in enriched[0]
        assert "in_cisa_kev" in enriched[0]
        assert enriched[0]["in_cisa_kev"] is True


class TestAstAndCodeReachability:
    def test_python_ast_route_and_sink_analysis(self):
        sample_py = """
from flask import Flask, redirect, request
app = Flask(__name__)

@app.route('/login')
def login():
    url = request.args.get('next')
    return redirect(url)
"""
        routes = analyze_python_source(sample_py)
        assert len(routes) == 1
        assert routes[0]["handler_name"] == "login"
        assert routes[0]["route_path"] == "/login"
        assert any(s["sink"] == "redirect" for s in routes[0]["dangerous_sinks"])

    def test_reachability_without_source_is_honest(self):
        res = evaluate_component_reachability("express", source_analysis=None)
        assert "unknown" in res["reachability_verdict"]
        assert res["reachability_factor"] == 1.0
        assert "without source code" in res["evidence"].lower()

    def test_reachability_with_unused_package_suppresses_factor(self):
        mock_source = {
            "source_provided": True,
            "declared_packages": ["express", "lodash"],
            "imported_packages": ["express"],  # lodash is NOT imported
            "routes": [{"path": "/api", "calls": ["express"]}]
        }
        res_lodash = evaluate_component_reachability("lodash", source_analysis=mock_source)
        assert res_lodash["reachability_factor"] == 0.0
        assert "dead code" in res_lodash["reachability_verdict"].lower()


class TestComplianceAndMitre:
    def test_compliance_scores_are_dynamic_and_calculated(self):
        findings_clean = []
        comp_clean = calculate_compliance(findings_clean, is_port_open=False)
        assert comp_clean["overall_readiness_score"] == 100.0
        assert comp_clean["overall_grade"] == "A"

        findings_with_gaps = [
            {"title": "Missing Security Header: CONTENT-SECURITY-POLICY", "severity": "Medium"},
            {"title": "TLS Certificate Expired", "severity": "Critical"},
            {"title": "Missing DNS SPF Record", "severity": "Medium"}
        ]
        comp_gaps = calculate_compliance(findings_with_gaps, is_port_open=True)
        assert comp_gaps["overall_readiness_score"] < 100.0
        assert comp_gaps["pci_dss_4"]["passing_controls"] < comp_gaps["pci_dss_4"]["total_controls"]

    def test_mitre_mapping_and_walkthrough(self):
        finding = {
            "title": "Open Port 80 Ingress",
            "source": "active_port_scan",
            "evidence": "TCP port 80 open to internet"
        }
        mitre_res = map_finding_to_mitre(finding)
        assert mitre_res["technique_id"] in ["T1595", "T1190"]

        sim = generate_attack_walkthrough(finding, target="example.com")
        assert len(sim["phases"]) == 4
        assert "ILLUSTRATIVE" in sim["simulation_disclaimer"]


class TestStorageAndExports:
    def test_csv_injection_sanitization(self):
        assert _sanitize_csv_cell("=1+1") == "'=1+1"
        assert _sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
        assert _sanitize_csv_cell("-CMD") == "'-CMD"
        assert _sanitize_csv_cell("+cmd") == "'+cmd"
        assert _sanitize_csv_cell("Normal Text") == "Normal Text"

    def test_cyclonedx_sbom_generation_validity(self):
        components = [
            {"name": "nginx", "version": "1.24.0", "ecosystem": "generic"}
        ]
        sbom = generate_cyclonedx_sbom(components, target="my-app.com")
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert sbom["serialNumber"].startswith("urn:uuid:")
        assert len(sbom["components"]) == 1
        assert sbom["components"][0]["name"] == "nginx"

    def test_report_diffing(self):
        prev = {
            "findings": [
                {"title": "Missing HSTS", "related_cves": []},
                {"title": "Port 3000 Open", "related_cves": []}
            ]
        }
        curr = {
            "findings": [
                {"title": "Missing HSTS", "related_cves": []},
                {"title": "Vulnerability in lodash", "related_cves": ["CVE-2021-23337"]}
            ]
        }
        diff = diff_reports(curr, prev)
        assert len(diff["new"]) == 1
        assert diff["new"][0]["title"] == "Vulnerability in lodash"
        assert len(diff["resolved"]) == 1
        assert diff["resolved"][0]["title"] == "Port 3000 Open"
        assert len(diff["persisting"]) == 1
        assert diff["persisting"][0]["title"] == "Missing HSTS"

    def test_remediation_bundle(self):
        bundle = generate_remediation_bundle("test.org")
        assert "nginx" in bundle
        assert "apache" in bundle
        assert "waf" in bundle
        assert "cloudflare" in bundle["waf"]
        assert "aws_waf" in bundle["waf"]


class TestApiPhase2Endpoints:
    def test_sbom_endpoint_returns_valid_cyclonedx(self, client):
        resp = client.get("/api/sbom")
        assert resp.status_code == 200
        data = json.loads(resp.data.decode("utf-8"))
        assert data.get("bomFormat") == "CycloneDX"
        assert data.get("specVersion") == "1.5"
        assert "components" in data

    def test_compliance_endpoint_returns_honest_evaluation(self, client):
        resp = client.get("/api/compliance")
        assert resp.status_code == 200
        data = json.loads(resp.data.decode("utf-8"))
        assert "overall_readiness_score" in data
        assert "pci_dss_4" in data
        assert "nist_csf_2" in data

    def test_remediation_endpoint(self, client):
        resp = client.get("/api/remediation?target=my-org.com")
        assert resp.status_code == 200
        data = json.loads(resp.data.decode("utf-8"))
        assert data.get("target") == "my-org.com"
        assert "nginx" in data

    def test_export_multi_format_html_and_csv(self, client):
        resp_csv = client.get("/api/export/csv")
        assert resp_csv.status_code == 200
        assert "text/csv" in resp_csv.content_type

        resp_html = client.get("/api/export/html")
        assert resp_html.status_code == 200
        assert "text/html" in resp_html.content_type
        assert "AEGIS-AI" in resp_html.data.decode("utf-8")

        resp_cef = client.get("/api/export/cef")
        assert resp_cef.status_code == 200

    def test_scan_stage_headers_endpoint(self, client):
        resp = client.get("/api/scan/headers?target=127.0.0.1")
        assert resp.status_code == 200
        data = json.loads(resp.data.decode("utf-8"))
        assert "missing_security_headers" in data or "reachable" in data
