"""
Unit tests for Phase 2: Fewer False Positives.

Covers:
1. Advisory consistency check (Dong et al. USENIX Sec 2019)
2. Backport-aware matching for Linux distributions (Debian, Ubuntu, RHEL, Alpine)
3. Function-level reachability AST analysis with fixture code (Ponta et al. Eclipse Steady 2018)
4. Score modulation and explainable breakdown integration in prioritize_findings
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ast_analyzer import (
    analyze_source_tree,
    evaluate_cve_function_reachability,
    load_cve_symbols,
)
from correlation.advisory_consistency import (
    AdvisoryConsistencyResult,
    check_advisory_consistency,
    evaluate_findings_advisory_consistency,
)
from correlation.backport_detector import (
    BackportVerdict,
    detect_backport,
    apply_backport_checks_to_findings,
)
from prioritize import prioritize_findings
from schemas import CveRecord


# ==============================================================================
# 1. Advisory Consistency Tests (Dong et al. 2019)
# ==============================================================================

def test_advisory_consistency_high_agreement():
    """When NVD and OSV agree on severity and version bounds, confidence is high."""
    nvd_raw = {
        "cvss_score": 7.5,
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "versionStartIncluding": "1.0.0",
                                "versionEndExcluding": "1.2.0",
                                "criteria": "cpe:2.3:a:example:lib:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    osv_raw = {
        "severity": [{"type": "CVSS_V3", "score": 7.5}],
        "affected": [
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.2.0"},
                        ],
                    }
                ]
            }
        ],
    }

    result = check_advisory_consistency("CVE-2024-1111", nvd_record=nvd_raw, osv_data=osv_raw)
    assert result.confidence == "high"
    assert result.is_consistent is True
    assert result.cvss_delta == 0.0
    assert "agree" in result.reason.lower()


def test_advisory_consistency_medium_minor_divergence():
    """When NVD and OSV have a minor CVSS difference, confidence is medium."""
    nvd_raw = {"cvss_score": 8.1}
    osv_raw = {
        "severity": [{"type": "CVSS_V3", "score": 6.8}],
        "affected": [],
    }

    result = check_advisory_consistency("CVE-2024-2222", nvd_record=nvd_raw, osv_data=osv_raw)
    assert result.confidence == "medium"
    assert result.cvss_delta == 1.3
    assert "minor advisory divergence" in result.reason.lower()


def test_advisory_consistency_low_severe_conflict():
    """When NVD and OSV report conflicting fixed versions, confidence is low."""
    nvd_raw = {
        "cvss_score": 9.8,
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "versionEndExcluding": "2.0.1",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    osv_raw = {
        "severity": [{"type": "CVSS_V3", "score": 6.5}],
        "affected": [
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "2.5.0"},
                        ],
                    }
                ]
            }
        ],
    }

    result = check_advisory_consistency("CVE-2024-3333", nvd_record=nvd_raw, osv_data=osv_raw)
    assert result.confidence == "low"
    assert result.is_consistent is False
    assert len(result.discrepancy_details) >= 1


def test_advisory_consistency_single_source():
    """When only NVD is available, return medium confidence with an honest single-source reason."""
    nvd_raw = {"cvss_score": 6.5}
    result = check_advisory_consistency("CVE-2024-4444", nvd_record=nvd_raw, osv_data={})
    assert result.confidence == "medium"
    assert "single advisory source" in result.reason.lower()


# ==============================================================================
# 2. Backport-Aware Matching Tests
# ==============================================================================

def test_detect_backport_ubuntu_package():
    verdict = detect_backport(product="nginx", version_string="1.18.0-0ubuntu1.4")
    assert verdict.is_backport_candidate is True
    assert verdict.distro == "Ubuntu"
    assert verdict.upstream_version == "1.18.0"
    assert verdict.package_release == "0ubuntu1.4"
    assert verdict.possibly_backported is True
    assert verdict.adjusted_confidence == "low"
    assert "Ubuntu LTS backports security patches" in verdict.explanation


def test_detect_backport_debian_package():
    verdict = detect_backport(product="apache2", version_string="2.4.38-3+deb10u7")
    assert verdict.is_backport_candidate is True
    assert verdict.distro == "Debian"
    assert verdict.upstream_version == "2.4.38"
    assert verdict.possibly_backported is True
    assert verdict.adjusted_confidence == "low"


def test_detect_backport_rhel_package():
    verdict = detect_backport(product="httpd", version_string="2.4.37-43.module_el8.5.0")
    assert verdict.is_backport_candidate is True
    assert verdict.distro == "RHEL/CentOS"
    assert verdict.upstream_version == "2.4.37"
    assert verdict.possibly_backported is True


def test_detect_backport_alpine_package():
    verdict = detect_backport(product="nginx", version_string="1.20.2-r1")
    assert verdict.is_backport_candidate is True
    assert verdict.distro == "Alpine"
    assert verdict.upstream_version == "1.20.2"
    assert verdict.package_release == "r1"
    assert verdict.possibly_backported is True


def test_detect_backport_banner_disclosure():
    verdict = detect_backport(product="apache", version_string="2.4.41", banner="Apache/2.4.41 (Ubuntu)")
    assert verdict.is_backport_candidate is True
    assert verdict.distro == "Ubuntu"
    assert verdict.banner_only is True
    assert verdict.possibly_backported is True
    assert verdict.adjusted_confidence == "low"


def test_detect_backport_upstream_clean():
    verdict = detect_backport(product="nginx", version_string="1.25.3", banner="nginx/1.25.3")
    assert verdict.is_backport_candidate is False
    assert verdict.possibly_backported is False
    assert verdict.distro is None
    assert verdict.adjusted_confidence == "high"


# ==============================================================================
# 3. Function-Level Reachability Tests (Ponta et al. 2018 / Eclipse Steady)
# ==============================================================================

def test_cve_symbols_yaml_loaded():
    symbols = load_cve_symbols()
    assert len(symbols) >= 5
    assert "CVE-2022-29217" in symbols  # PyJWT
    assert "CVE-2021-33503" in symbols  # Urllib3
    assert "CVE-2021-23337" in symbols  # Lodash


def test_reachability_no_source_returns_unknown():
    verdict = evaluate_cve_function_reachability("CVE-2022-29217", package_name="pyjwt", source_analysis=None)
    assert verdict["verdict"] == "unknown (no source provided)"
    assert verdict["reachability_factor"] == 1.0


def test_reachability_not_imported_returns_not_reachable():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "app.py").write_text("print('hello world')", encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("pyjwt==2.0.0\n", encoding="utf-8")

        analysis = analyze_source_tree(str(tmp_path))
        verdict = evaluate_cve_function_reachability("CVE-2022-29217", package_name="pyjwt", source_analysis=analysis)

        assert verdict["verdict"] == "not_reachable"
        assert verdict["reachability_factor"] == 0.0


def test_reachability_imported_only_returns_imported_only():
    """PyJWT imported and encode() called, but vulnerable decode() is NOT called."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        code = (
            "import jwt\n"
            "token = jwt.encode({'user': 'alice'}, 'secret', algorithm='HS256')\n"
        )
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("pyjwt==2.0.0\n", encoding="utf-8")

        analysis = analyze_source_tree(str(tmp_path))
        verdict = evaluate_cve_function_reachability("CVE-2022-29217", package_name="pyjwt", source_analysis=analysis)

        assert verdict["verdict"] == "imported_only"
        assert verdict["reachability_factor"] == 0.3
        assert len(verdict["matched_symbols"]) == 0


def test_reachability_vulnerable_function_called():
    """PyJWT imported and vulnerable decode() is directly invoked in code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        code = (
            "import jwt\n"
            "def authenticate(token):\n"
            "    data = jwt.decode(token, key='public_key')\n"
            "    return data\n"
        )
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("pyjwt==2.0.0\n", encoding="utf-8")

        analysis = analyze_source_tree(str(tmp_path))
        verdict = evaluate_cve_function_reachability("CVE-2022-29217", package_name="pyjwt", source_analysis=analysis)

        assert verdict["verdict"] == "reachable_function"
        assert verdict["reachability_factor"] == 1.0
        assert any("decode" in sym for sym in verdict["matched_symbols"])


def test_reachability_javascript_vulnerable_symbol():
    """Lodash imported and vulnerable template() invoked in JS code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        js_code = (
            "const lodash = require('lodash');\n"
            "function render(str) {\n"
            "    return lodash.template(str)();\n"
            "}\n"
        )
        (tmp_path / "index.js").write_text(js_code, encoding="utf-8")
        (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}', encoding="utf-8")

        analysis = analyze_source_tree(str(tmp_path))
        verdict = evaluate_cve_function_reachability("CVE-2021-23337", package_name="lodash", source_analysis=analysis)

        assert verdict["verdict"] == "reachable_function"
        assert verdict["reachability_factor"] == 1.0
        assert any("template" in sym for sym in verdict["matched_symbols"])


# ==============================================================================
# 4. End-to-End Prioritize Integration
# ==============================================================================

def test_prioritize_findings_phase2_integration():
    """Verify that prioritize_findings populates reachability, backport, and advisory fields."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Create code where pyjwt is imported only (no decode)
        (tmp_path / "app.py").write_text("import jwt\ntoken = jwt.encode({}, 'k')", encoding="utf-8")

        findings = [
            {
                "title": "PyJWT Algorithm Confusion",
                "affected_component": "pyjwt",
                "version": "2.0.0",
                "related_cves": ["CVE-2022-29217"],
                "cvss_score": 8.0,
                "epss_probability": 0.05,
            },
            {
                "title": "Nginx Ubuntu Backported Flaw",
                "affected_component": "nginx",
                "version": "1.18.0-0ubuntu1.4",
                "related_cves": ["CVE-2021-23017"],
                "cvss_score": 7.7,
                "epss_probability": 0.10,
            },
        ]
        discovery_data = {
            "target": "lab.internal",
            "http": {"server_banner": "nginx/1.18.0 (Ubuntu)"},
            "discovered_assets": [{"port": 80, "state": "open"}],
        }

        with patch("storage.write_json"):
            report = prioritize_findings(
                findings=findings,
                discovery_data=discovery_data,
                source_path=str(tmp_path),
            )

        items = report["findings"]
        pyjwt_f = next(f for f in items if f["affected_component"] == "pyjwt")
        nginx_f = next(f for f in items if f["affected_component"] == "nginx")

        # PyJWT checks: imported_only -> reachability_factor 0.3
        assert pyjwt_f["reachability_verdict"] == "imported_only"
        assert pyjwt_f["reachability_factor"] == 0.3
        assert pyjwt_f["xai_formula"]["s_code"] == 0.3

        # Nginx checks: Ubuntu package -> possibly_backported True, confidence low
        assert nginx_f["possibly_backported"] is True
        assert nginx_f["confidence"] == "low"
        assert "Ubuntu" in nginx_f["confidence_reason"]
