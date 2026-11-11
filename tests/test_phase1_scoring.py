"""
AEGIS-AI: Phase 1 Unit and Integration Test Suite.
Tests Scientifically Defensible Scoring Improvements:
1. Weight calibration & temporal train/test split (Bozorgi 2010, Jacobs 2021)
2. Ranking agreement metrics: Spearman rho, Kendall tau, RBO@k (Webber 2010)
3. Stakeholder-Specific Vulnerability Categorization (CISA SSVC v2.0, Spring 2019)
4. Uncertainty quantification & risk intervals (Angelopoulos & Bates 2021 heuristic)
5. FAIR-style Monte Carlo quantitative loss modeling (Open FAIR, Hubbard & Seiersen 2016)
6. Prioritization engine integration & backward compatibility
"""

import math
import os
import pytest
from pathlib import Path

import config
from scoring.ranking_metrics import (
    spearman_rho,
    kendall_tau,
    rank_biased_overlap,
    compute_ranking_concordance,
)
from scoring.ssvc import evaluate_ssvc
from scoring.uncertainty import compute_risk_interval
from scoring.fair_loss import (
    simulate_fair_loss,
    simulate_portfolio_fair_loss,
    DISCLAIMER_TEXT,
)
from scoring.calibrate_weights import (
    build_calibration_dataset,
    calibrate_scoring_weights,
    extract_cve_year,
    load_calibrated_weights,
    precision_recall_at_k,
)
from prioritize import prioritize_findings, get_active_weights


class TestRankingAgreementMetrics:
    def test_spearman_rho_identical_and_reversed(self):
        r1 = [1, 2, 3, 4, 5]
        r2 = [1, 2, 3, 4, 5]
        assert spearman_rho(r1, r2) == 1.0

        r3 = [5, 4, 3, 2, 1]
        assert spearman_rho(r1, r3) == -1.0

    def test_spearman_rho_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            spearman_rho([1, 2], [1, 2, 3])

    def test_kendall_tau_identical_and_reversed(self):
        r1 = [1, 2, 3, 4, 5]
        r2 = [1, 2, 3, 4, 5]
        assert kendall_tau(r1, r2) == 1.0

        r3 = [5, 4, 3, 2, 1]
        assert kendall_tau(r1, r3) == -1.0

    def test_kendall_tau_partial_agreement(self):
        r1 = [1, 2, 3, 4]
        r2 = [1, 3, 2, 4]  # 1 pair swapped out of 6 pairs -> tau = (5 - 1)/6 = 4/6 = 0.6667
        tau = kendall_tau(r1, r2)
        assert 0.60 <= tau <= 0.70

    def test_rbo_identical_and_disjoint(self):
        l1 = ["A", "B", "C", "D", "E"]
        l2 = ["A", "B", "C", "D", "E"]
        assert rank_biased_overlap(l1, l2, p=0.9) == 1.0

        l3 = ["V", "W", "X", "Y", "Z"]
        assert rank_biased_overlap(l1, l3, p=0.9) == 0.0

    def test_rbo_top_heaviness(self):
        # Swapping top items should yield lower RBO than swapping bottom items
        base = ["A", "B", "C", "D", "E", "F", "G", "H"]
        top_swapped = ["B", "A", "C", "D", "E", "F", "G", "H"]
        bottom_swapped = ["A", "B", "C", "D", "E", "F", "H", "G"]

        rbo_top = rank_biased_overlap(base, top_swapped, p=0.8)
        rbo_bottom = rank_biased_overlap(base, bottom_swapped, p=0.8)
        assert rbo_top < rbo_bottom

    def test_ranking_concordance_schema(self):
        l1 = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-38606"]
        l2 = ["CVE-2021-44228", "CVE-2023-38606", "CVE-2022-22965"]
        conc = compute_ranking_concordance(l1, l2)
        assert "spearman_rho" in conc
        assert "kendall_tau" in conc
        assert "rank_biased_overlap" in conc
        assert "sample_size" in conc
        assert conc["sample_size"] == 3


class TestSSVCEvaluation:
    def test_ssvc_act_on_active_and_open(self):
        res = evaluate_ssvc(
            in_cisa_kev=True,
            epss_prob=0.85,
            exposure_factor=1.0,
            is_behind_waf=False,
            is_network_automatable=True,
            business_criticality=9.0,
        )
        assert res["decision"] == "Act"
        assert res["exploitation"] == "Active"
        assert res["exposure"] == "Open"
        assert "< 24-48 hours" in res["action_urgency"]
        assert "decision_path" in res
        assert "rationale" in res

    def test_ssvc_attend_on_active_shielded(self):
        res = evaluate_ssvc(
            in_cisa_kev=True,
            epss_prob=0.85,
            exposure_factor=0.5,
            is_behind_waf=True,
            is_network_automatable=False,
            business_criticality=5.0,
        )
        assert res["decision"] == "Attend"
        assert res["exposure"] == "Controlled"

    def test_ssvc_track_on_low_threat_internal(self):
        res = evaluate_ssvc(
            in_cisa_kev=False,
            epss_prob=0.002,
            exposure_factor=0.2,
            is_behind_waf=False,
            is_network_automatable=False,
            business_criticality=3.0,
            cvss_base_score=4.0,
        )
        assert res["decision"] == "Track"
        assert res["exploitation"] == "None"
        assert res["exposure"] == "Small"

    def test_ssvc_track_star_for_active_low_mission(self):
        res = evaluate_ssvc(
            in_cisa_kev=True,
            epss_prob=0.60,
            exposure_factor=0.2,
            business_criticality=3.0,
            cvss_base_score=4.0,
        )
        assert res["decision"] == "Track*"


class TestUncertaintyQuantification:
    def test_risk_interval_bounds(self):
        res = compute_risk_interval(point_score=7.5)
        lower, upper = res["risk_interval_90"]
        assert 1.0 <= lower <= 7.5
        assert 7.5 <= upper <= 10.0
        assert res["point_score"] == 7.5
        assert res["coverage_nominal"] == 0.90
        assert "conformal" in res["method"]

    def test_risk_interval_widens_for_banner_and_unknown_reachability(self):
        baseline = compute_risk_interval(point_score=5.0, finding_context={})
        banner_unknown = compute_risk_interval(
            point_score=5.0,
            finding_context={
                "source": "http_header_banner",
                "code_reachability": "unknown (no source provided)",
                "advisory_confidence": "conflicting",
            },
        )
        assert banner_unknown["dispersion_margin"] > baseline["dispersion_margin"]
        assert len(banner_unknown["uncertainty_widening_factors"]) >= 2

    def test_risk_interval_extreme_clamping(self):
        res_high = compute_risk_interval(point_score=9.9)
        assert res_high["risk_interval_90"][1] <= 10.0

        res_low = compute_risk_interval(point_score=1.1)
        assert res_low["risk_interval_90"][0] >= 1.0


class TestFAIRLossSimulation:
    def test_fair_reproducibility(self):
        sim1 = simulate_fair_loss(epss_prob=0.45, business_criticality=8.0, seed=123)
        sim2 = simulate_fair_loss(epss_prob=0.45, business_criticality=8.0, seed=123)
        assert sim1["ale_mean"] == sim2["ale_mean"]
        assert sim1["ci_90"] == sim2["ci_90"]
        assert sim1["ale_max"] == sim2["ale_max"]

    def test_fair_probability_monotonicity(self):
        low_threat = simulate_fair_loss(epss_prob=0.01, seed=42)
        high_threat = simulate_fair_loss(epss_prob=0.80, seed=42)
        assert high_threat["ale_mean"] > low_threat["ale_mean"]
        assert high_threat["loss_probability"] > low_threat["loss_probability"]

    def test_fair_criticality_scaling(self):
        low_crit = simulate_fair_loss(epss_prob=0.50, business_criticality=2.0, seed=42)
        high_crit = simulate_fair_loss(epss_prob=0.50, business_criticality=10.0, seed=42)
        assert high_crit["ale_mean"] > low_crit["ale_mean"]
        assert high_crit["parameters"]["loss_magnitude_max"] > low_crit["parameters"]["loss_magnitude_max"]

    def test_fair_disclaimer_presence(self):
        res = simulate_fair_loss(epss_prob=0.10)
        assert res["assumption_disclaimer"] == DISCLAIMER_TEXT
        assert "illustrative" in res["assumption_disclaimer"]

    def test_fair_portfolio_aggregation(self):
        findings = [
            {"epss_probability": 0.40, "in_cisa_kev": True, "xai_formula": {"s_exposure": 1.0, "s_crit": 0.8}},
            {"epss_probability": 0.05, "in_cisa_kev": False, "xai_formula": {"s_exposure": 0.3, "s_crit": 0.4}},
        ]
        port = simulate_portfolio_fair_loss(findings, simulations=500, seed=42)
        assert port["portfolio_ale_mean"] > 0
        assert port["findings_modeled"] == 2
        assert port["portfolio_ci_90"][0] <= port["portfolio_ci_90"][1]


class TestWeightCalibration:
    def test_extract_cve_year(self):
        assert extract_cve_year("CVE-2021-44228") == 2021
        assert extract_cve_year("cve-2024-3094") == 2024
        assert extract_cve_year("INVALID-STRING", default_year=2020) == 2020

    def test_build_calibration_dataset(self):
        dataset = build_calibration_dataset(seed=42, num_samples=100)
        assert len(dataset) == 100
        pos = sum(1 for d in dataset if d["in_kev"] == 1)
        neg = sum(1 for d in dataset if d["in_kev"] == 0)
        assert pos > 0
        assert neg > 0
        assert all(0.0 <= d["s_cvss"] <= 1.0 for d in dataset)
        assert all(0.0 <= d["s_epss"] <= 1.0 for d in dataset)

    def test_calibration_pipeline_and_leakage_protection(self):
        report = calibrate_scoring_weights(split_year=2023, seed=42, num_samples=300)
        assert report["split_year"] == 2023
        assert report["sample_counts"]["train_pre_split"] > 0
        assert report["sample_counts"]["test_post_split"] > 0

        # Weights sum to approximately 1.0
        w = report["learned_weights"]
        total_w = sum(w.values())
        assert math.isclose(total_w, 1.0, abs_tol=0.01)

        # Comparative metrics contain all required baselines
        metrics = report["comparative_metrics"]
        assert "calibrated_weights" in metrics
        assert "default_production_weights" in metrics
        assert "cvss_only_baseline" in metrics
        assert "epss_only_baseline" in metrics

        for method in metrics:
            assert "k=10" in metrics[method]
            assert "precision" in metrics[method]["k=10"]
            assert "recall" in metrics[method]["k=10"]

    def test_opt_in_config_weight_loading(self, monkeypatch):
        # Default mode returns default weights
        monkeypatch.setattr(config, "SCORING_WEIGHTS_SOURCE", "default")
        weights = load_calibrated_weights()
        assert weights["cvss"] == 0.35
        assert weights["epss"] == 0.30

        # Calibrated mode with existing calibration file
        monkeypatch.setattr(config, "SCORING_WEIGHTS_SOURCE", "calibrated")
        cal_weights = load_calibrated_weights()
        assert sum(cal_weights.values()) > 0.0


class TestPrioritizeIntegration:
    def test_prioritize_findings_enriches_phase1_fields(self):
        findings = [
            {
                "title": "Log4Shell RCE in log4j-core",
                "cvss_score": 10.0,
                "epss_probability": 0.97,
                "in_cisa_kev": True,
                "affected_component": "log4j-core",
                "source": "verified_package_manifest",
            },
            {
                "title": "Weak Cipher Suites Allowed",
                "cvss_score": 5.0,
                "epss_probability": 0.002,
                "in_cisa_kev": False,
                "source": "http_header_banner",
            },
        ]
        discovery = {
            "target": "test-host.local",
            "mode": "PASSIVE OSINT",
            "discovered_assets": [{"port": 443, "state": "open"}],
            "waf": {"detected": False},
        }

        report = prioritize_findings(findings, discovery, business_criticality=0.8)
        assert "portfolio_fair_loss" in report
        assert "ssvc_summary" in report
        assert "scoring_metadata" in report
        assert report["total_findings"] == 2

        f0 = report["findings"][0]
        # Check SSVC
        assert "ssvc" in f0
        assert "ssvc_decision" in f0
        assert f0["ssvc_decision"] in ["Act", "Attend", "Track*", "Track"]

        # Check Uncertainty Interval
        assert "risk_interval_90" in f0
        low, high = f0["risk_interval_90"]["risk_interval_90"]
        assert 1.0 <= low <= high <= 10.0

        # Check FAIR Expected Loss
        assert "fair_expected_loss" in f0
        assert f0["fair_expected_loss"]["ale_mean"] >= 0.0
        assert "illustrative" in f0["fair_expected_loss"]["assumption_disclaimer"]

        # Backward compatibility checks
        assert "contextual_risk_score" in f0
        assert "priority_level" in f0
        assert "xai_formula" in f0
        assert "radar_comparison" in report
