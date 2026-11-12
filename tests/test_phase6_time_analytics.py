"""
Unit and Integration Tests for Phase 6: Time-Aware Monitoring & Patch Analytics.

Covers:
- Kaplan–Meier vulnerability survival analysis (Li & Paxson 2017)
- Greenwood variance standard errors and 95% confidence intervals
- Median Time-to-Remediate (MTTR) calculation overall and by severity
- SLA breach probability evaluation
- Cumulative Sum (CUSUM) change-point risk score drift detection (Page 1954)
- Versioned historical scan snapshot persistence (schema_version: '2.0')
"""

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from analytics.drift_detector import (
    CusumDriftDetector,
    ChangePointResult,
    HISTORY_SCHEMA_VERSION,
    append_scan_snapshot,
    load_history,
    save_history,
)
from analytics.patch_lifetime import (
    compute_kaplan_meier,
    calculate_patch_analytics,
    KaplanMeierPoint,
    PatchAnalyticsReport,
)


class TestKaplanMeierAnalytics(unittest.TestCase):
    """Test suite for Kaplan-Meier survival curves and MTTR estimation."""

    def test_compute_kaplan_meier_mathematical_properties(self):
        # Durations in days, with events: [resolved, censored, resolved, resolved]
        durations = [5.0, 10.0, 15.0, 20.0]
        events = [True, False, True, True]

        curve = compute_kaplan_meier(durations, events)
        self.assertGreaterEqual(len(curve), 3)

        # 1. Curve must start at t=0 with S(0) = 1.0
        self.assertEqual(curve[0].time_days, 0.0)
        self.assertEqual(curve[0].survival_prob, 1.0)

        # 2. Survival curve must be non-increasing S(t_i) <= S(t_{i-1})
        for i in range(1, len(curve)):
            self.assertLessEqual(curve[i].survival_prob, curve[i - 1].survival_prob)

        # 3. 95% Confidence intervals must lie within [0.0, 1.0]
        for pt in curve:
            self.assertGreaterEqual(pt.ci_lower, 0.0)
            self.assertLessEqual(pt.ci_upper, 1.0)
            self.assertLessEqual(pt.ci_lower, pt.survival_prob)
            self.assertGreaterEqual(pt.ci_upper, pt.survival_prob)

    def test_calculate_patch_analytics_lifecycle(self):
        # 3 sequential weekly snapshots
        snapshots = [
            {
                "snapshot_id": "snap-1",
                "timestamp_days": 0.0,
                "overall_risk_score": 7.5,
                "findings": [
                    {"id": "F1", "title": "Apache RCE", "severity": "Critical"},
                    {"id": "F2", "title": "Missing HSTS", "severity": "High"},
                    {"id": "F3", "title": "Missing CSP", "severity": "Medium"},
                ],
            },
            {
                "snapshot_id": "snap-2",
                "timestamp_days": 7.0,
                "overall_risk_score": 5.0,
                "findings": [
                    # F1 (Apache RCE) was patched!
                    {"id": "F2", "title": "Missing HSTS", "severity": "High"},
                    {"id": "F3", "title": "Missing CSP", "severity": "Medium"},
                ],
            },
            {
                "snapshot_id": "snap-3",
                "timestamp_days": 14.0,
                "overall_risk_score": 3.0,
                "findings": [
                    # F2 (Missing HSTS) was patched! Only F3 persists
                    {"id": "F3", "title": "Missing CSP", "severity": "Medium"},
                ],
            },
        ]

        report = calculate_patch_analytics(snapshots)
        self.assertEqual(report.total_tracked, 3)
        self.assertEqual(report.remediated_count, 2)
        self.assertEqual(report.unremediated_count, 1)

        # F1 was resolved at day 7; F2 was resolved at day 14
        self.assertIsNotNone(report.overall_mttr_days)
        self.assertEqual(report.mttr_by_severity.get("Critical"), 7.0)
        self.assertEqual(report.mttr_by_severity.get("High"), 14.0)

        # SLA breach probabilities
        # Critical SLA target is 7 days: F1 was resolved at day 7 (within SLA)
        sla_probs = report.sla_breach_probabilities
        self.assertIn("Critical", sla_probs)
        self.assertIn("High", sla_probs)
        self.assertGreaterEqual(sla_probs["Critical"], 0.0)
        self.assertLessEqual(sla_probs["Critical"], 1.0)

    def test_empty_snapshots_handled_cleanly(self):
        report = calculate_patch_analytics([])
        self.assertEqual(report.total_tracked, 0)
        self.assertIsNone(report.overall_mttr_days)
        self.assertEqual(report.survival_curve, [])


class TestCusumDriftDetector(unittest.TestCase):
    """Test suite for two-sided CUSUM statistical change-point detection (Page 1954)."""

    def setUp(self):
        self.detector = CusumDriftDetector(k_sigma=0.5, h_sigma=3.5)

    def test_stable_series_no_drift(self):
        # Stable risk score with minor normal fluctuation
        stable_series = [5.0, 5.1, 4.9, 5.0, 5.2, 5.0, 4.8, 5.1]
        res = self.detector.detect(stable_series)
        self.assertFalse(res.drift_detected)
        self.assertEqual(res.direction, "stable")
        self.assertIsNone(res.change_point_index)
        self.assertIn("stable", res.explanation.lower())

    def test_deterioration_drift_detected(self):
        # Baseline ~4.0, then sharp persistent risk increase to 9.0
        deteriorating = [4.0, 4.1, 3.9, 4.0, 8.5, 9.0, 9.5, 9.2]
        res = self.detector.detect(deteriorating)
        self.assertTrue(res.drift_detected)
        self.assertEqual(res.direction, "deterioration")
        self.assertIsNotNone(res.change_point_index)
        self.assertGreaterEqual(res.shift_magnitude, 4.0)
        self.assertIn("Deterioration", res.explanation)

    def test_improvement_drift_detected(self):
        # Baseline ~9.0, then significant drop down to ~2.0
        improving = [9.0, 8.9, 9.1, 9.0, 3.5, 2.5, 2.0, 2.1]
        res = self.detector.detect(improving)
        self.assertTrue(res.drift_detected)
        self.assertEqual(res.direction, "improvement")
        self.assertIsNotNone(res.change_point_index)
        self.assertLess(res.shift_magnitude, -5.0)
        self.assertIn("Improvement", res.explanation)

    def test_short_series_graceful_handling(self):
        short_series = [5.0, 6.0]
        res = self.detector.detect(short_series)
        self.assertFalse(res.drift_detected)
        self.assertEqual(res.direction, "stable")
        self.assertIn("Insufficient", res.explanation)


class TestHistoryPersistence(unittest.TestCase):
    """Test suite for versioned history.json storage."""

    @patch("analytics.drift_detector._get_history_file_path")
    def test_append_snapshot_and_load(self, mock_path):
        tmp_history_file = Path("reports/test_temp_history.json")
        mock_path.return_value = tmp_history_file

        try:
            if tmp_history_file.exists():
                tmp_history_file.unlink()

            findings_1 = [
                {"title": "Open Port 80", "severity": "Info"},
                {"title": "Missing HSTS", "severity": "High"},
            ]
            hist, drift_1 = append_scan_snapshot("test.domain.com", 6.5, findings_1, timestamp_days=0.0)
            self.assertEqual(hist["schema_version"], HISTORY_SCHEMA_VERSION)
            self.assertEqual(len(hist["snapshots"]), 1)
            self.assertFalse(drift_1.drift_detected)

            # Append second scan
            findings_2 = [{"title": "Open Port 80", "severity": "Info"}]
            hist, drift_2 = append_scan_snapshot("test.domain.com", 2.0, findings_2, timestamp_days=7.0)
            self.assertEqual(len(hist["snapshots"]), 2)

            # Verify persisted content on disk
            loaded = load_history("test.domain.com")
            self.assertEqual(loaded["schema_version"], "2.0")
            self.assertEqual(len(loaded["snapshots"]), 2)
        finally:
            if tmp_history_file.exists():
                tmp_history_file.unlink()


if __name__ == "__main__":
    unittest.main()
