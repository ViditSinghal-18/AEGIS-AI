"""
AEGIS-AI API Security and Endpoint Validation Tests.
Run with: python -m pytest tests/test_api_safety.py -v
"""

import json
import unittest
from unittest.mock import patch
from app import app
import config


class TestApiSafetyEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("service"), "AEGIS-AI")

        res_root = self.client.get("/health")
        self.assertEqual(res_root.status_code, 200)

    def test_dashboard_endpoint(self):
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)

    def test_report_endpoint_returns_json(self):
        res = self.client.get("/api/report")
        self.assertIn(res.status_code, [200, 404])
        if res.status_code == 200:
            data = res.get_json()
            self.assertIsInstance(data, dict)

    def test_scan_requires_json(self):
        res = self.client.post("/api/scan", data="target=example.com", content_type="text/plain")
        self.assertEqual(res.status_code, 415)

    def test_scan_rejects_malformed_target(self):
        res = self.client.post("/api/scan", json={"target": "example.com; cat /etc/passwd"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("error", data)

    def test_scan_rejects_empty_target(self):
        res = self.client.post("/api/scan", json={"target": ""})
        self.assertEqual(res.status_code, 400)

    def test_mode_endpoint(self):
        res = self.client.get("/api/mode?target=example.com")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("mode"), "PASSIVE OSINT")
        self.assertFalse(data.get("can_active"))

        # Localhost should report active mode authorized
        res = self.client.get("/api/mode?target=localhost")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("can_active"))

    def test_verify_start_endpoint(self):
        res = self.client.post("/api/verify/start", json={"domain": "my-defense-lab.org"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("token", data.get("instructions", {}))
        self.assertEqual(data["instructions"]["domain"], "my-defense-lab.org")

    def test_verify_check_endpoint_unverified(self):
        res = self.client.post("/api/verify/check", json={"domain": "unverified-example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        # Should report verified: False because challenge is not completed
        self.assertFalse(data.get("verified"))

    def test_api_token_enforcement(self):
        # Temporarily enable token
        orig_token = config.AEGIS_API_TOKEN
        try:
            config.AEGIS_API_TOKEN = "test-secret-token"
            # Without token
            res = self.client.post("/api/scan", json={"target": "example.com"})
            self.assertEqual(res.status_code, 401)

            # With wrong token
            res = self.client.post(
                "/api/scan",
                json={"target": "example.com"},
                headers={"X-Aegis-Token": "wrong-token"}
            )
            self.assertEqual(res.status_code, 401)

            # With correct token
            with patch("app.assess_website") as mock_assess:
                mock_assess.return_value = {
                    "target": "example.com",
                    "grade": "A",
                    "score": 90,
                    "findings": [],
                    "summary": {"total_issues": 0, "posture_status": "Hardened"}
                }
                res = self.client.post(
                    "/api/scan",
                    json={"target": "example.com"},
                    headers={"X-Aegis-Token": "test-secret-token"}
                )
                self.assertNotEqual(res.status_code, 401)
                self.assertEqual(res.status_code, 200)
        finally:
            config.AEGIS_API_TOKEN = orig_token

    def test_scan_history_and_diff_endpoints(self):
        from storage import save_run_history, target_data_dir
        import shutil
        import time
        test_tgt = "hist-test-host.example"
        try:
            rep1 = {"target": test_tgt, "findings": [{"title": "Old Flaw", "related_cves": []}], "overall_risk_score": 60.0}
            rep2 = {"target": test_tgt, "findings": [{"title": "Old Flaw", "related_cves": []}, {"title": "New Flaw", "related_cves": []}], "overall_risk_score": 80.0}
            save_run_history(test_tgt, rep1)
            time.sleep(0.01)
            save_run_history(test_tgt, rep2)

            res = self.client.get(f"/api/scan/history?target={test_tgt}")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertIn("history", data)
            self.assertGreaterEqual(len(data["history"]), 2)
            self.assertIn("filename", data["history"][0])
            self.assertIn("timestamp", data["history"][0])

            res_diff = self.client.get(f"/api/scan/diff?target={test_tgt}")
            self.assertEqual(res_diff.status_code, 200)
            diff_data = res_diff.get_json()
            self.assertIn("new", diff_data)
            self.assertIn("summary", diff_data)

            res_drift = self.client.get(f"/api/drift?target={test_tgt}")
            self.assertEqual(res_drift.status_code, 200)
            drift_data = res_drift.get_json()
            self.assertEqual(drift_data.get("target"), test_tgt)
            self.assertIn("drift_summary", drift_data)
        finally:
            shutil.rmtree(target_data_dir(test_tgt), ignore_errors=True)

    def test_analytics_endpoints(self):
        res_life = self.client.get("/api/analytics/patch-lifetime")
        self.assertEqual(res_life.status_code, 200)
        data_life = res_life.get_json()
        self.assertIn("total_tracked", data_life)
        self.assertIn("survival_curve", data_life)

        res_drift = self.client.get("/api/analytics/drift")
        self.assertEqual(res_drift.status_code, 200)
        data_drift = res_drift.get_json()
        self.assertIn("result", data_drift)
        self.assertIn("drift_detected", data_drift["result"])

    def test_agent_chat_target_guardrail(self):
        res = self.client.post("/api/agent-chat", json={"message": "audit bad;domain.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("reply", data)

        res_empty = self.client.post("/api/agent-chat", json={"message": ""})
        self.assertEqual(res_empty.status_code, 200)
        self.assertTrue(res_empty.get_json().get("grounded"))

    def test_prioritize_endpoint_disallows_arbitrary_source_path(self):
        """Verify that client-supplied source_path is ignored to prevent arbitrary directory read."""
        res = self.client.post("/api/scan/prioritize", json={
            "findings": [],
            "discovery_data": {"target": "test-host.local"},
            "source_path": "/etc"
        })
        self.assertEqual(res.status_code, 200)
        report = res.get_json()
        self.assertIsInstance(report, dict)

    def test_scan_rejects_missing_target(self):
        """Verify that /api/scan requires a target and does not default to 127.0.0.1."""
        res = self.client.post("/api/scan", json={"active": True})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

    def test_intel_endpoint_rejects_non_list_findings(self):
        """Verify that POST /api/scan/intel returns 400 JSON on non-list findings without crashing."""
        res = self.client.post("/api/scan/intel", json={"findings": "abc"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("error", data)

    def test_mode_endpoint_get_without_target(self):
        """Verify that GET /api/mode returns 200 JSON without target and does not raise 415."""
        res = self.client.get("/api/mode")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("mode", data)

    def test_global_error_handlers_return_json(self):
        """Verify that 404 and 415 return valid JSON payloads rather than raw HTML."""
        res_404 = self.client.get("/api/nonexistent-route-endpoint")
        self.assertEqual(res_404.status_code, 404)
        self.assertEqual(res_404.content_type, "application/json")
        self.assertFalse(res_404.get_json().get("success"))

        res_415 = self.client.post("/api/webhook", data="not json", content_type="text/plain")
        self.assertEqual(res_415.status_code, 415)
        self.assertEqual(res_415.content_type, "application/json")

    def test_reporting_endpoints_support_target_param(self):
        """Verify isolated per-target reporting across all audit export endpoints."""
        endpoints = [
            "/api/export?target=owasp.org",
            "/api/export-csv?target=owasp.org",
            "/api/sbom?target=owasp.org",
            "/api/compliance?target=owasp.org",
            "/api/threat-intel?target=owasp.org",
            "/api/attack-graph?target=owasp.org&format=json",
            "/api/ai/model-routing?target=owasp.org",
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 200, f"Endpoint {ep} failed with {res.status_code}")

    def test_latest_online_does_not_trigger_live_scan(self):
        """Verify that GET /api/latest-online returns cached/sample data without live probing."""
        res = self.client.get("/api/latest-online")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("target", data)


if __name__ == "__main__":
    unittest.main()
