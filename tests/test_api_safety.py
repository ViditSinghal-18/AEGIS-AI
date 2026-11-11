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


if __name__ == "__main__":
    unittest.main()
