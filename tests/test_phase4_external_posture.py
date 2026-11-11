"""
Unit and integration tests for Phase 4: External Posture Intelligence.

Covers:
- Content Security Policy (CSP) quality grading (Weichselbaum et al. 2016)
- Email transport security and anti-spoofing grading (Durumeric et al. 2015)
- Evidence-grounded dangling DNS / subdomain takeover verification (Liu et al. 2016)
- High-precision secret and sensitive file detection with strict masking (Meli et al. 2019)
- Multi-factor breach propensity and external hygiene score (Liu et al. 2015)
- Correlation integration for Critical severity secrets and takeovers
"""

import unittest
from unittest.mock import MagicMock, patch

from discovery.csp_grader import grade_csp, parse_csp, CspGradeResult
from discovery.email_grader import (
    grade_email_security,
    parse_dmarc,
    parse_spf,
    EmailSecurityResult,
)
from discovery.dangling_dns import (
    verify_dangling_dns,
    DanglingDnsResult,
)
from discovery.secret_classifier import (
    mask_secret,
    shannon_entropy,
    classify_secrets_in_text,
    probe_exposed_files,
    ExposedSecretFinding,
)
from discovery.breach_propensity import (
    calculate_breach_propensity,
    BreachPropensityReport,
)
from correlation.correlate import correlate, _config_issues, _issue_severity


class TestCspGrader(unittest.TestCase):
    """Test suite for CSP AST parsing and defense grading."""

    def test_missing_csp_fails(self):
        result = grade_csp("")
        self.assertFalse(result.is_present)
        self.assertEqual(result.grade, "F")
        self.assertEqual(result.score, 0)
        self.assertTrue(len(result.weaknesses) > 0)
        self.assertIn("Missing Content-Security-Policy", result.weaknesses[0])

    def test_strict_csp_passes_with_a_plus(self):
        strict_header = (
            "default-src 'none'; "
            "script-src 'self' 'nonce-aGVsbG93b3JsZDEyMzQ1Njc4'; "
            "style-src 'self' 'nonce-aGVsbG93b3JsZDEyMzQ1Njc4'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "require-trusted-types-for 'script'"
        )
        result = grade_csp(strict_header)
        self.assertTrue(result.is_present)
        self.assertIn(result.grade, ["A+", "A"])
        self.assertGreaterEqual(result.score, 90)
        self.assertIn("script-src", result.parsed_directives)
        self.assertTrue(any("nonces or hashes" in s.lower() for s in result.strengths))

    def test_unsafe_inline_without_nonce_penalized(self):
        permissive = "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; object-src *;"
        result = grade_csp(permissive)
        self.assertTrue(result.is_present)
        self.assertIn(result.grade, ["D", "F"])
        self.assertLess(result.score, 60)
        weakness_text = " ".join(result.weaknesses)
        self.assertIn("'unsafe-inline'", weakness_text)
        self.assertIn("'unsafe-eval'", weakness_text)
        self.assertIn("Wildcard", weakness_text)

    def test_nonce_with_unsafe_inline_fallback_recognized(self):
        compat_csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'nonce-c2VjdXJlMTIzNDU2Nzg5'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )
        result = grade_csp(compat_csp)
        # Should recognize nonce overrides unsafe-inline in modern browsers
        self.assertTrue(any("backward compatibility" in s for s in result.strengths))
        self.assertGreaterEqual(result.score, 80)


class TestEmailGrader(unittest.TestCase):
    """Test suite for SPF, DMARC, MTA-STS, and TLS-RPT grading."""

    def test_parse_spf_hardfail(self):
        qual, issues = parse_spf("v=spf1 ip4:198.51.100.1 include:_spf.google.com -all")
        self.assertEqual(qual, "-all")
        self.assertEqual(issues, [])

    def test_parse_spf_softfail(self):
        qual, issues = parse_spf("v=spf1 ip4:198.51.100.1 ~all")
        self.assertEqual(qual, "~all")
        self.assertTrue(any("softfail" in iss for iss in issues))

    def test_parse_dmarc_reject(self):
        policy, pct, has_rua, issues = parse_dmarc("v=DMARC1; p=reject; pct=100; rua=mailto:sec@example.com")
        self.assertEqual(policy, "reject")
        self.assertEqual(pct, 100)
        self.assertTrue(has_rua)
        self.assertEqual(issues, [])

    def test_parse_dmarc_none_policy(self):
        policy, pct, has_rua, issues = parse_dmarc("v=DMARC1; p=none;")
        self.assertEqual(policy, "none")
        self.assertFalse(has_rua)
        self.assertTrue(any("monitoring only" in iss for iss in issues))
        self.assertTrue(any("lacks 'rua='" in iss for iss in issues))

    def test_hardened_domain_grade_a(self):
        res = grade_email_security(
            domain="hardened.example.com",
            spf_override="v=spf1 ip4:192.0.2.1 -all",
            dmarc_override="v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@hardened.example.com",
            mta_sts_override="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800",
            tls_rpt_override=True,
        )
        self.assertEqual(res.grade, "A+")
        self.assertGreaterEqual(res.score, 95)
        self.assertEqual(res.spf_qualifier, "-all")
        self.assertEqual(res.dmarc_policy, "reject")
        self.assertTrue(res.mta_sts_enabled)
        self.assertTrue(res.tls_rpt_enabled)

    def test_unprotected_domain_grade_f(self):
        res = grade_email_security(
            domain="unprotected.example.com",
            spf_override=None,
            dmarc_override=None,
            mta_sts_override=None,
            tls_rpt_override=False,
        )
        self.assertEqual(res.grade, "F")
        self.assertLessEqual(res.score, 30)
        self.assertIsNone(res.spf_record)
        self.assertIsNone(res.dmarc_record)


class TestDanglingDns(unittest.TestCase):
    """Test suite for evidence-grounded dangling DNS verification."""

    @patch("discovery.dangling_dns.safe_fetch")
    def test_github_pages_takeover_verified(self, mock_fetch):
        # Return 404 with authentic GitHub Pages unclaimed fingerprint
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<html><body><h1>404</h1><p>There isn't a GitHub Pages site here.</p></body></html>"
        mock_fetch.return_value = mock_resp

        res = verify_dangling_dns("docs.example.com", cname_target="example.github.io")
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.provider_name, "GitHub Pages")
        self.assertIn("There isn't a GitHub Pages site here", res.evidence)
        self.assertEqual(res.status_code, 404)

    @patch("discovery.dangling_dns.safe_fetch")
    def test_active_github_pages_not_vulnerable(self, mock_fetch):
        # Return 200 with normal active site
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body><h1>Welcome to My Documentation</h1></body></html>"
        mock_fetch.return_value = mock_resp

        res = verify_dangling_dns("docs.example.com", cname_target="example.github.io")
        self.assertFalse(res.is_vulnerable)
        self.assertIsNone(res.fingerprint_matched)

    @patch("discovery.dangling_dns.safe_fetch")
    def test_aws_s3_takeover_verified(self, mock_fetch):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
        mock_fetch.return_value = mock_resp

        res = verify_dangling_dns("assets.example.com", cname_target="assets-example.s3.amazonaws.com")
        self.assertTrue(res.is_vulnerable)
        self.assertEqual(res.provider_name, "Amazon S3")
        self.assertIn("NoSuchBucket", res.evidence)

    def test_unrecognized_cname_ignored(self):
        res = verify_dangling_dns("api.example.com", cname_target="custom-lb.internal.corp")
        self.assertFalse(res.is_vulnerable)
        self.assertIsNone(res.provider_name)


class TestSecretClassifier(unittest.TestCase):
    """Test suite for secret detection and strict non-disclosure masking."""

    def test_mask_secret_compliance(self):
        # Strict rule: never store/log raw values
        raw_aws = "AKIAIOSFODNN7EXAMPLE"
        masked_aws = mask_secret(raw_aws)
        self.assertEqual(masked_aws, "AKIA****MPLE")
        self.assertNotIn("IOSFODNN7", masked_aws)

        raw_gh = "ghp_0123456789abcdef0123456789abcdef0123"
        masked_gh = mask_secret(raw_gh)
        self.assertEqual(masked_gh, "ghp_****0123")
        self.assertNotIn("abcdef", masked_gh)

        # Short tokens
        self.assertEqual(mask_secret("secret"), "****")
        self.assertEqual(mask_secret("12345678"), "12****78")

    def test_shannon_entropy(self):
        low_ent = shannon_entropy("AAAAAAAAAAAAAAAAAAAA")
        self.assertLess(low_ent, 0.5)

        high_ent = shannon_entropy("7bF9#kP2$vXzQ1!mR8@wL5&yT4")
        self.assertGreater(high_ent, 3.8)

    def test_detect_aws_and_github_secrets(self):
        sample_text = (
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "export GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef0123\n"
            "dummy_var=AKIAAAAAAAAAAAAAAAAA\n"  # Low entropy repeated string, should be skipped
        )
        findings = classify_secrets_in_text(sample_text, location_source="https://example.com/config.js")
        self.assertEqual(len(findings), 2)

        # Verify AWS finding
        aws_finding = next(f for f in findings if "AWS" in f.secret_type)
        self.assertEqual(aws_finding.severity, "Critical")
        self.assertEqual(aws_finding.masked_hint, "AKIA****MPLE")
        # Ensure raw secret is NOT in finding attributes
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", aws_finding.masked_hint)

        # Verify GitHub finding
        gh_finding = next(f for f in findings if "GitHub" in f.secret_type)
        self.assertEqual(gh_finding.severity, "Critical")
        self.assertEqual(gh_finding.masked_hint, "ghp_****0123")

    @patch("discovery.secret_classifier.safe_fetch")
    def test_probe_exposed_git_head(self, mock_fetch):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ref: refs/heads/main\n"
        mock_fetch.return_value = mock_resp

        findings = probe_exposed_files("https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("Git Repository", findings[0].secret_type)
        self.assertEqual(findings[0].severity, "Critical")
        self.assertIn("/.git/HEAD", findings[0].location)


class TestBreachPropensity(unittest.TestCase):
    """Test suite for empirical breach propensity score calculation."""

    def test_hardened_posture(self):
        report = calculate_breach_propensity(
            target="secure.org",
            email_score=95.0,
            csp_score=90.0,
            tls_valid=True,
            tls_days_left=180,
            exposed_secrets_count=0,
            dangling_takeovers_count=0,
            open_ports=[443],
            missing_headers_count=0,
        )
        self.assertGreaterEqual(report.overall_score, 85.0)
        self.assertIn(report.posture_grade, ["A+", "A"])
        self.assertEqual(report.propensity_tier, "Low")
        self.assertTrue(len(report.positive_controls) > 0)

    def test_compromised_posture(self):
        report = calculate_breach_propensity(
            target="vulnerable.org",
            email_score=20.0,
            csp_score=0.0,
            tls_valid=False,
            tls_days_left=0,
            exposed_secrets_count=2,
            dangling_takeovers_count=1,
            open_ports=[22, 3389, 3306],
            missing_headers_count=4,
        )
        self.assertLessEqual(report.overall_score, 45.0)
        self.assertIn(report.posture_grade, ["D", "F"])
        self.assertIn(report.propensity_tier, ["High", "Critical"])
        self.assertTrue(len(report.key_deficiencies) > 0)


class TestCorrelationPhase4(unittest.TestCase):
    """Verify that Phase 4 discoveries integrate properly into correlation engine."""

    def test_secrets_and_takeovers_correlated_as_critical(self):
        sample_discovered = {
            "target": "example.com",
            "ports": [],
            "http": {"missing_security_headers": []},
            "tls": {"grade": "A", "raw": {}},
            "passive_meta": {
                "dns": {"issues": []},
                "ct_subdomains": [],
                "exposed_secrets": [
                    {
                        "secret_type": "AWS Access Key ID",
                        "location": "https://example.com/app.js",
                        "masked_hint": "AKIA****MPLE",
                    }
                ],
                "dangling_dns": [
                    {
                        "is_vulnerable": True,
                        "subdomain": "blog.example.com",
                        "provider_name": "GitHub Pages",
                        "cname_target": "org.github.io",
                    }
                ],
            },
        }

        issues_rich = _config_issues(sample_discovered)
        # Verify Critical severity assigned
        secret_issue = next((iss, sev) for iss, sev in issues_rich if "Exposed Secret" in iss)
        self.assertEqual(secret_issue[1], "Critical")
        self.assertIn("AKIA****MPLE", secret_issue[0])

        takeover_issue = next((iss, sev) for iss, sev in issues_rich if "Dangling Subdomain" in iss)
        self.assertEqual(takeover_issue[1], "Critical")
        self.assertIn("GitHub Pages", takeover_issue[0])

        # Test full correlate() output
        with patch("correlation.correlate.write_json"):
            findings = correlate(sample_discovered)
            self.assertEqual(len(findings.assets), 1)
            self.assertTrue(any("Exposed Secret" in c for c in findings.assets[0].config_issues))
            self.assertTrue(any("Dangling Subdomain" in c for c in findings.assets[0].config_issues))


if __name__ == "__main__":
    unittest.main()
