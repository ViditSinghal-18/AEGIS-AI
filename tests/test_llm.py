"""
Unit tests for ai/llm.py — provider-neutral LLM abstraction.

All HTTP calls are mocked; no live network or AWS credentials required.
Covers: none provider, openai_compatible success/failure, 429 retry,
key-masking, tier routing, copilot fallback, router failure, prioritize
fallback text, get_model() error on none.
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _openai_response(text: str = "READY", in_tokens: int = 5, out_tokens: int = 1) -> dict:
    """Build a minimal OpenAI-style chat/completions response dict."""
    return {
        "choices": [{"message": {"content": text}}],
        "model": "test-model-id",
        "usage": {"prompt_tokens": in_tokens, "completion_tokens": out_tokens},
    }


# ---------------------------------------------------------------------------
# 1. Default provider is 'none' — zero LLM calls, raises LLMUnavailable
# ---------------------------------------------------------------------------

def test_default_provider_is_none(monkeypatch):
    """With no env vars set, provider must be 'none' and complete() must raise."""
    monkeypatch.delenv("AEGIS_LLM_PROVIDER", raising=False)
    # Re-import to pick up clean env
    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    assert llm_mod.active_provider() == "none"
    assert not llm_mod.is_enabled()
    with pytest.raises(llm_mod.LLMUnavailable):
        llm_mod.complete("sys", "user")


# ---------------------------------------------------------------------------
# 2. Unknown provider string treated as 'none'
# ---------------------------------------------------------------------------

def test_unknown_provider_treated_as_none(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "magic_unicorn_llm")
    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    assert llm_mod.active_provider() == "none"
    with pytest.raises(llm_mod.LLMUnavailable):
        llm_mod.complete("sys", "user")


# ---------------------------------------------------------------------------
# 3. AWS env vars alone must NOT enable Bedrock implicitly
# ---------------------------------------------------------------------------

def test_aws_env_vars_alone_do_not_enable_bedrock(monkeypatch):
    monkeypatch.delenv("AEGIS_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    assert llm_mod.active_provider() == "none"
    with pytest.raises(llm_mod.LLMUnavailable):
        llm_mod.complete("sys", "user")


# ---------------------------------------------------------------------------
# 4. openai_compatible success — measures tokens/model/latency, Bearer header
# ---------------------------------------------------------------------------

def test_openai_compatible_success(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "gsk_test_key_12345")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "llama-3.1-8b-instant")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = _openai_response("READY", in_tokens=10, out_tokens=2)

    captured_headers = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured_headers.update(headers or {})
        return mock_resp

    with patch("requests.post", side_effect=fake_post):
        result = llm_mod.complete("sys", "user", max_tokens=5)

    assert result.text == "READY"
    assert result.model_id == "test-model-id"
    assert result.provider == "openai_compatible"
    assert result.input_tokens == 10
    assert result.output_tokens == 2
    assert result.latency_ms >= 0
    assert "Authorization" in captured_headers
    assert captured_headers["Authorization"].startswith("Bearer ")
    # Key must NOT appear in the header value masked form check
    assert "gsk_test_key_12345" in captured_headers["Authorization"]


# ---------------------------------------------------------------------------
# 5. Missing AEGIS_LLM_API_KEY → LLMUnavailable
# ---------------------------------------------------------------------------

def test_missing_api_key_raises(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.delenv("AEGIS_LLM_API_KEY", raising=False)
    monkeypatch.setenv("AEGIS_LLM_MODEL", "llama-3.1-8b-instant")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    with pytest.raises(llm_mod.LLMUnavailable):
        llm_mod.complete("sys", "user")


# ---------------------------------------------------------------------------
# 6. Missing AEGIS_LLM_MODEL → LLMUnavailable
# ---------------------------------------------------------------------------

def test_missing_model_raises(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "gsk_test_key")
    monkeypatch.delenv("AEGIS_LLM_MODEL", raising=False)
    monkeypatch.delenv("AEGIS_LLM_MODEL_LARGE", raising=False)

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    with pytest.raises(llm_mod.LLMUnavailable):
        llm_mod.complete("sys", "user")


# ---------------------------------------------------------------------------
# 7. HTTP 429 → retries once with Retry-After, then succeeds
# ---------------------------------------------------------------------------

def test_http_429_retry_succeeds(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "gsk_test")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "llama-3.1-8b-instant")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    call_count = [0]

    def fake_post(url, json=None, headers=None, timeout=None):
        call_count[0] += 1
        if call_count[0] == 1:
            resp = MagicMock()
            resp.status_code = 429
            resp.headers = {"Retry-After": "0"}
            resp.json.return_value = {"error": "rate limit"}
            return resp
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = _openai_response("READY")
        return resp

    with patch("requests.post", side_effect=fake_post):
        with patch("time.sleep"):  # don't actually sleep in tests
            result = llm_mod.complete("sys", "user")

    assert call_count[0] == 2
    assert result.text == "READY"


# ---------------------------------------------------------------------------
# 8. HTTP errors don't leak the API key in exception message
# ---------------------------------------------------------------------------

def test_http_error_does_not_leak_api_key(monkeypatch):
    api_key = "gsk_super_secret_key_XYZ"
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", api_key)
    monkeypatch.setenv("AEGIS_LLM_MODEL", "llama-3.1-8b-instant")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    def fake_post(url, json=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 401
        resp.json.return_value = {"error": f"Unauthorized: key={api_key}"}
        return resp

    with patch("requests.post", side_effect=fake_post):
        with pytest.raises(llm_mod.LLMUnavailable) as exc_info:
            llm_mod.complete("sys", "user")

    assert api_key not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 9. tier="large" uses AEGIS_LLM_MODEL_LARGE
# ---------------------------------------------------------------------------

def test_tier_large_uses_large_model(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "gsk_test")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "llama-3.1-8b-instant")
    monkeypatch.setenv("AEGIS_LLM_MODEL_LARGE", "llama-3.3-70b-versatile")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    captured_body = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured_body.update(json or {})
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = _openai_response()
        return resp

    with patch("requests.post", side_effect=fake_post):
        llm_mod.complete("sys", "user", tier="large")

    assert captured_body.get("model") == "llama-3.3-70b-versatile"


# ---------------------------------------------------------------------------
# 10. Copilot: LLM enabled → uses LLM; LLM fails → falls back to offline
# ---------------------------------------------------------------------------

def test_copilot_uses_llm_when_enabled():
    from ai.copilot import _call_llm_copilot, _generate_offline_copilot_response, query_copilot

    report = {"target": "example.com", "findings": [], "summary": "No issues.", "top_risks": []}

    with patch("ai.llm.is_enabled", return_value=True):
        with patch("ai.llm.complete") as mock_complete:
            mock_result = MagicMock()
            mock_result.text = "LLM copilot answer"
            mock_complete.return_value = mock_result
            answer = query_copilot("executive briefing", report)

    assert "LLM copilot answer" in answer


def test_copilot_falls_back_to_offline_when_llm_fails():
    from ai.copilot import query_copilot
    import ai.llm as llm_mod

    report = {"target": "example.com", "findings": [], "summary": "No issues.", "top_risks": [], "mode": "passive"}

    with patch("ai.llm.is_enabled", return_value=True):
        with patch("ai.llm.complete", side_effect=llm_mod.LLMUnavailable("test failure")):
            answer = query_copilot("executive briefing", report)

    # Should fall back to the offline reasoner
    assert "example.com" in answer


# ---------------------------------------------------------------------------
# 11. Router failure: returns template text with correct zero values
# ---------------------------------------------------------------------------

def test_router_failure_returns_zero_tokens_no_estimate():
    from decision_patterns.model_routing.router import FindingRouter
    import ai.llm as llm_mod

    router = FindingRouter()
    finding = {
        "title": "Test CVE Finding",
        "severity": "High",
        "exploitability": "Active exploit in KEV.",
        "related_cves": ["CVE-2024-0001"],
    }

    with patch("ai.llm.complete", side_effect=llm_mod.LLMUnavailable("no provider")):
        result = router.execute_with_tier(finding, tier="large", target="test-host")

    assert result.input_tokens == 0
    assert result.output_tokens == 0
    assert result.cost_usd == 0.0
    assert result.is_estimated_cost is False
    assert "llm-unavailable" in result.model_id.lower()


# ---------------------------------------------------------------------------
# 12. Router with free provider (openai_compatible): cost_usd == 0.0
# ---------------------------------------------------------------------------

def test_router_free_provider_zero_cost(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai_compatible")

    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    from decision_patterns.model_routing.router import FindingRouter

    router = FindingRouter()
    finding = {"title": "Test", "severity": "Low", "exploitability": "minimal", "related_cves": []}

    mock_result = MagicMock()
    mock_result.text = "Apply patch."
    mock_result.model_id = "llama-3.1-8b-instant"
    mock_result.input_tokens = 50
    mock_result.output_tokens = 30

    with patch("ai.llm.complete", return_value=mock_result):
        with patch("ai.llm.active_provider", return_value="openai_compatible"):
            result = router.execute_with_tier(finding, tier="small", target="test-host")

    assert result.cost_usd == 0.0


# ---------------------------------------------------------------------------
# 13. prioritize() with no LLM → "LLM fallback reason" in notes
# ---------------------------------------------------------------------------

def test_prioritize_no_llm_fallback_note():
    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    from ai.prioritize import prioritize

    correlated = {
        "target": "test-host",
        "mode": "passive",
        "assets": [
            {
                "service": "http",
                "product": "nginx",
                "version": "1.18.0",
                "exposure": "Public",
                "cves": [],
                "config_issues": [],
            }
        ],
    }

    with patch("ai.llm.is_enabled", return_value=False):
        with patch("ai.llm.complete", side_effect=llm_mod.LLMUnavailable("no provider")):
            with patch("storage.write_json"):
                report = prioritize(correlated)

    notes_text = " ".join(report.notes)
    assert "LLM fallback reason" in notes_text
    assert report.used_llm is False


# ---------------------------------------------------------------------------
# 14. get_model() with provider=none → RuntimeError
# ---------------------------------------------------------------------------

def test_get_model_none_provider_raises():
    import importlib
    import ai.llm as llm_mod
    importlib.reload(llm_mod)

    from agent.core import get_model

    with patch("ai.llm.active_provider", return_value="none"):
        with pytest.raises(RuntimeError, match="No LLM provider configured"):
            get_model()
