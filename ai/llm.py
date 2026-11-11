"""
Provider-neutral LLM abstraction for AEGIS-AI.

Provider is chosen ONLY by env AEGIS_LLM_PROVIDER:
  none             (default) – make zero LLM calls; raise LLMUnavailable
  openai_compatible – POST to {AEGIS_LLM_BASE_URL}/chat/completions with requests
  ollama            – same OpenAI-style call to {OLLAMA_HOST}/v1, no key needed
  bedrock           – lazy-import boto3 Converse API

AWS credentials present in the environment alone never enable Bedrock; the
provider must be explicitly set to "bedrock".

Never log or include API keys in errors or logs.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------
_PROVIDER_ENV = "AEGIS_LLM_PROVIDER"
_BASE_URL_ENV = "AEGIS_LLM_BASE_URL"
_API_KEY_ENV = "AEGIS_LLM_API_KEY"
_MODEL_ENV = "AEGIS_LLM_MODEL"
_MODEL_LARGE_ENV = "AEGIS_LLM_MODEL_LARGE"

_DEFAULT_OPENAI_BASE = "https://api.groq.com/openai/v1"
_VALID_PROVIDERS = frozenset({"none", "openai_compatible", "ollama", "bedrock"})


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------
@dataclass
class LLMResult:
    """All values are measured from the real API call, never estimated."""
    text: str
    model_id: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency_ms: float


class LLMUnavailable(Exception):
    """Raised when the LLM is not configured or a provider call fails."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _get_provider() -> str:
    raw = os.getenv(_PROVIDER_ENV, "none").strip().lower()
    if raw not in _VALID_PROVIDERS:
        logger.warning(
            "Unknown AEGIS_LLM_PROVIDER=%r; treating as 'none'. "
            "Valid choices: %s",
            raw,
            sorted(_VALID_PROVIDERS),
        )
        return "none"
    return raw


def _mask_key(key: str) -> str:
    """Return a masked hint; never the full key."""
    if not key:
        return "<empty>"
    return key[:4] + "****" + key[-4:] if len(key) > 8 else "****"


# ---------------------------------------------------------------------------
# Provider: openai_compatible  (Groq / Cerebras / OpenRouter / Gemini / …)
# ---------------------------------------------------------------------------
def _call_openai_compatible(
    system: str,
    user: str,
    *,
    max_tokens: int,
    temperature: float,
    tier: str,
) -> LLMResult:
    import requests as _requests  # stdlib-free import, only needed here

    base_url = os.getenv(_BASE_URL_ENV, _DEFAULT_OPENAI_BASE).rstrip("/")
    api_key = os.getenv(_API_KEY_ENV, "").strip()
    model_default = os.getenv(_MODEL_ENV, "").strip()
    model_large = os.getenv(_MODEL_LARGE_ENV, "").strip()

    if not api_key:
        raise LLMUnavailable(
            f"AEGIS_LLM_PROVIDER=openai_compatible but {_API_KEY_ENV} is not set."
        )
    model_id = (model_large if tier == "large" and model_large else model_default)
    if not model_id:
        raise LLMUnavailable(
            f"AEGIS_LLM_PROVIDER=openai_compatible but {_MODEL_ENV} is not set."
        )

    endpoint = f"{base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    def _do_request() -> "_requests.Response":
        return _requests.post(endpoint, json=payload, headers=headers, timeout=30)

    t0 = time.perf_counter()
    try:
        resp = _do_request()
        # Retry once on 429 honouring Retry-After (capped at 10 s)
        if resp.status_code == 429:
            retry_after = min(float(resp.headers.get("Retry-After", "2")), 10.0)
            logger.warning(
                "LLM provider returned 429; retrying after %.1f s", retry_after
            )
            time.sleep(retry_after)
            resp = _do_request()

        if resp.status_code != 200:
            # Do NOT include any response body that could contain reflected keys
            raise LLMUnavailable(
                f"LLM provider returned HTTP {resp.status_code} from {base_url}"
            )

        data = resp.json()
    except LLMUnavailable:
        raise
    except Exception as exc:
        # Mask URL to avoid leaking tokens embedded in query params
        raise LLMUnavailable(f"LLM request failed: {type(exc).__name__}") from exc

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    choices = data.get("choices") or []
    if not choices:
        raise LLMUnavailable("LLM provider returned empty choices list.")

    text = (choices[0].get("message") or {}).get("content") or ""
    returned_model = data.get("model") or model_id
    usage = data.get("usage") or {}
    input_tokens = int(usage.get("prompt_tokens", 0))
    output_tokens = int(usage.get("completion_tokens", 0))

    return LLMResult(
        text=text,
        model_id=returned_model,
        provider="openai_compatible",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=round(elapsed_ms, 2),
    )


# ---------------------------------------------------------------------------
# Provider: ollama
# ---------------------------------------------------------------------------
def _call_ollama(
    system: str,
    user: str,
    *,
    max_tokens: int,
    temperature: float,
    tier: str,
) -> LLMResult:
    import requests as _requests

    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    model_default = os.getenv(_MODEL_ENV, "llama3.2").strip()
    model_large = os.getenv(_MODEL_LARGE_ENV, "").strip()
    model_id = (model_large if tier == "large" and model_large else model_default)

    endpoint = f"{ollama_host}/v1/chat/completions"
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    t0 = time.perf_counter()
    try:
        resp = _requests.post(endpoint, json=payload, timeout=60)
        if resp.status_code != 200:
            raise LLMUnavailable(
                f"Ollama returned HTTP {resp.status_code} from {ollama_host}"
            )
        data = resp.json()
    except LLMUnavailable:
        raise
    except Exception as exc:
        raise LLMUnavailable(f"Ollama request failed: {type(exc).__name__}") from exc

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    choices = data.get("choices") or []
    if not choices:
        raise LLMUnavailable("Ollama returned empty choices list.")

    text = (choices[0].get("message") or {}).get("content") or ""
    usage = data.get("usage") or {}
    input_tokens = int(usage.get("prompt_tokens", 0))
    output_tokens = int(usage.get("completion_tokens", 0))

    return LLMResult(
        text=text,
        model_id=model_id,
        provider="ollama",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=round(elapsed_ms, 2),
    )


# ---------------------------------------------------------------------------
# Provider: bedrock  (boto3 is lazy-imported here and ONLY here)
# ---------------------------------------------------------------------------
def _call_bedrock(
    system: str,
    user: str,
    *,
    max_tokens: int,
    temperature: float,
    tier: str,
) -> LLMResult:
    try:
        import boto3  # noqa: PLC0415 – intentional lazy import
    except ImportError as exc:
        raise LLMUnavailable(
            "boto3 is not installed; install it to use the bedrock provider."
        ) from exc

    from config import AWS_REGION, BEDROCK_MODEL_ID  # noqa: PLC0415

    model_small = os.getenv("BEDROCK_SMALL_MODEL", BEDROCK_MODEL_ID or "amazon.nova-micro-v1:0")
    model_large_id = os.getenv("BEDROCK_LARGE_MODEL", "amazon.nova-pro-v1:0")
    model_id = model_large_id if tier == "large" else model_small

    # Build fallback list (Bedrock provider keeps existing multi-model fallback)
    candidates = [model_id]
    for fallback in [
        "amazon.nova-micro-v1:0",
        "amazon.nova-lite-v1:0",
        "us.anthropic.claude-3-5-haiku-20241022-v1:0",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0",
    ]:
        if fallback not in candidates:
            candidates.append(fallback)

    region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", getattr(AWS_REGION, '__class__', type)(AWS_REGION) if isinstance(AWS_REGION, str) else "us-east-1"))

    try:
        client = boto3.client("bedrock-runtime", region_name=region)
    except Exception as exc:
        raise LLMUnavailable(f"Failed to create Bedrock client: {type(exc).__name__}") from exc

    last_exc: Exception | None = None
    t0 = time.perf_counter()
    for mid in candidates:
        try:
            response = client.converse(
                modelId=mid,
                system=[{"text": system}],
                messages=[{"role": "user", "content": [{"text": user}]}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": temperature},
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            usage = response.get("usage", {})
            input_tokens = int(usage.get("inputTokens", 0))
            output_tokens = int(usage.get("outputTokens", 0))

            parts = response.get("output", {}).get("message", {}).get("content", [])
            text = "".join(
                p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p
            )
            if text:
                return LLMResult(
                    text=text,
                    model_id=mid,
                    provider="bedrock",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    latency_ms=round(elapsed_ms, 2),
                )
        except Exception as exc:
            last_exc = exc
            continue

    raise LLMUnavailable(
        f"All Bedrock model candidates failed. Last error: {type(last_exc).__name__}"
    ) from last_exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def active_provider() -> str:
    """Return the currently configured provider name (never raises)."""
    return _get_provider()


def is_enabled() -> bool:
    """Return True if any LLM provider is active (not 'none')."""
    return _get_provider() != "none"


def describe() -> str:
    """Return a human-readable UI label such as 'Groq: llama-3.1-8b-instant'."""
    prov = _get_provider()
    if prov == "none":
        return "Heuristic Engine (no LLM)"
    if prov == "openai_compatible":
        base = os.getenv(_BASE_URL_ENV, _DEFAULT_OPENAI_BASE)
        model = os.getenv(_MODEL_ENV, "<model not set>")
        # Derive a friendly name from the base URL
        if "groq" in base:
            label = "Groq"
        elif "cerebras" in base:
            label = "Cerebras"
        elif "openrouter" in base:
            label = "OpenRouter"
        elif "generativelanguage" in base or "googleapis" in base:
            label = "Gemini"
        else:
            label = "OpenAI-compatible"
        return f"{label}: {model}"
    if prov == "ollama":
        host = os.getenv("OLLAMA_HOST", "localhost:11434")
        model = os.getenv(_MODEL_ENV, "llama3.2")
        return f"Ollama ({host}): {model}"
    if prov == "bedrock":
        try:
            from config import BEDROCK_MODEL_ID  # noqa: PLC0415
            model = os.getenv("BEDROCK_SMALL_MODEL", BEDROCK_MODEL_ID or "amazon.nova-micro-v1:0")
        except Exception:
            model = os.getenv("BEDROCK_SMALL_MODEL", "amazon.nova-micro-v1:0")
        return f"Amazon Bedrock: {model}"
    return f"Unknown provider: {prov}"


def complete(
    system: str,
    user: str,
    *,
    max_tokens: int = 1000,
    temperature: float = 0.2,
    tier: str = "default",
) -> LLMResult:
    """
    Send a chat completion request to the configured LLM provider.

    Args:
        system: System prompt text.
        user: User message text.
        max_tokens: Maximum tokens to generate.
        temperature: Sampling temperature.
        tier: "default" / "small" for standard models, "large" for high-capacity models.

    Returns:
        LLMResult with real measured values.

    Raises:
        LLMUnavailable: If no provider is configured or the call fails.
    """
    prov = _get_provider()
    if prov == "none":
        raise LLMUnavailable(
            "No LLM provider configured. Set AEGIS_LLM_PROVIDER to "
            "'openai_compatible', 'ollama', or 'bedrock'."
        )

    kwargs = dict(
        system=system,
        user=user,
        max_tokens=max_tokens,
        temperature=temperature,
        tier=tier,
    )

    try:
        if prov == "openai_compatible":
            return _call_openai_compatible(**kwargs)
        if prov == "ollama":
            return _call_ollama(**kwargs)
        if prov == "bedrock":
            return _call_bedrock(**kwargs)
    except LLMUnavailable:
        raise
    except Exception as exc:
        raise LLMUnavailable(f"Provider '{prov}' call failed: {type(exc).__name__}") from exc

    raise LLMUnavailable(f"Unhandled provider: {prov}")
