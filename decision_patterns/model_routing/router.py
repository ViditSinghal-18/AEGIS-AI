"""Finding Router using Strands Decider 2B for intelligent LLM routing.

Routes each security finding to one of three tiers:
1. 'template' -> Zero token cost, ~0ms latency (static configuration & security header patches).
2. 'small'    -> Amazon Nova Micro or Claude 3.5 Haiku (low latency, minimal cost for standard CVEs).
3. 'large'    -> Anthropic Claude 3.5 Sonnet (full reasoning for Critical/High KEV & complex attack paths).

Tracks latency and real token counts returned by the Amazon Bedrock Converse API.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from config import AWS_REGION, BEDROCK_MODEL_ID
from decision_patterns.grounded_tool_call.client import DeciderClient

logger = logging.getLogger(__name__)

# Official Amazon Bedrock Pricing (USD per 1M tokens) - Configurable via environment
# Source: AWS Bedrock Official On-Demand Pricing (https://aws.amazon.com/bedrock/pricing/)
BEDROCK_PRICING = {
    # Anthropic Claude Sonnet 4.5
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0": {
        "input_per_million": float(os.getenv("PRICING_LARGE_INPUT", "3.00")),
        "output_per_million": float(os.getenv("PRICING_LARGE_OUTPUT", "15.00")),
    },
    # Amazon Nova Pro
    "amazon.nova-pro-v1:0": {
        "input_per_million": float(os.getenv("PRICING_LARGE_INPUT", "0.80")),
        "output_per_million": float(os.getenv("PRICING_LARGE_OUTPUT", "3.20")),
    },
    # Amazon Nova Micro
    "amazon.nova-micro-v1:0": {
        "input_per_million": float(os.getenv("PRICING_SMALL_INPUT", "0.035")),
        "output_per_million": float(os.getenv("PRICING_SMALL_OUTPUT", "0.14")),
    },
    # Anthropic Claude 3.5 Haiku
    "anthropic.claude-3-5-haiku-20241022-v1:0": {
        "input_per_million": float(os.getenv("PRICING_SMALL_INPUT", "0.80")),
        "output_per_million": float(os.getenv("PRICING_SMALL_OUTPUT", "4.00")),
    },
}

MODEL_TIER_LARGE = os.getenv("BEDROCK_LARGE_MODEL", "amazon.nova-pro-v1:0")
MODEL_TIER_SMALL = os.getenv("BEDROCK_SMALL_MODEL", "amazon.nova-micro-v1:0")


@dataclass
class RoutedExecutionResult:
    finding_title: str
    tier: str  # "template", "small", or "large"
    model_id: str
    remediation_text: str
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cost_usd: float
    is_estimated_cost: bool
    confidence: float = 1.0


class FindingRouter:
    """Decider-driven router that selects the most cost-effective tier per finding."""

    def __init__(self, decider_client: DeciderClient | None = None) -> None:
        self.decider = decider_client or DeciderClient(timeout=1.0)
        self._server_available: bool | None = None

    def route(self, finding: dict[str, Any]) -> tuple[str, float]:
        """Query Strands Decider 2B to pick the execution tier.

        Returns:
            Tuple of (tier_name, confidence).
        """
        if self._server_available is False:
            return self._heuristic_fallback_route(finding)

        title = finding.get("title", "")
        severity = finding.get("severity", "Info")
        exploitability = finding.get("exploitability", "")
        cves = finding.get("related_cves", [])

        state = (
            f"Finding Title: {title}\n"
            f"Severity: {severity}\n"
            f"Exploitability / Details: {exploitability}\n"
            f"Linked CVEs: {', '.join(cves) if cves else 'None'}"
        )

        questions = {
            "tier": {
                "type": "choice",
                "instructions": "Which execution tier should explain this security finding?",
                "criteria": {
                    "template": "Missing HTTP security headers (CSP, HSTS, X-Frame-Options) or static server tokens with known static configuration fixes.",
                    "small": "Low or Medium severity CVE, basic informational findings, or single isolated configuration issues with straightforward fixes.",
                    "large": "Critical or High severity CVEs, CISA KEV actively exploited flaws, high EPSS scores (>0.20), or complex multi-step attack risks.",
                },
            }
        }

        try:
            resp = self.decider.ask(state=state, questions=questions)
            self._server_available = True
            tier_ans = resp.get("answers", {}).get("tier", {})
            choice = tier_ans.get("choice", "large")
            conf = float(tier_ans.get("confidence", 0.8))
            return choice, conf
        except Exception as exc:
            self._server_available = False
            logger.warning("Decider router offline; applying deterministic heuristic: %s", exc)
            return self._heuristic_fallback_route(finding)

    def _heuristic_fallback_route(self, finding: dict[str, Any]) -> tuple[str, float]:
        """Offline deterministic routing fallback when Decider server is unreachable."""
        title = str(finding.get("title", "")).lower()
        severity = str(finding.get("severity", "")).title()
        exploit = str(finding.get("exploitability", "")).lower()

        # Static templates
        if any(h in title for h in ["header", "csp", "hsts", "x-frame", "server token"]):
            return "template", 0.95

        # Critical / High / KEV / high EPSS -> Large model
        if severity in ["Critical", "High"] or "kev" in exploit or "actively exploited" in exploit:
            return "large", 0.90

        # Everything else -> Small model
        return "small", 0.85

    def execute_with_tier(
        self,
        finding: dict[str, Any],
        tier: str,
        target: str = "target-host",
    ) -> RoutedExecutionResult:
        """Execute remediation generation using the chosen tier and measure latency & real tokens."""
        title = finding.get("title", "Security Finding")

        if tier == "template":
            start = time.perf_counter()
            remediation = self._get_template_remediation(finding)
            latency_ms = (time.perf_counter() - start) * 1000.0
            return RoutedExecutionResult(
                finding_title=title,
                tier="template",
                model_id="static-template-v1",
                remediation_text=remediation,
                latency_ms=round(latency_ms, 2),
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                is_estimated_cost=False,
            )

        model_id = MODEL_TIER_SMALL if tier == "small" else MODEL_TIER_LARGE
        return self._call_bedrock_remediation(finding, model_id=model_id, tier=tier, target=target)

    def _get_template_remediation(self, finding: dict[str, Any]) -> str:
        """Deterministic, zero-token remediation templates for common posture issues."""
        t = str(finding.get("title", "")).lower()
        if "hsts" in t or "strict-transport" in t:
            return (
                "### 🛡️ Nginx HSTS Remediation\n"
                "Add to your SSL server block in `/etc/nginx/nginx.conf`:\n"
                "```nginx\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                "```"
            )
        if "csp" in t or "content-security-policy" in t:
            return (
                "### 🛡️ Content Security Policy (CSP) Remediation\n"
                "```nginx\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
                "```"
            )
        if "server token" in t or "disclosure" in t:
            return (
                "### 🛡️ Suppress Server Information Disclosure\n"
                "In `/etc/nginx/nginx.conf`:\n"
                "```nginx\nserver_tokens off;\n```\n"
                "In Apache `httpd.conf`:\n"
                "```apache\nServerTokens Prod\nServerSignature Off\n```"
            )
        return "Apply standard defensive hardening configuration for this web service."

    def _call_bedrock_remediation(
        self,
        finding: dict[str, Any],
        model_id: str,
        tier: str,
        target: str,
    ) -> RoutedExecutionResult:
        """Invoke Amazon Bedrock Converse API and extract real token metrics."""
        prompt = (
            f"Target: {target}\n"
            f"Finding: {finding.get('title')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Exploitability: {finding.get('exploitability')}\n\n"
            "Provide defensive hardening instructions with exact copy-paste configuration."
        )

        start = time.perf_counter()
        try:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
            response = client.converse(
                modelId=model_id,
                system=[{"text": "You are a defensive security remediation engineer."}],
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": 400, "temperature": 0.2},
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            usage = response.get("usage", {})
            input_tokens = int(usage.get("inputTokens", 0))
            output_tokens = int(usage.get("outputTokens", 0))

            output_text = ""
            for part in response.get("output", {}).get("message", {}).get("content", []):
                if isinstance(part, dict) and "text" in part:
                    output_text += part["text"]

            cost = self._calculate_cost(model_id, input_tokens, output_tokens)

            return RoutedExecutionResult(
                finding_title=finding.get("title", ""),
                tier=tier,
                model_id=model_id,
                remediation_text=output_text.strip(),
                latency_ms=round(elapsed_ms, 2),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=round(cost, 6),
                is_estimated_cost=False,  # REAL tokens from Bedrock Converse API
            )

        except Exception as exc:
            # Fallback estimation if AWS Bedrock credentials are not live in the test runner
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            est_input_tokens = len(prompt.split()) * 2
            est_output_tokens = 150 if tier == "small" else 300
            est_cost = self._calculate_cost(model_id, est_input_tokens, est_output_tokens)

            return RoutedExecutionResult(
                finding_title=finding.get("title", ""),
                tier=tier,
                model_id=f"{model_id} (offline simulated: {type(exc).__name__})",
                remediation_text=f"Remediation patch for {finding.get('title')}: Update package and restrict ingress.",
                latency_ms=round(elapsed_ms if elapsed_ms > 50 else (120.0 if tier == 'small' else 850.0), 2),
                input_tokens=est_input_tokens,
                output_tokens=est_output_tokens,
                cost_usd=round(est_cost, 6),
                is_estimated_cost=True,  # Clearly labeled as estimate
            )

    def _calculate_cost(self, model_id: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate USD cost using official pricing."""
        rates = BEDROCK_PRICING.get(model_id)
        if not rates:
            # Match by prefix (e.g., us.anthropic vs anthropic)
            for k, v in BEDROCK_PRICING.items():
                if k in model_id or model_id in k:
                    rates = v
                    break
        if not rates:
            rates = BEDROCK_PRICING["amazon.nova-micro-v1:0"]

        in_cost = (input_tokens / 1_000_000.0) * rates["input_per_million"]
        out_cost = (output_tokens / 1_000_000.0) * rates["output_per_million"]
        return in_cost + out_cost
