"""Core Strands Agent implementation utilizing Amazon Bedrock and defensive tools."""

from __future__ import annotations

import os
from typing import Any

from config import AWS_REGION, BEDROCK_MODEL_ID
from agent.tools import active_scan, correlate, explain, passive_scan

SYSTEM_PROMPT = """You are a defensive AI Security Operations Center (SOC) agent.
Your primary role is to assist security analysts in discovering attack surfaces,
evaluating vulnerabilities (CVE, CISA KEV, FIRST EPSS), and recommending defensive mitigations.

Rules and Operational Guidance:
1. DEFENSE ONLY: Never generate attack scripts, exploits, payload injections, or denial-of-service commands.
2. PASSIVE vs ACTIVE:
   - Use `passive_scan` for external domains, OSINT discovery, and public reconnaissance.
   - Use `active_scan` ONLY when the user explicitly requests an active or port scan of a specific target,
     and only against verified/allowlisted systems.
3. GROUNDING: Strictly ground your tool arguments in what the user actually said. Never invent or hallucinate
   hosts, IP ranges, or ports. If a target is ambiguous, ask the user to clarify.
4. ACTIONABLE REMEDIATION: When explaining findings, provide concrete configuration fixes (e.g., Nginx headers,
   Express helmet configuration, or firewall rules) to improve the security posture.
"""


def get_bedrock_model(model_id: str | None = None, region_name: str | None = None) -> Any:
    """Create a configured Strands BedrockModel instance."""
    from strands.models.bedrock import BedrockModel

    resolved_model_id = model_id or BEDROCK_MODEL_ID or "amazon.nova-micro-v1:0"
    resolved_region = region_name or AWS_REGION or "us-east-1"

    return BedrockModel(
        model_id=resolved_model_id,
        region_name=resolved_region,
    )


def create_security_agent(
    model: Any | None = None,
    interventions: list[Any] | None = None,
    system_prompt: str = SYSTEM_PROMPT,
) -> Any:
    """Instantiate and configure the Strands defensive security agent.

    Args:
        model: Custom model instance (defaults to BedrockModel with BEDROCK_MODEL_ID).
        interventions: Optional list of Strands InterventionHandler instances.
                       Defaults to [GroundedToolCallIntervention()].
        system_prompt: System prompt instructing the agent on security boundaries.

    Returns:
        Configured strands.Agent instance.
    """
    from strands import Agent
    from decision_patterns.grounded_tool_call import GroundedToolCallIntervention

    agent_model = model or get_bedrock_model()
    agent_tools = [passive_scan, active_scan, correlate, explain]

    if interventions is None:
        interventions = [GroundedToolCallIntervention()]

    return Agent(
        model=agent_model,
        tools=agent_tools,
        interventions=interventions,
        system_prompt=system_prompt,
    )


def run_security_agent(
    prompt: str,
    agent: Any | None = None,
    interventions: list[Any] | None = None,
) -> Any:
    """Convenience runner for executing a prompt against the security agent."""
    active_agent = agent or create_security_agent(interventions=interventions)
    return active_agent(prompt)
