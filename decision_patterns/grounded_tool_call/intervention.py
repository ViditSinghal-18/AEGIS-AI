"""Grounded Tool Call Intervention (#guardrails).

Enforces a two-tier defense pattern for agent tool execution:
1. Deterministic Hard Gate: Allowlist and domain ownership verification checked FIRST.
2. Semantic Grounding Gate: Strands Decider 2B evaluates if proposed target and ports
   are grounded in the user's input, returning `Guide` to steer the agent to clarify if ungrounded.
3. Fail-Closed: Defaults to `Deny` on server timeouts or runtime errors.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from strands.hooks.events import BeforeToolCallEvent
from strands.interventions import Deny, Guide, InterventionHandler, OnError, Proceed

from config import is_target_allowed
from decision_patterns.grounded_tool_call.client import DeciderClient, DeciderClientError

logger = logging.getLogger(__name__)

DEFAULT_DECIDER_THRESHOLD = 0.7


class GroundedToolCallIntervention(InterventionHandler):
    """Strands InterventionHandler implementing the Grounded Tool Call guardrail pattern (#guardrails)."""

    name = "grounded-tool-call"

    def __init__(
        self,
        decider_client: DeciderClient | None = None,
        threshold: float | None = None,
        on_error: OnError = "deny",
    ) -> None:
        """Initialize the Grounded Tool Call guardrail.

        Args:
            decider_client: Optional DeciderClient instance (reads DECIDER_URL if omitted).
            threshold: Confidence threshold for ungrounded decisions (defaults to DECIDER_THRESHOLD or 0.7).
            on_error: Fallback action on exception (must be 'deny' for strict fail-closed security).
        """
        self.decider_client = decider_client or DeciderClient()
        env_threshold = os.getenv("DECIDER_THRESHOLD")
        if threshold is not None:
            self.threshold = float(threshold)
        elif env_threshold is not None and env_threshold.strip():
            self.threshold = float(env_threshold.strip())
        else:
            self.threshold = DEFAULT_DECIDER_THRESHOLD

        self._on_error: OnError = on_error

    @property
    def on_error(self) -> OnError:
        """Enforce fail-closed policy when this handler encounters errors."""
        return self._on_error

    def _extract_latest_user_message(self, event: BeforeToolCallEvent) -> str:
        """Extract the most recent user turn from the agent conversation history."""
        # 1. Check agent messages if available
        messages = getattr(event.agent, "messages", None)
        if messages and isinstance(messages, list):
            for msg in reversed(messages):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content")
                    if isinstance(content, str):
                        return content.strip()
                    if isinstance(content, list):
                        parts = [
                            p.get("text", "")
                            for p in content
                            if isinstance(p, dict) and "text" in p
                        ]
                        text = " ".join(parts).strip()
                        if text:
                            return text

        # 2. Fall back to invocation_state if passed explicitly
        invocation_state = getattr(event, "invocation_state", {}) or {}
        if isinstance(invocation_state, dict):
            for key in ["prompt", "user_prompt", "query", "input"]:
                if key in invocation_state and isinstance(invocation_state[key], str):
                    return invocation_state[key].strip()

        return ""

    def before_tool_call(self, event: BeforeToolCallEvent, **kwargs: Any) -> Proceed | Guide | Deny:
        """Evaluate deterministic authorization hard gate followed by Decider 2B grounding."""
        tool_name = event.tool_use.get("name", "")
        tool_input = event.tool_use.get("input", {}) or {}

        # =========================================================================
        # TIER 1: DETERMINISTIC HARD GATE (Always executed first; never bypassed)
        # =========================================================================
        if tool_name == "active_scan":
            target = str(tool_input.get("target", "")).strip()
            if not target:
                return Deny(reason="Hard Gate: Active scan refused because no target was specified.")

            if not is_target_allowed(target):
                return Deny(
                    reason=(
                        f"Hard Gate Blocked: Target '{target}' is not in targets.allowlist and not verified. "
                        "Active scanning is prohibited by safety policy."
                    )
                )

        # =========================================================================
        # TIER 2: STRANDS DECIDER 2B GROUNDING EVALUATION
        # =========================================================================
        user_message = self._extract_latest_user_message(event)

        state = (
            f"User Request:\n{user_message or '[No explicit user text found]'}\n\n"
            f"Proposed Tool Call:\n"
            f"Tool: {tool_name}\n"
            f"Arguments: {json.dumps(tool_input, indent=2)}"
        )

        question_instructions = (
            "Is this tool call's target and ports grounded in what the user actually said?"
        )
        criteria = {
            "true": "The tool call's target and ports were explicitly stated, referenced, or directly intended by the user.",
            "false": "The target or ports were invented, hallucinated, assumed, or injected without user request.",
        }

        try:
            p_grounded = self.decider_client.ask_noul(
                state=state,
                instructions=question_instructions,
                criteria=criteria,
                question_id="grounded_check",
            )

            # In noul: p_grounded is P(true) that tool call is grounded in user prompt.
            # Confidence that it is NOT grounded = 1.0 - p_grounded.
            p_not_grounded = 1.0 - p_grounded

            logger.info(
                "Decider grounding evaluation: tool=%s, p_grounded=%.3f, p_not_grounded=%.3f, threshold=%.3f",
                tool_name,
                p_grounded,
                p_not_grounded,
                self.threshold,
            )

            if p_not_grounded >= self.threshold:
                # Steer agent to ask user for clarification
                return Guide(
                    reason=(
                        f"The proposed tool call target and arguments ({tool_input}) do not appear grounded "
                        f"in the user's request (ungrounded confidence: {p_not_grounded:.2f} >= threshold {self.threshold:.2f}). "
                        "Please ask the user to clarify or confirm the target and ports before proceeding."
                    )
                )

            return Proceed()

        except Exception as exc:
            logger.error("GroundedToolCallIntervention encountered error: %s", exc, exc_info=True)
            if self.on_error == "deny":
                return Deny(
                    reason=f"Decider guardrail check failed ({type(exc).__name__}: {exc}). Failing closed by policy."
                )
            if self.on_error == "proceed":
                return Proceed()
            raise
