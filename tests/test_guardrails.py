"""Unit tests for GroundedToolCallIntervention (#guardrails).

Uses MockDeciderClient to verify control wiring only:
- Hard gate check executes FIRST before Decider
- Proceed path on grounded calls
- Guide path on ungrounded calls
- Fail-closed (Deny) on server timeout or connection error
- Message extraction from agent conversation turns

NOTE: Accuracy and false-block rates are reported exclusively by evals/eval_guardrail_live.py.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decision_patterns.grounded_tool_call.client import DeciderClientError
from decision_patterns.grounded_tool_call.intervention import GroundedToolCallIntervention
from strands.hooks.events import BeforeToolCallEvent
from strands.interventions import Deny, Guide, Proceed


class MockDeciderClient:
    """Mock client for deterministic unit testing without a live Decider daemon."""

    def __init__(self, p_grounded: float = 0.95, should_fail: bool = False, fail_error: Exception | None = None):
        self.p_grounded = p_grounded
        self.should_fail = should_fail
        self.fail_error = fail_error or DeciderClientError("Mock connection timeout")
        self.call_count = 0
        self.last_state = ""
        self.last_instructions = ""

    def is_healthy(self) -> bool:
        return not self.should_fail

    def ask(self, state: Any, questions: dict[str, Any], model: str = "strands-decider-latest") -> dict[str, Any]:
        self.call_count += 1
        self.last_state = str(state)
        if self.should_fail:
            raise self.fail_error
        answers = {}
        for q_id, q_val in questions.items():
            answers[q_id] = {"type": "noul", "noul": self.p_grounded}
        return {"model": "mock-decider", "answers": answers, "usage": {"input_tokens": 10, "output_tokens": 0}}

    def ask_noul(self, state: Any, instructions: str, criteria: dict[str, str] | None = None, question_id: str = "q") -> float:
        self.call_count += 1
        self.last_state = str(state)
        self.last_instructions = instructions
        if self.should_fail:
            raise self.fail_error
        return self.p_grounded


def _create_mock_event(
    tool_name: str,
    tool_input: dict[str, Any],
    user_message: str = "Run an active scan on localhost",
) -> BeforeToolCallEvent:
    """Helper to assemble a valid BeforeToolCallEvent with conversation context."""
    agent_mock = MagicMock()
    agent_mock.messages = [
        {"role": "user", "content": [{"text": user_message}]}
    ]

    event = BeforeToolCallEvent(
        selected_tool=None,
        tool_use={
            "name": tool_name,
            "input": tool_input,
            "toolUseId": "tooluse-mock-001",
        },
        invocation_state={"user_prompt": user_message},
        agent=agent_mock,
    )
    return event


class TestGroundedToolCallGuardrailWiring(unittest.TestCase):
    """Verify structural control paths for the guardrail pattern."""

    def test_01_hard_gate_runs_first_and_denies_unallowlisted(self):
        """Tier 1: Unauthorized active scan target is denied BEFORE Decider is invoked."""
        mock_client = MockDeciderClient(p_grounded=1.0)  # Even if Decider would say 100% grounded
        guardrail = GroundedToolCallIntervention(decider_client=mock_client)

        event = _create_mock_event(
            tool_name="active_scan",
            tool_input={"target": "evil-hacker.com", "ports": [80, 443]},
            user_message="Scan evil-hacker.com immediately",
        )

        decision = guardrail.before_tool_call(event)

        self.assertIsInstance(decision, Deny)
        self.assertIn("Hard Gate", decision.reason)
        # Decider must NEVER be queried when hard gate rejects the target!
        self.assertEqual(mock_client.call_count, 0, "Hard gate must block before invoking Decider client")

    def test_02_hard_gate_allows_allowlisted_target(self):
        """Tier 1: Allowlisted target passes hard gate to Decider."""
        mock_client = MockDeciderClient(p_grounded=0.95)
        guardrail = GroundedToolCallIntervention(decider_client=mock_client)

        event = _create_mock_event(
            tool_name="active_scan",
            tool_input={"target": "localhost", "ports": [80, 443]},
            user_message="Scan localhost on port 80 and 443",
        )

        decision = guardrail.before_tool_call(event)

        self.assertIsInstance(decision, Proceed)
        self.assertEqual(mock_client.call_count, 1, "Decider should be queried after hard gate passes")

    def test_03_proceed_path_when_grounded(self):
        """Tier 2: Tool call grounded in user request proceeds."""
        # p_grounded = 0.90 -> p_not_grounded = 0.10 (< threshold 0.70)
        mock_client = MockDeciderClient(p_grounded=0.90)
        guardrail = GroundedToolCallIntervention(decider_client=mock_client, threshold=0.7)

        event = _create_mock_event(
            tool_name="passive_scan",
            tool_input={"domain": "owasp.org"},
            user_message="Perform passive scan on owasp.org",
        )

        decision = guardrail.before_tool_call(event)

        self.assertIsInstance(decision, Proceed)
        self.assertEqual(mock_client.call_count, 1)

    def test_04_guide_path_when_ungrounded(self):
        """Tier 2: Hallucinated tool arguments trigger Guide steering."""
        # p_grounded = 0.10 -> p_not_grounded = 0.90 (>= threshold 0.70)
        mock_client = MockDeciderClient(p_grounded=0.10)
        guardrail = GroundedToolCallIntervention(decider_client=mock_client, threshold=0.7)

        event = _create_mock_event(
            tool_name="active_scan",
            tool_input={"target": "localhost", "ports": [22, 25, 3306, 5432]},
            user_message="Scan web ports on localhost",
        )

        decision = guardrail.before_tool_call(event)

        self.assertIsInstance(decision, Guide)
        self.assertIn("clarify", decision.reason.lower())
        self.assertEqual(mock_client.call_count, 1)

    def test_05_threshold_configuration(self):
        """Threshold edge case behavior."""
        # p_grounded = 0.25 -> p_not_grounded = 0.75
        mock_client = MockDeciderClient(p_grounded=0.25)

        # Threshold 0.80: 0.75 < 0.80 -> Proceed
        guardrail_lenient = GroundedToolCallIntervention(decider_client=mock_client, threshold=0.80)
        event1 = _create_mock_event("active_scan", {"target": "localhost", "ports": [80]})
        self.assertIsInstance(guardrail_lenient.before_tool_call(event1), Proceed)

        # Threshold 0.70: 0.75 >= 0.70 -> Guide
        guardrail_strict = GroundedToolCallIntervention(decider_client=mock_client, threshold=0.70)
        event2 = _create_mock_event("active_scan", {"target": "localhost", "ports": [80]})
        self.assertIsInstance(guardrail_strict.before_tool_call(event2), Guide)

    def test_06_fail_closed_on_decider_timeout(self):
        """Fail-closed invariant: on server timeout or error, returns Deny."""
        mock_client = MockDeciderClient(should_fail=True, fail_error=DeciderClientError("Connection timed out after 5s"))
        guardrail = GroundedToolCallIntervention(decider_client=mock_client, on_error="deny")

        event = _create_mock_event(
            tool_name="active_scan",
            tool_input={"target": "localhost", "ports": [80]},
            user_message="Scan localhost on port 80",
        )

        decision = guardrail.before_tool_call(event)

        self.assertIsInstance(decision, Deny)
        self.assertIn("Decider guardrail check failed", decision.reason)
        self.assertIn("Failing closed", decision.reason)

    def test_07_extracts_user_message_from_various_message_formats(self):
        """Verify extraction handles both string content and block list content."""
        guardrail = GroundedToolCallIntervention(decider_client=MockDeciderClient(p_grounded=0.95))

        # Format A: list of text blocks
        event_a = _create_mock_event("passive_scan", {"domain": "owasp.org"}, "Inspect owasp.org")
        extracted_a = guardrail._extract_latest_user_message(event_a)
        self.assertEqual(extracted_a, "Inspect owasp.org")

        # Format B: plain string in content
        agent_b = MagicMock()
        agent_b.messages = [{"role": "user", "content": "Plain string user prompt"}]
        event_b = BeforeToolCallEvent(
            selected_tool=None,
            tool_use={"name": "correlate", "input": {"target": "localhost"}, "toolUseId": "2"},
            invocation_state={},
            agent=agent_b,
        )
        extracted_b = guardrail._extract_latest_user_message(event_b)
        self.assertEqual(extracted_b, "Plain string user prompt")

    def test_08_active_scan_missing_target_denied(self):
        """Empty or missing target is rejected by hard gate."""
        guardrail = GroundedToolCallIntervention(decider_client=MockDeciderClient())
        event = _create_mock_event("active_scan", {"target": "", "ports": [80]})
        decision = guardrail.before_tool_call(event)
        self.assertIsInstance(decision, Deny)
        self.assertIn("no target was specified", decision.reason)


if __name__ == "__main__":
    unittest.main()
