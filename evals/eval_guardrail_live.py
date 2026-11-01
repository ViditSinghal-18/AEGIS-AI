"""Live Evaluation Suite for Grounded Tool Call Guardrail (#guardrails).

Evaluates the GroundedToolCallIntervention against a LIVE running Strands Decider 2B server
using the 25 benchmark test cases from `tests/guardrail_dataset.py`.

Requirements:
- Refuses to run if the Strands Decider server is not reachable.
- Evaluates Grounded, Hallucinated, Ambiguous, Prompt Injection, and Hard Gate test cases.
- Measures and reports:
  * Overall Guardrail Accuracy
  * False-Block Rate (legitimate grounded calls blocked or guided)
  * False-Allow Rate (hallucinations/injections allowed through)
  * Latency metrics (mean, p50, p95)
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decision_patterns.grounded_tool_call.client import DeciderClient
from decision_patterns.grounded_tool_call.intervention import GroundedToolCallIntervention
from strands.hooks.events import BeforeToolCallEvent
from tests.guardrail_dataset import GUARDRAIL_BENCHMARK_DATASET, GuardrailTestCase


def make_event_for_case(case: GuardrailTestCase) -> BeforeToolCallEvent:
    """Build a BeforeToolCallEvent modeling the agent context for a test case."""
    agent_mock = MagicMock()
    # If the case has context notes or simulated banner injection, include in messages
    messages = []
    if case.context_note:
        messages.append({
            "role": "assistant",
            "content": f"[Simulated Tool Result / Banner: {case.description}]",
        })
    messages.append({
        "role": "user",
        "content": [{"text": case.user_prompt}],
    })
    agent_mock.messages = messages

    return BeforeToolCallEvent(
        selected_tool=None,
        tool_use={
            "name": case.proposed_tool,
            "input": case.proposed_input,
            "toolUseId": f"tooluse-{case.id}",
        },
        invocation_state={"user_prompt": case.user_prompt},
        agent=agent_mock,
    )


def run_live_evaluation() -> None:
    decider_url = os.getenv("DECIDER_URL", "http://127.0.0.1:8000")
    client = DeciderClient(base_url=decider_url, timeout=10.0)

    print("================================================================================")
    print("  STRANDS DECIDER 2B GUARDRAIL LIVE BENCHMARK EVALUATION (#guardrails)")
    print("================================================================================")
    print(f"Target Decider URL: {decider_url}")
    print(f"Configured Threshold: {os.getenv('DECIDER_THRESHOLD', '0.7')}")

    # Step 1: Health check - refuse to run if server is not reachable
    if not client.is_healthy():
        print("\n[!] FATAL: Strands Decider server is NOT reachable or healthy at:")
        print(f"    {decider_url}")
        print("\nTo start the Decider server locally, execute in another terminal:")
        print("    strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8000")
        print("\nAborting live evaluation.")
        sys.exit(1)

    print("[+] Decider server connection verified! Running 25 prompt benchmark...\n")

    guardrail = GroundedToolCallIntervention(decider_client=client)

    results: list[dict[str, Any]] = []
    latencies: list[float] = []

    correct_count = 0
    grounded_cases = 0
    false_blocks = 0
    ungrounded_cases = 0
    false_allows = 0

    col_fmt = "{:<16} {:<18} {:<10} {:<10} {:<8} {:<10}"
    print(col_fmt.format("Case ID", "Category", "Expected", "Actual", "Match?", "Latency"))
    print("-" * 80)

    for case in GUARDRAIL_BENCHMARK_DATASET:
        event = make_event_for_case(case)

        start = time.perf_counter()
        decision = guardrail.before_tool_call(event)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latencies.append(elapsed_ms)

        actual_action = decision.__class__.__name__  # "Proceed", "Guide", or "Deny"
        is_match = (actual_action == case.expected_action)
        if is_match:
            correct_count += 1

        is_grounded_case = (case.expected_action == "Proceed")
        if is_grounded_case:
            grounded_cases += 1
            if actual_action in ["Guide", "Deny"]:
                false_blocks += 1
        else:
            ungrounded_cases += 1
            if actual_action == "Proceed":
                false_allows += 1

        match_str = " PASS " if is_match else " FAIL "
        print(col_fmt.format(
            case.id,
            case.category[:17],
            case.expected_action,
            actual_action,
            match_str,
            f"{elapsed_ms:.1f}ms",
        ))

        results.append({
            "id": case.id,
            "category": case.category,
            "user_prompt": case.user_prompt,
            "proposed_tool": case.proposed_tool,
            "proposed_input": case.proposed_input,
            "expected_action": case.expected_action,
            "actual_action": actual_action,
            "is_match": is_match,
            "latency_ms": round(elapsed_ms, 2),
            "reason": getattr(decision, "reason", ""),
        })

    total_cases = len(GUARDRAIL_BENCHMARK_DATASET)
    accuracy = (correct_count / total_cases) * 100.0
    false_block_rate = (false_blocks / grounded_cases * 100.0) if grounded_cases else 0.0
    false_allow_rate = (false_allows / ungrounded_cases * 100.0) if ungrounded_cases else 0.0

    latencies.sort()
    p50_latency = latencies[int(len(latencies) * 0.50)]
    p95_latency = latencies[min(int(len(latencies) * 0.95), len(latencies) - 1)]
    mean_latency = sum(latencies) / len(latencies)

    print("\n" + "=" * 80)
    print("  EVALUATION SUMMARY REPORT")
    print("=" * 80)
    print(f"Total Benchmark Cases:      {total_cases}")
    print(f"Overall Accuracy:           {accuracy:.1f}% ({correct_count}/{total_cases})")
    print(f"False-Block Rate:           {false_block_rate:.1f}% ({false_blocks}/{grounded_cases} legitimate calls blocked/guided)")
    print(f"False-Allow Rate:           {false_allow_rate:.1f}% ({false_allows}/{ungrounded_cases} ungrounded calls allowed)")
    print(f"Latency (Mean):             {mean_latency:.2f} ms")
    print(f"Latency (p50):              {p50_latency:.2f} ms")
    print(f"Latency (p95):              {p95_latency:.2f} ms")
    print("=" * 80)

    # Save summary artifact to data/
    out_dir = ROOT / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "decider_url": decider_url,
        "total_cases": total_cases,
        "accuracy_pct": round(accuracy, 2),
        "false_block_rate_pct": round(false_block_rate, 2),
        "false_allow_rate_pct": round(false_allow_rate, 2),
        "latency_ms": {
            "mean": round(mean_latency, 2),
            "p50": round(p50_latency, 2),
            "p95": round(p95_latency, 2),
        },
        "results": results,
    }

    out_file = out_dir / "guardrail_eval_results.json"
    out_file.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")
    print(f"[+] Full JSON results written to: {out_file}\n")


if __name__ == "__main__":
    run_live_evaluation()
