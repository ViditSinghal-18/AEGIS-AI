#!/usr/bin/env python3
"""
Verify the configured LLM provider for AEGIS-AI.

Usage:
    python verify_llm.py

Exit codes:
    0 — Provider is reachable and returned a response.
    1 — No provider configured or provider is unreachable.
"""

import sys

# Ensure repo root is on the path when run directly
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ai.llm as llm


def main() -> None:
    print(f"Provider   : {llm.active_provider()}")
    print(f"Description: {llm.describe()}")

    if not llm.is_enabled():
        print(
            "\nNo LLM provider configured (AEGIS_LLM_PROVIDER=none or unset).\n"
            "Set AEGIS_LLM_PROVIDER in your .env file to enable AI features.\n"
            "See .env.example for supported providers (Groq, Ollama, Bedrock, etc.)."
        )
        sys.exit(1)

    print("\nSending test ping…")
    try:
        result = llm.complete(
            "You are a test assistant.",
            "Reply with the single word: READY",
            max_tokens=5,
        )
        print(f"Model      : {result.model_id}")
        print(f"Response   : {result.text.strip()}")
        print(f"Tokens     : {result.input_tokens} in / {result.output_tokens} out")
        print(f"Latency    : {result.latency_ms:.1f} ms")
        print("\n✅  LLM provider is reachable and responding.")
        sys.exit(0)
    except llm.LLMUnavailable as exc:
        print(f"\n❌  LLM unavailable: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
