"""
AEGIS-AI Real Intelligence Package.
Provides multi-model LLM provider integration, grounded Copilot assistant,
anti-exploit guardrails, and ranking comparison.
"""

from ai.provider import (
    query_copilot,
    get_available_llm_provider,
    check_cve_grounding,
    SYSTEM_PROMPT
)
from ai.ai_prioritize import compare_rankings, spearman_rank_correlation

__all__ = [
    "query_copilot",
    "get_available_llm_provider",
    "check_cve_grounding",
    "SYSTEM_PROMPT",
    "compare_rankings",
    "spearman_rank_correlation"
]
