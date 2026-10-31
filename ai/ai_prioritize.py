"""
AEGIS-AI: AI-Assisted Prioritisation & Ranking Comparison.
Compares deterministic formula ranking against optional LLM re-ranking.
Calculates Spearman's Rank Correlation Coefficient (rho) by hand using Python standard library.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


def spearman_rank_correlation(ranks1: List[int], ranks2: List[int]) -> float:
    """
    Compute Spearman's rank correlation coefficient (rho) by hand.
    Formula: rho = 1 - (6 * sum(d_i^2)) / (n * (n^2 - 1))
    """
    n = len(ranks1)
    if n <= 1:
        return 1.0
    sum_d_sq = sum((r1 - r2) ** 2 for r1, r2 in zip(ranks1, ranks2))
    denom = n * (n ** 2 - 1)
    if denom == 0:
        return 1.0
    return round(1.0 - (6.0 * sum_d_sq) / denom, 3)


def compare_rankings(
    deterministic_findings: List[Dict[str, Any]],
    ai_reordered_findings: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Compare deterministic mathematical ranking vs LLM suggested ranking.
    Always transparent and shows both rankings and rank delta.
    """
    n = len(deterministic_findings)
    if not n:
        return {
            "spearman_rho": 1.0,
            "alignment": "Full Alignment",
            "comparisons": []
        }

    det_ranks = [f.get("rank", idx + 1) for idx, f in enumerate(deterministic_findings)]

    if not ai_reordered_findings:
        # Default aligned ranking
        ai_ranks = list(det_ranks)
    else:
        # Match by title or vuln_id
        ai_ranks = []
        for det_f in deterministic_findings:
            det_id = det_f.get("title")
            matched_rank = None
            for idx, ai_f in enumerate(ai_reordered_findings, 1):
                if ai_f.get("title") == det_id:
                    matched_rank = idx
                    break
            ai_ranks.append(matched_rank or det_f.get("rank", 99))

    rho = spearman_rank_correlation(det_ranks, ai_ranks)

    comparisons = []
    for idx, (d_f, r_det, r_ai) in enumerate(zip(deterministic_findings, det_ranks, ai_ranks)):
        comparisons.append({
            "finding_title": d_f.get("title"),
            "deterministic_rank": r_det,
            "ai_rank": r_ai,
            "rank_delta": r_det - r_ai,
            "deterministic_score": d_f.get("contextual_risk_score"),
            "justification": d_f.get("xai_formula", {}).get("formula", "Deterministic formula")
        })

    alignment = "Strong Agreement" if rho >= 0.8 else ("Moderate Divergence" if rho >= 0.5 else "Significant Divergence")

    return {
        "spearman_rho": rho,
        "alignment": alignment,
        "total_evaluated": n,
        "comparisons": comparisons
    }
