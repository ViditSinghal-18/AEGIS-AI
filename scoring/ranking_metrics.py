"""
AEGIS-AI: Scientifically Defensible Ranking Agreement Metrics.

Implements rank-correlation and rank-biased agreement measures:
- Spearman rank correlation coefficient (rho)
- Kendall rank correlation coefficient (tau-b with tie correction)
- Rank-Biased Overlap (RBO@k with parameter p)

Inspired by:
- Webber, Moffat, & Zobel (2010), "A Similarity Measure for Indefinite Rankings", ACM TOIS.
  (Flag: verify before publishing)
- Kendall (1938), "A New Measure of Rank Correlation", Biometrika.
- Spearman (1904), "The Proof and Measurement of Association between Two Things", Am. J. Psychol.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, List, Sequence, Tuple


def spearman_rho(ranks1: Sequence[float | int], ranks2: Sequence[float | int]) -> float:
    """
    Compute Spearman's rank correlation coefficient between two equal-length numerical series.
    Returns value in [-1.0, 1.0]. Returns 1.0 if identical or 0.0 if length < 2 or variance is 0.
    """
    n = len(ranks1)
    if n != len(ranks2):
        raise ValueError(f"Series length mismatch: {len(ranks1)} vs {len(ranks2)}")
    if n < 2:
        return 1.0

    # Calculate ranks with fractional ties
    r1 = _fractional_ranks(ranks1)
    r2 = _fractional_ranks(ranks2)

    mean1 = sum(r1) / n
    mean2 = sum(r2) / n

    cov = sum((a - mean1) * (b - mean2) for a, b in zip(r1, r2))
    var1 = sum((a - mean1) ** 2 for a in r1)
    var2 = sum((b - mean2) ** 2 for b in r2)

    denom = math.sqrt(var1 * var2)
    if denom == 0.0:
        return 0.0

    score = cov / denom
    return round(max(-1.0, min(1.0, score)), 4)


def kendall_tau(ranks1: Sequence[float | int], ranks2: Sequence[float | int]) -> float:
    """
    Compute Kendall's tau-b rank correlation coefficient (accounting for ties).
    Returns value in [-1.0, 1.0].
    """
    n = len(ranks1)
    if n != len(ranks2):
        raise ValueError(f"Series length mismatch: {len(ranks1)} vs {len(ranks2)}")
    if n < 2:
        return 1.0

    concordant = 0
    discordant = 0
    ties_x = 0
    ties_y = 0

    for i in range(n):
        for j in range(i + 1, n):
            dx = ranks1[i] - ranks1[j]
            dy = ranks2[i] - ranks2[j]

            if dx == 0 and dy == 0:
                continue
            elif dx == 0:
                ties_x += 1
            elif dy == 0:
                ties_y += 1
            elif (dx > 0 and dy > 0) or (dx < 0 and dy < 0):
                concordant += 1
            else:
                discordant += 1

    total_pairs = n * (n - 1) / 2
    denom = math.sqrt((total_pairs - ties_x) * (total_pairs - ties_y))
    if denom == 0.0:
        return 0.0

    tau = (concordant - discordant) / denom
    return round(max(-1.0, min(1.0, tau)), 4)


def rank_biased_overlap(
    list1: Sequence[Any],
    list2: Sequence[Any],
    p: float = 0.9,
    k: int | None = None,
) -> float:
    """
    Compute the Rank-Biased Overlap (RBO) between two ordered lists.
    
    Inspired by Webber, Moffat, & Zobel (2010), ACM TOIS.
    
    Args:
        list1: First ranked list of item identifiers.
        list2: Second ranked list of item identifiers.
        p: Persistence parameter in (0, 1). Higher p gives more weight to deeper ranks.
           p=0.9 heavily weights the top 10 items.
        k: Optional maximum prefix depth to evaluate (e.g., RBO@10). If None, min(len1, len2).

    Returns:
        RBO score bounded in [0.0, 1.0]. 1.0 means identical rankings.
    """
    if not (0.0 < p < 1.0):
        raise ValueError("Persistence parameter p must be strictly in (0.0, 1.0)")

    if not list1 and not list2:
        return 1.0
    if not list1 or not list2:
        return 0.0

    depth = min(len(list1), len(list2))
    if k is not None and k > 0:
        depth = min(depth, k)

    if depth == 0:
        return 0.0

    seen1 = set()
    seen2 = set()
    overlap_count = 0
    rbo_sum = 0.0

    for d in range(1, depth + 1):
        item1 = list1[d - 1]
        item2 = list2[d - 1]

        seen1.add(item1)
        seen2.add(item2)

        if item1 in seen2:
            overlap_count += 1
        if item2 in seen1 and item1 != item2:
            overlap_count += 1

        agreement = overlap_count / d
        weight = (1.0 - p) * (p ** (d - 1))
        rbo_sum += weight * agreement

    # Residual / extrapolated tail contribution
    final_agreement = overlap_count / depth
    rbo_score = rbo_sum + (p ** depth) * final_agreement

    return round(max(0.0, min(1.0, rbo_score)), 4)


def compute_ranking_concordance(
    baseline_items: Sequence[Any],
    candidate_items: Sequence[Any],
    p: float = 0.9,
    top_k: int = 10,
) -> dict[str, float]:
    """
    Comprehensive multi-metric rank concordance report between two ranked entity sequences.
    """
    rbo_val = rank_biased_overlap(baseline_items, candidate_items, p=p, k=top_k)

    # Compute spearman and kendall if item sets overlap
    common = [item for item in baseline_items if item in candidate_items]
    if len(common) >= 2:
        pos1 = [baseline_items.index(x) + 1 for x in common]
        pos2 = [candidate_items.index(x) + 1 for x in common]
        s_rho = spearman_rho(pos1, pos2)
        k_tau = kendall_tau(pos1, pos2)
    else:
        s_rho = 0.0
        k_tau = 0.0

    return {
        "spearman_rho": s_rho,
        "kendall_tau": k_tau,
        "rbo_score": rbo_val,
        "rank_biased_overlap": rbo_val,
        "rbo_p": p,
        "eval_depth_k": top_k,
        "sample_size": len(common),
    }


def _fractional_ranks(values: Sequence[float | int]) -> List[float]:
    """Assign fractional ranks to elements (average rank for ties), 1-based."""
    n = len(values)
    sorted_indices = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n

    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[sorted_indices[j + 1]] == values[sorted_indices[i]]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[sorted_indices[k]] = avg_rank
        i = j + 1

    return ranks
