"""
Compare vulnerability ranking methodologies:
1. Plain CVSS-only ranking
2. KEV + EPSS enriched heuristic ranking
3. AI-Assisted (Amazon Bedrock) defensive ranking

Computes Spearman's Rank Correlation Coefficient by hand using the Python standard library.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai.prioritize import _heuristic_report, prioritize
from storage import read_json


def _cvss_only_ranking(correlated: dict) -> list[dict]:
    """Sort purely by CVSS base score descending (ignoring KEV and EPSS)."""
    items = []
    for asset in correlated.get("assets") or []:
        for cve in asset.get("cves") or []:
            score = float(cve.get("cvss_score") or 0.0)
            items.append({
                "id": cve.get("cve_id"),
                "title": f"{cve.get('cve_id')} on {asset.get('service') or 'service'}",
                "cvss": score,
                "kev": bool(cve.get("kev")),
                "epss": float(cve.get("epss") or 0.0),
                "type": "cve",
            })
        for issue in asset.get("config_issues") or []:
            items.append({
                "id": issue[:30],
                "title": issue,
                "cvss": 4.0,  # Medium default
                "kev": False,
                "epss": 0.0,
                "type": "config",
            })
    # Sort purely by CVSS score descending
    items.sort(key=lambda x: x["cvss"], reverse=True)
    for idx, it in enumerate(items, start=1):
        it["rank"] = idx
    return items


def spearman_rank_correlation(ranks1: list[int], ranks2: list[int]) -> float:
    """
    Compute Spearman's rank correlation coefficient (rho) by hand.
    Formula: rho = 1 - (6 * sum(d_i^2)) / (n * (n^2 - 1))
    Where d_i = rank1_i - rank2_i
    """
    n = len(ranks1)
    if n <= 1:
        return 1.0
    sum_d_sq = sum((r1 - r2) ** 2 for r1, r2 in zip(ranks1, ranks2))
    denom = n * (n ** 2 - 1)
    if denom == 0:
        return 1.0
    return 1.0 - (6.0 * sum_d_sq) / denom


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare Plain CVSS ranking vs KEV/EPSS vs AI ranking")
    parser.add_argument("--file", default=None, help="Path to correlated_findings.json")
    args = parser.parse_args()

    try:
        correlated = json.loads(Path(args.file).read_text(encoding="utf-8")) if args.file else read_json("correlated_findings.json")
    except Exception as exc:
        print(f"Error loading correlated findings: {exc}")
        print("Run `python run_pipeline.py --target localhost` first.")
        return

    print("================================================================================")
    print("                     VULNERABILITY RANKING COMPARISON                           ")
    print("================================================================================")

    # 1. Plain CVSS ranking
    cvss_ranked = _cvss_only_ranking(correlated)

    # 2. KEV + EPSS enriched heuristic ranking
    heuristic_rep = _heuristic_report(correlated)
    heuristic_ranked = heuristic_rep.findings

    # 3. Existing Prioritized Report
    try:
        ai_rep = read_json("prioritized_report.json")
        ai_ranked = ai_rep.get("findings") or []
    except Exception:
        ai_ranked = []

    print("\n--- 1. Plain CVSS-Only Ranking (Baseline) ---")
    for item in cvss_ranked[:5]:
        print(f"  #{item['rank']} [CVSS: {item['cvss']}] {item['title'][:65]}")

    print("\n--- 2. KEV + EPSS Threat-Enriched Ranking ---")
    for item in heuristic_ranked[:5]:
        print(f"  #{item.rank} [{item.severity}] {item.title[:45]} | {item.exploitability[:30]}")

    if ai_ranked:
        print(f"\n--- 3. AI Bedrock Ranking (Model: {ai_rep.get('model_id', 'LLM')}) ---")
        for item in ai_ranked[:5]:
            print(f"  #{item.get('rank')} [{item.get('severity')}] {item.get('title')[:45]} | {item.get('exploitability', '')[:30]}")

    # Compute Rank Correlation if comparable
    if cvss_ranked and heuristic_ranked:
        n = min(len(cvss_ranked), len(heuristic_ranked))
        cvss_ranks = list(range(1, n + 1))
        # Build map of title to heuristic rank
        heur_map = {f.title.strip().lower()[:40]: f.rank for f in heuristic_ranked}
        heur_ranks = []
        for c in cvss_ranked[:n]:
            key = c["title"].strip().lower()[:40]
            heur_ranks.append(heur_map.get(key, c["rank"]))

        rho = spearman_rank_correlation(cvss_ranks, heur_ranks)
        print("\n" + "=" * 80)
        print(f"  Spearman's Rank Correlation (CVSS Baseline vs KEV/EPSS Enriched): rho = {rho:.3f}")
        if rho < 0.8:
            print("  [*] INSIGHT: Threat Intelligence (KEV/EPSS) significantly reordered priorities,")
            print("      promoting actively exploited/weaponized flaws above high-CVSS theoretical issues.")
        else:
            print("  [*] INSIGHT: Rankings are closely aligned between CVSS and Threat Intelligence.")
        print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
