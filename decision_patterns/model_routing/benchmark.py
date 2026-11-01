"""Benchmark comparing 'Always Large Model' vs 'Decider-Routed' model execution.

Logs latency, real/estimated token counts, and calculates official AWS Bedrock costs.
Writes comparison results to:
- data/model_routing_comparison.json
- data/model_routing_comparison.md
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decision_patterns.model_routing.router import (
    BEDROCK_PRICING,
    MODEL_TIER_LARGE,
    MODEL_TIER_SMALL,
    FindingRouter,
)

SAMPLE_FINDINGS: list[dict[str, Any]] = [
    {
        "rank": 1,
        "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
        "severity": "Low",
        "exploitability": "Man-in-the-middle protocol downgrade risk.",
        "related_cves": [],
    },
    {
        "rank": 2,
        "title": "Missing Content-Security-Policy (CSP) Header",
        "severity": "Medium",
        "exploitability": "Allows cross-site scripting and unauthorized iframe rendering.",
        "related_cves": [],
    },
    {
        "rank": 3,
        "title": "Server Information Disclosure in HTTP Banner",
        "severity": "Info",
        "exploitability": "Discloses exact backend version to unauthenticated probes.",
        "related_cves": [],
    },
    {
        "rank": 4,
        "title": "OpenSSL Denial of Service in Certificate Parsing",
        "severity": "Low",
        "exploitability": "CVSS 3.7. No known public exploit in the wild.",
        "related_cves": ["CVE-2023-0286"],
    },
    {
        "rank": 5,
        "title": "Express Cookie Without Secure and SameSite Attributes",
        "severity": "Low",
        "exploitability": "Session cookie vulnerable to cross-site request forgery.",
        "related_cves": [],
    },
    {
        "rank": 6,
        "title": "Node.js HTTP Request Smuggling",
        "severity": "Medium",
        "exploitability": "CVSS 6.5. EPSS 0.04. Requires specific proxy configuration.",
        "related_cves": ["CVE-2022-35256"],
    },
    {
        "rank": 7,
        "title": "Nginx TLS 1.0 / 1.1 Weak Cipher Suites Enabled",
        "severity": "Low",
        "exploitability": "Legacy cipher negotiation vulnerable to passive eavesdropping.",
        "related_cves": [],
    },
    {
        "rank": 8,
        "title": "Apache HTTP Server Path Traversal and Remote Code Execution",
        "severity": "Critical",
        "exploitability": "CVSS 9.8. CISA KEV actively exploited. EPSS 0.88.",
        "related_cves": ["CVE-2021-41773", "CVE-2021-42013"],
    },
    {
        "rank": 9,
        "title": "Log4j JNDI Remote Code Execution (Log4Shell)",
        "severity": "Critical",
        "exploitability": "CVSS 10.0. CISA KEV actively weaponized. EPSS 0.97.",
        "related_cves": ["CVE-2021-44228"],
    },
    {
        "rank": 10,
        "title": "Spring Framework Remote Code Execution (Spring4Shell)",
        "severity": "High",
        "exploitability": "CVSS 8.1. CISA KEV recorded. EPSS 0.42.",
        "related_cves": ["CVE-2022-22965"],
    },
]


def run_benchmark() -> dict[str, Any]:
    router = FindingRouter()
    print("================================================================================")
    print("  MODEL ROUTING BENCHMARK: 'ALWAYS LARGE' vs 'STRANDS DECIDER-ROUTED'")
    print("================================================================================")

    large_results = []
    routed_results = []

    print(f"{'Finding Title':<45} | {'Routed Tier':<10} | {'Baseline (Large)':<16} | {'Decider-Routed':<16}")
    print("-" * 95)

    for finding in SAMPLE_FINDINGS:
        title = finding["title"]
        short_title = (title[:42] + "...") if len(title) > 42 else title

        # Strategy A: Baseline - Always Large Model
        res_large = router.execute_with_tier(finding, tier="large")
        large_results.append(res_large)

        # Strategy B: Decider-Routed
        tier, conf = router.route(finding)
        res_routed = router.execute_with_tier(finding, tier=tier)
        res_routed.confidence = conf
        routed_results.append(res_routed)

        base_summary = f"{res_large.latency_ms:.0f}ms / ${res_large.cost_usd:.5f}"
        routed_summary = f"{res_routed.latency_ms:.0f}ms / ${res_routed.cost_usd:.5f}"
        print(f"{short_title:<45} | {tier:<10} | {base_summary:<16} | {routed_summary:<16}")

    # Aggregations
    total_large_latency = sum(r.latency_ms for r in large_results)
    total_routed_latency = sum(r.latency_ms for r in routed_results)
    latency_reduction = ((total_large_latency - total_routed_latency) / total_large_latency) * 100.0 if total_large_latency else 0.0

    total_large_cost = sum(r.cost_usd for r in large_results)
    total_routed_cost = sum(r.cost_usd for r in routed_results)
    cost_reduction = ((total_large_cost - total_routed_cost) / total_large_cost) * 100.0 if total_large_cost else 0.0

    total_large_tokens = sum(r.input_tokens + r.output_tokens for r in large_results)
    total_routed_tokens = sum(r.input_tokens + r.output_tokens for r in routed_results)
    token_reduction = ((total_large_tokens - total_routed_tokens) / total_large_tokens) * 100.0 if total_large_tokens else 0.0

    template_count = sum(1 for r in routed_results if r.tier == "template")
    small_count = sum(1 for r in routed_results if r.tier == "small")
    large_count = sum(1 for r in routed_results if r.tier == "large")

    print("\n" + "=" * 95)
    print("  EXECUTIVE SUMMARY: COST & LATENCY COMPARISON")
    print("=" * 95)
    print(f"Tier Distribution:          {template_count} Template (0ms/$0), {small_count} Small (Nova), {large_count} Large (Claude Sonnet)")
    print(f"Total Latency:              Baseline: {total_large_latency:.1f}ms  -->  Routed: {total_routed_latency:.1f}ms  ({latency_reduction:.1f}% faster)")
    print(f"Total Token Cost (USD):     Baseline: ${total_large_cost:.5f}  -->  Routed: ${total_routed_cost:.5f}  ({cost_reduction:.1f}% savings)")
    print(f"Total Tokens Consumed:      Baseline: {total_large_tokens} tokens   -->  Routed: {total_routed_tokens} tokens   ({token_reduction:.1f}% reduction)")
    print("=" * 95)

    # Format Markdown Table
    md_lines = [
        "# Model Routing Benchmark Results: Strands Decider 2B vs Always Large Model",
        "",
        "**Benchmark Goal:** Compare latency, token consumption, and official Amazon Bedrock execution costs between:",
        f"1. **Baseline Strategy (`Always Large`):** Every finding is analyzed using the large model tier (`{MODEL_TIER_LARGE}`).",
        f"2. **Strands Decider-Routed Strategy:** Strands Decider 2B categorizes findings into `template` ($0.00 / instant), `small` (`{MODEL_TIER_SMALL}`), or `large` (`{MODEL_TIER_LARGE}`).",
        "",
        "## Summary Metrics",
        "",
        "| Metric | Always Large Model | Decider-Routed | Reduction / Benefit |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Total Latency** | `{total_large_latency:.1f} ms` | `{total_routed_latency:.1f} ms` | **{latency_reduction:.1f}% Faster** |",
        f"| **Total Token Cost** | `${total_large_cost:.5f}` | `${total_routed_cost:.5f}` | **{cost_reduction:.1f}% Cost Reduction** |",
        f"| **Total Tokens** | `{total_large_tokens}` tokens | `{total_routed_tokens}` tokens | **{token_reduction:.1f}% Fewer Tokens** |",
        f"| **Workload Split** | 100% Large Model | {template_count*10}% Template, {small_count*10}% Small, {large_count*10}% Large | Balanced System-1 / System-2 |",
        "",
        "## Detailed Finding Breakdown",
        "",
        "| Finding | Severity | Routed Tier | Baseline Latency / Cost | Routed Latency / Cost | Cost Type |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for f, b, r in zip(SAMPLE_FINDINGS, large_results, routed_results):
        cost_flag = "Estimated" if (b.is_estimated_cost or r.is_estimated_cost) else "Real Bedrock Tokens"
        md_lines.append(
            f"| {f['title']} | {f['severity']} | `{r.tier}` | {b.latency_ms:.0f}ms / ${b.cost_usd:.5f} | {r.latency_ms:.0f}ms / ${r.cost_usd:.5f} | {cost_flag} |"
        )

    large_in_rate = BEDROCK_PRICING.get(MODEL_TIER_LARGE, {}).get("input_per_million", 0.80)
    large_out_rate = BEDROCK_PRICING.get(MODEL_TIER_LARGE, {}).get("output_per_million", 3.20)
    small_in_rate = BEDROCK_PRICING.get(MODEL_TIER_SMALL, {}).get("input_per_million", 0.035)
    small_out_rate = BEDROCK_PRICING.get(MODEL_TIER_SMALL, {}).get("output_per_million", 0.14)

    md_lines.extend([
        "",
        "## Official AWS Bedrock Pricing Baseline",
        f"- **Large Tier Model (`{MODEL_TIER_LARGE}`):** ${large_in_rate:.3f} / 1M input, ${large_out_rate:.3f} / 1M output (Source: AWS Bedrock Pricing).",
        f"- **Small Tier Model (`{MODEL_TIER_SMALL}`):** ${small_in_rate:.3f} / 1M input, ${small_out_rate:.3f} / 1M output (Source: AWS Bedrock Pricing).",
        "- **Template Remediation:** $0.00 / 0ms execution time.",
        "- **Strands Decider 2B:** System One pointer-head classification (measured on the deployed instance: TBD, zero autoregressive token overhead).",
    ])

    out_dir = ROOT / "data"
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / "model_routing_comparison.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    json_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "latency_reduction_pct": round(latency_reduction, 2),
            "cost_reduction_pct": round(cost_reduction, 2),
            "token_reduction_pct": round(token_reduction, 2),
            "baseline_total_cost_usd": round(total_large_cost, 6),
            "routed_total_cost_usd": round(total_routed_cost, 6),
            "baseline_total_latency_ms": round(total_large_latency, 2),
            "routed_total_latency_ms": round(total_routed_latency, 2),
            "distribution": {
                "template": template_count,
                "small": small_count,
                "large": large_count,
            },
        },
        "findings_results": [
            {
                "title": f["title"],
                "severity": f["severity"],
                "tier": r.tier,
                "baseline_latency_ms": b.latency_ms,
                "baseline_cost_usd": b.cost_usd,
                "routed_latency_ms": r.latency_ms,
                "routed_cost_usd": r.cost_usd,
                "is_estimated_cost": r.is_estimated_cost,
            }
            for f, b, r in zip(SAMPLE_FINDINGS, large_results, routed_results)
        ],
    }

    json_path = out_dir / "model_routing_comparison.json"
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    print(f"\n[+] Comparison table written to: {md_path}")
    print(f"[+] Full JSON comparison written to: {json_path}\n")

    return json_payload


if __name__ == "__main__":
    run_benchmark()
