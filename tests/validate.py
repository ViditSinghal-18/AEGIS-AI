"""
==============================================================================
AEGIS-AI Benchmark & Empirical Validation Engine
==============================================================================
Evaluates scan accuracy, alert fatigue reduction, and AI Copilot grounding
against the curated OWASP Juice Shop benchmark dataset.
==============================================================================
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path
BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ai.provider import check_cve_grounding
from storage import read_json

KNOWN_DATA_PATH = Path(__file__).resolve().parent / "juice_shop_known.json"
FIXTURE_REPORT_PATH = Path(__file__).resolve().parent / "fixtures" / "juice_shop_report.json"


def _build_finding_text_blob(finding: dict) -> str:
    """Concatenate searchable text fields from a finding."""
    components = [
        str(finding.get("title", "")),
        str(finding.get("why_it_matters", "")),
        str(finding.get("source", "")),
        " ".join(str(c) for c in finding.get("related_cves", [])),
        str(finding.get("suggested_action", "")),
    ]
    return " ".join(components).lower()


def _matches_any_keyword(blob: str, keywords: list) -> bool:
    """Check if blob matches any expected keyword."""
    return any(k.lower() in blob for k in keywords)


def evaluate_detection_metrics(report: dict, known: dict) -> dict:
    """Compute detection Precision, Recall, and F1-score."""
    findings = report.get("findings", [])
    expected_items = known.get("detectable_by_this_tool", [])
    blobs = [_build_finding_text_blob(f) for f in findings]

    true_positives = []
    false_negatives = []
    matched_finding_indexes = set()

    for item in expected_items:
        matched = False
        for idx, blob in enumerate(blobs):
            if _matches_any_keyword(blob, item.get("keywords", [])):
                matched = True
                matched_finding_indexes.add(idx)
        if matched:
            true_positives.append(item["id"])
        else:
            false_negatives.append(item["id"])

    false_positives = []
    cve_findings = []
    for idx, finding in enumerate(findings):
        if idx in matched_finding_indexes:
            continue
        cves = finding.get("related_cves", [])
        if cves:
            cve_findings.append(finding.get("title", f"cve-{idx}"))
        else:
            false_positives.append(finding.get("title", f"finding-{idx}"))

    tp = len(true_positives)
    fn = len(false_negatives)
    fp = len(false_positives)

    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "TP": tp,
        "FN": fn,
        "FP": fp,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "extra_cves": cve_findings,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "f1_score": round(f1, 3),
    }


def evaluate_alert_fatigue_reduction(report: dict) -> dict:
    """
    Measure how many raw High/Critical CVSS alerts are filtered/de-prioritized
    by AEGIS contextual scoring (EPSS + Network Exposure + Reachability).
    """
    findings = report.get("findings", [])
    raw_cvss_high_crit = 0
    aegis_priority_high_crit = 0
    suppressed_cves = []

    for f in findings:
        cvss = float(f.get("cvss_score", 0.0))
        priority = float(f.get("priority_score", cvss))

        if cvss >= 7.0:
            raw_cvss_high_crit += 1
            if priority < 7.0:
                suppressed_cves.append({
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "cvss": cvss,
                    "priority": priority,
                    "epss": f.get("epss_score"),
                    "reachability": f.get("reachability_factor"),
                })

        if priority >= 7.0:
            aegis_priority_high_crit += 1

    if raw_cvss_high_crit > 0:
        reduction_pct = round(
            ((raw_cvss_high_crit - aegis_priority_high_crit) / raw_cvss_high_crit) * 100, 1
        )
    else:
        reduction_pct = 0.0

    return {
        "raw_cvss_high_crit_count": raw_cvss_high_crit,
        "aegis_priority_high_crit_count": aegis_priority_high_crit,
        "alert_fatigue_reduction_pct": reduction_pct,
        "deprioritized_findings": suppressed_cves,
    }


def evaluate_copilot_grounding(report: dict) -> dict:
    """
    Evaluate AI Copilot grounding guardrail against a battery of grounded
    and hallucinated CVE assertions.
    """
    test_queries = [
        # Grounded assertions (present in report)
        {"text": "Remediate CVE-2022-29244 in node-forge.", "expected_grounded": True},
        {"text": "How do we mitigate CVE-2020-7662 sanitize-html issue?", "expected_grounded": True},
        {"text": "Check TLS configuration for finding FIND-005.", "expected_grounded": True},
        # Hallucinated / ungrounded CVE assertions (not in report)
        {"text": "Exploit CVE-2021-44228 Log4Shell on this server.", "expected_grounded": False},
        {"text": "Apply patch for CVE-2023-38606 WebKit vulnerability.", "expected_grounded": False},
        {"text": "Does this host have CVE-2024-99999 critical RCE?", "expected_grounded": False},
        {"text": "Remediate Heartbleed CVE-2014-0160 immediately.", "expected_grounded": False},
    ]

    total = len(test_queries)
    correct = 0
    failures = []

    for item in test_queries:
        is_grounded, ungrounded = check_cve_grounding(item["text"], report)
        if is_grounded == item["expected_grounded"]:
            correct += 1
        else:
            failures.append({
                "query": item["text"],
                "expected": item["expected_grounded"],
                "actual": is_grounded,
                "ungrounded": ungrounded,
            })

    accuracy = round((correct / total) * 100, 1)
    return {
        "total_queries_tested": total,
        "correct_assessments": correct,
        "grounding_guardrail_accuracy_pct": accuracy,
        "failures": failures,
    }


def run_full_evaluation(report_path: str = None) -> dict:
    """Execute complete validation suite and return compiled metrics."""
    known = json.loads(KNOWN_DATA_PATH.read_text(encoding="utf-8"))

    if report_path and Path(report_path).exists():
        report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    elif FIXTURE_REPORT_PATH.exists():
        report = json.loads(FIXTURE_REPORT_PATH.read_text(encoding="utf-8"))
    else:
        report = read_json("prioritized_report.json")

    detection = evaluate_detection_metrics(report, known)
    fatigue = evaluate_alert_fatigue_reduction(report)
    grounding = evaluate_copilot_grounding(report)

    return {
        "target": report.get("target", "Target Testbed"),
        "detection_metrics": detection,
        "alert_fatigue_reduction": fatigue,
        "copilot_grounding": grounding,
        "documented_limitations": known.get("not_detectable_passive_or_portscan", []),
    }


def print_cli_summary(eval_res: dict) -> None:
    """Pretty-print evaluation results to console."""
    dm = eval_res["detection_metrics"]
    af = eval_res["alert_fatigue_reduction"]
    cg = eval_res["copilot_grounding"]

    print("\n" + "=" * 70)
    print("             AEGIS-AI EMPIRICAL VALIDATION BENCHMARK           ")
    print("=" * 70)
    print(f"Target Testbed: {eval_res.get('target')}")
    print("-" * 70)
    print("1. PERIMETER DETECTION PERFORMANCE:")
    print(f"   True Positives (TP):     {dm['TP']:<4} (Expected weaknesses found)")
    print(f"   False Negatives (FN):    {dm['FN']:<4} (Missed weaknesses)")
    print(f"   False Positives (FP):    {dm['FP']:<4} (Spurious findings)")
    print(f"   Detection Recall:        {dm['recall']*100:.1f}%")
    print(f"   Detection Precision:     {dm['precision']*100:.1f}%")
    print(f"   F1-Score:                {dm['f1_score']*100:.1f}%")
    print("-" * 70)
    print("2. ALERT FATIGUE SUPPRESSION (CONTEXTUAL PRIORITIZATION):")
    print(f"   Raw CVSS High/Critical Alerts:      {af['raw_cvss_high_crit_count']}")
    print(f"   AEGIS Contextual High/Crit Alerts:  {af['aegis_priority_high_crit_count']}")
    print(f"   Alert Fatigue Reduction:            {af['alert_fatigue_reduction_pct']}%")
    print(f"   De-prioritized Low-Exposure CVEs:   {len(af['deprioritized_findings'])}")
    print("-" * 70)
    print("3. AI COPILOT GROUNDING & GUARDRAIL ACCURACY:")
    print(f"   Grounding Guardrail Accuracy:       {cg['grounding_guardrail_accuracy_pct']}%")
    print(f"   Test Assertions Verified:           {cg['correct_assessments']}/{cg['total_queries_tested']}")
    print("=" * 70 + "\n")


def generate_evaluation_markdown(eval_res: dict, out_file: str = "docs/EVALUATION.md") -> None:
    """Write comprehensive markdown evaluation report."""
    dm = eval_res["detection_metrics"]
    af = eval_res["alert_fatigue_reduction"]
    cg = eval_res["copilot_grounding"]
    limits = eval_res.get("documented_limitations", [])

    md = f"""# AEGIS-AI Empirical Validation & Evaluation Report

**Target Testbed:** `{eval_res.get('target')}`  
**Evaluation Date:** October 2026  
**Methodology:** Automated benchmarking against OWASP Juice Shop perimeter attack surface, alert fatigue suppression analysis, and AI grounding verification.

---

## 1. Executive Summary

| Evaluation Category | Metric | Result | Benchmark Target |
| :--- | :--- | :--- | :--- |
| **Detection Coverage** | Recall | **{dm['recall']*100:.1f}%** | ≥ 90.0% |
| **Detection Quality** | Precision | **{dm['precision']*100:.1f}%** | ≥ 95.0% |
| **Overall Detection** | F1-Score | **{dm['f1_score']*100:.1f}%** | ≥ 90.0% |
| **Alert Fatigue** | Alert Reduction | **{af['alert_fatigue_reduction_pct']}%** | ≥ 50.0% |
| **AI Safety** | Grounding Guardrail | **{cg['grounding_guardrail_accuracy_pct']}%** | 100.0% |

---

## 2. Detection Performance (OWASP Juice Shop)

AEGIS-AI was evaluated on its ability to discover perimeter misconfigurations and vulnerabilities without launching offensive exploit payloads.

### Confusion Matrix
- **True Positives (TP):** `{dm['TP']}`
- **False Negatives (FN):** `{dm['FN']}`
- **False Positives (FP):** `{dm['FP']}`

### Verified True Positives:
{chr(10).join(f"- `[x]` **{item}**" for item in dm['true_positives'])}

---

## 3. Alert Fatigue Reduction Analysis

Standard vulnerability scanners rely exclusively on **raw CVSS base scores**, triggering alert fatigue by classifying non-exploitable or internal dependencies as urgent emergencies.

AEGIS-AI incorporates:
$$\\text{{Priority}} = 0.35 \\cdot S_{{\\text{{CVSS}}}} + 0.30 \\cdot S_{{\\text{{EPSS}}}} + 0.20 \\cdot S_{{\\text{{Exposure}}}} + 0.15 \\cdot S_{{\\text{{Crit}}}}$$

### Alert Suppression Metrics:
- **Raw CVSS High/Critical Count:** `{af['raw_cvss_high_crit_count']}`
- **AEGIS Contextual High/Critical Count:** `{af['aegis_priority_high_crit_count']}`
- **Net Alert Reduction:** **{af['alert_fatigue_reduction_pct']}%**

### De-prioritized Low-Exposure Findings:
{chr(10).join(f"- **{f['title']}**: Raw CVSS `{f['cvss']}` dropped to AEGIS Priority `{f['priority']}` (EPSS: `{f['epss']}`, Reachability: `{f['reachability']}`)" for f in af['deprioritized_findings'])}

---

## 4. AI Copilot Grounding & Anti-Hallucination

Every AI-generated response is subject to a strict CVE grounding guardrail that intercepts and flags any CVE cited by the model that does not exist in the verified telemetry report.

- **Test Battery:** `{cg['total_queries_tested']}` adversarial and standard prompt queries
- **Correct Guardrail Interceptions:** `{cg['correct_assessments']}`
- **Grounding Accuracy:** **{cg['grounding_guardrail_accuracy_pct']}%**

---

## 5. Documented Scope Boundaries & Honest Limitations

Perimeter RBVM scanners have natural structural boundaries. AEGIS-AI explicitly documents what is outside of perimeter scan scope:

{chr(10).join(f"- **{lim['id']}**: {lim['label']}" for lim in limits)}
"""
    os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Generated evaluation report: {out_file}")


def main():
    parser = argparse.ArgumentParser(description="AEGIS-AI Benchmark & Evaluation")
    parser.add_argument("--report", default=None, help="Path to report JSON")
    parser.add_argument("--out", default="docs/EVALUATION.md", help="Output markdown path")
    args = parser.parse_args()

    results = run_full_evaluation(args.report)
    print_cli_summary(results)
    generate_evaluation_markdown(results, args.out)


if __name__ == "__main__":
    main()
