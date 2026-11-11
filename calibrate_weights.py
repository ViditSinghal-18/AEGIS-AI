"""
AEGIS-AI: CLI Entrypoint for Scoring Weight Calibration.

Usage:
    python calibrate_weights.py [--split-year 2023] [--samples 1000] [--seed 42]

Inspired by:
- Bozorgi et al. (2010), "Beyond Heuristics: Learning to Classify Vulnerabilities", ACM KDD.
  (Flag: verify before publishing)
- Jacobs et al. (2021), "Exploit Prediction Scoring System (EPSS)", Digital Threats: Research and Practice.
  (Flag: verify before publishing)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scoring.calibrate_weights import calibrate_scoring_weights


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate AEGIS-AI risk scoring weights against CISA KEV empirical weaponization data."
    )
    parser.add_argument(
        "--split-year",
        type=int,
        default=2023,
        help="Cutoff year for temporal train/test split to prevent data leakage (default: 2023)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1000,
        help="Number of CVE records in calibration dataset (default: 1000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic RNG seed for reproducible experiments (default: 42)",
    )

    args = parser.parse_args()

    print("================================================================================")
    print("           AEGIS-AI: EMPIRICAL RISK SCORING WEIGHT CALIBRATION                  ")
    print("================================================================================")
    print(f"[*] Temporal split cutoff: Year < {args.split_year} (Train) vs >= {args.split_year} (Test)")
    print(f"[*] Calibration dataset size: {args.samples} samples (Seed: {args.seed})")

    report = calibrate_scoring_weights(
        split_year=args.split_year,
        seed=args.seed,
        num_samples=args.samples,
    )

    print("\n[+] Learned Weights (Sum = 1.0):")
    for k, v in report["learned_weights"].items():
        print(f"    - {k:<15}: {v:.3f} (default: {report['default_weights'][k]:.2f})")

    print("\n[+] Comparative Ranking Performance on Unseen Test Split (Post-Cutoff):")
    print(f"{'Method':<28} | {'P@10':<7} | {'R@10':<7} | {'P@50':<7} | {'R@50':<7}")
    print("-" * 65)

    for method, p_r in report["comparative_metrics"].items():
        p10 = p_r["k=10"]["precision"]
        r10 = p_r["k=10"]["recall"]
        p50 = p_r["k=50"]["precision"]
        r50 = p_r["k=50"]["recall"]
        print(f"{method:<28} | {p10:<7.3f} | {r10:<7.3f} | {p50:<7.3f} | {r50:<7.3f}")

    print(f"\n[+] Calibration report persisted to: {report['saved_report_path']}")
    print("[!] NOTE: Production defaults remain active until `SCORING_WEIGHTS_SOURCE=calibrated` is set in config.")


if __name__ == "__main__":
    main()
