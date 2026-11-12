"""
Longitudinal Exposure Score Drift & CUSUM Change-Point Detection Engine.

Inspired by:
1. Page, E. S. "Continuous Inspection Schemes." Biometrika, 41(1/2), pp. 100-115, 1954.
2. Adams, R. P., & MacKay, D. J. "Bayesian Online Changepoint Detection."
   arXiv preprint arXiv:0710.3742, 2007.

Applies two-sided Cumulative Sum (CUSUM) quality-control charting to exposure-score
time series to differentiate statistically significant security posture shifts
(new vulnerabilities or regressions) from routine background noise.
Manages versioned historical scan storage (schema_version: '2.0').

NON-NEGOTIABLE AEGIS CONSTRAINTS:
- Deterministic change-point detection without fabricated noise.
- Explainable output detailing baseline mean, std, CUSUM values, and exact threshold.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import DATA_DIR

HISTORY_SCHEMA_VERSION = "2.0"
HISTORY_FILE_NAME = "history.json"


@dataclass
class ChangePointResult:
    """Statistical outcome of CUSUM exposure-score drift detection."""

    drift_detected: bool
    direction: str  # "deterioration", "improvement", "stable"
    change_point_index: Optional[int]
    shift_magnitude: float
    threshold: float
    baseline_mean: float
    baseline_std: float
    cusum_positive: List[float] = field(default_factory=list)
    cusum_negative: List[float] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_detected": self.drift_detected,
            "direction": self.direction,
            "change_point_index": self.change_point_index,
            "shift_magnitude": round(self.shift_magnitude, 3),
            "threshold": round(self.threshold, 3),
            "baseline_mean": round(self.baseline_mean, 3),
            "baseline_std": round(self.baseline_std, 3),
            "cusum_positive": [round(v, 3) for v in self.cusum_positive],
            "cusum_negative": [round(v, 3) for v in self.cusum_negative],
            "explanation": self.explanation,
        }


class CusumDriftDetector:
    """Two-sided CUSUM change-point detector (Page 1954)."""

    def __init__(self, k_sigma: float = 0.5, h_sigma: float = 3.5) -> None:
        """
        Args:
            k_sigma: Allowance parameter in units of sigma (default 0.5).
            h_sigma: Decision threshold parameter in units of sigma (default 3.5).
        """
        self.k_sigma = k_sigma
        self.h_sigma = h_sigma

    def detect(self, series: List[float], baseline_window: int = 4) -> ChangePointResult:
        """Evaluate a numeric exposure score series for statistically significant shift."""
        n = len(series)
        if n < 3:
            return ChangePointResult(
                drift_detected=False,
                direction="stable",
                change_point_index=None,
                shift_magnitude=0.0,
                threshold=0.0,
                baseline_mean=float(series[0]) if series else 0.0,
                baseline_std=0.0,
                explanation="Insufficient historical data points (< 3 scans) to detect statistical drift.",
            )

        # Establish baseline mean and standard deviation from initial window
        b_win = max(2, min(baseline_window, n - 1))
        baseline_slice = series[:b_win]
        mu_0 = sum(baseline_slice) / len(baseline_slice)
        variance = sum((x - mu_0) ** 2 for x in baseline_slice) / max(1, len(baseline_slice) - 1)
        sigma = math.sqrt(variance)

        # Floor sigma to prevent division by zero or hypersensitivity on constant series
        sigma_eff = max(0.1, sigma)
        k = self.k_sigma * sigma_eff
        h = self.h_sigma * sigma_eff

        c_pos: List[float] = [0.0]
        c_neg: List[float] = [0.0]

        drift_detected = False
        direction = "stable"
        change_idx: Optional[int] = None

        for i, x in enumerate(series[1:], 1):
            s_plus = max(0.0, c_pos[-1] + (x - mu_0) - k)
            s_minus = max(0.0, c_neg[-1] - (x - mu_0) - k)

            c_pos.append(s_plus)
            c_neg.append(s_minus)

            if not drift_detected:
                if s_plus >= h:
                    drift_detected = True
                    direction = "deterioration"
                    change_idx = i
                elif s_minus >= h:
                    drift_detected = True
                    direction = "improvement"
                    change_idx = i

        current_val = series[-1]
        shift_mag = current_val - mu_0

        if drift_detected:
            if direction == "deterioration":
                expl = (
                    f"Statistical Risk Deterioration detected at scan #{change_idx + 1} "
                    f"(CUSUM+ = {c_pos[-1]:.2f} >= threshold {h:.2f}). "
                    f"Current exposure score ({current_val:.2f}) increased by +{shift_mag:.2f} above baseline ({mu_0:.2f})."
                )
            else:
                expl = (
                    f"Statistical Risk Improvement detected at scan #{change_idx + 1} "
                    f"(CUSUM- = {c_neg[-1]:.2f} >= threshold {h:.2f}). "
                    f"Current exposure score ({current_val:.2f}) reduced by {shift_mag:.2f} below baseline ({mu_0:.2f})."
                )
        else:
            expl = (
                f"Security posture is stable (CUSUM+ = {c_pos[-1]:.2f}, CUSUM- = {c_neg[-1]:.2f} < threshold {h:.2f}). "
                f"Variations remain within normal statistical tolerance."
            )

        return ChangePointResult(
            drift_detected=drift_detected,
            direction=direction,
            change_point_index=change_idx,
            shift_magnitude=shift_mag,
            threshold=h,
            baseline_mean=mu_0,
            baseline_std=sigma_eff,
            cusum_positive=c_pos,
            cusum_negative=c_neg,
            explanation=expl,
        )


def _get_history_file_path() -> Path:
    """Return canonical path to versioned history.json."""
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir / HISTORY_FILE_NAME


def load_history(target: str = "default") -> Dict[str, Any]:
    """Load historical scan telemetry from versioned JSON storage."""
    file_path = _get_history_file_path()
    if not file_path.exists():
        return {
            "schema_version": HISTORY_SCHEMA_VERSION,
            "target": target,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "snapshots": [],
        }

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if data.get("schema_version") != HISTORY_SCHEMA_VERSION:
                # Migrate or set version
                data["schema_version"] = HISTORY_SCHEMA_VERSION
            return data
    except Exception:
        return {
            "schema_version": HISTORY_SCHEMA_VERSION,
            "target": target,
            "snapshots": [],
        }


def save_history(history_data: Dict[str, Any]) -> None:
    """Persist history telemetry to versioned JSON file."""
    file_path = _get_history_file_path()
    history_data["schema_version"] = HISTORY_SCHEMA_VERSION
    history_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(history_data, f, indent=2)


def append_scan_snapshot(
    target: str,
    overall_score: float,
    findings: List[Dict[str, Any]],
    timestamp_days: Optional[float] = None,
) -> Tuple[Dict[str, Any], ChangePointResult]:
    """Append a newly completed scan snapshot and evaluate for statistical drift."""
    hist = load_history(target=target)
    snapshots = hist.get("snapshots", [])

    now_ts = datetime.now(timezone.utc).isoformat()
    t_days = timestamp_days if timestamp_days is not None else float(len(snapshots) * 7.0)

    crit_count = sum(1 for f in findings if str(f.get("severity", "")).title() == "Critical")
    high_count = sum(1 for f in findings if str(f.get("severity", "")).title() == "High")

    new_snap = {
        "snapshot_id": f"scan-{len(snapshots) + 1}",
        "timestamp": now_ts,
        "timestamp_days": round(t_days, 2),
        "overall_risk_score": round(float(overall_score), 2),
        "findings_count": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "findings": [
            {
                "id": f.get("id") or f.get("title"),
                "title": f.get("title"),
                "severity": f.get("severity"),
            }
            for f in findings
        ],
    }

    snapshots.append(new_snap)
    hist["snapshots"] = snapshots
    save_history(hist)

    # Run CUSUM drift detection on series of risk scores
    series = [float(s["overall_risk_score"]) for s in snapshots]
    detector = CusumDriftDetector()
    drift_res = detector.detect(series)

    return hist, drift_res
