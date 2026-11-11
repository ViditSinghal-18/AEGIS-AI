"""
AEGIS-AI Scientifically Defensible Scoring Package.

Modules:
- ranking_metrics: Spearman rho, Kendall tau-b, Rank-Biased Overlap (RBO@k).
- ssvc: Stakeholder-Specific Vulnerability Categorization (CISA SSVC v2.0).
- uncertainty: Conformal-inspired calibrated risk interval quantification.
- fair_loss: FAIR-style Monte Carlo quantitative annual loss estimation.
- calibrate_weights: Supervised logistic regression calibration on CISA KEV data.
"""

from scoring.ranking_metrics import (
    spearman_rho,
    kendall_tau,
    rank_biased_overlap,
    compute_ranking_concordance,
)
from scoring.ssvc import evaluate_ssvc
from scoring.uncertainty import compute_risk_interval
from scoring.fair_loss import simulate_fair_loss, simulate_portfolio_fair_loss
from scoring.calibrate_weights import (
    calibrate_scoring_weights,
    load_calibrated_weights,
)

__all__ = [
    "spearman_rho",
    "kendall_tau",
    "rank_biased_overlap",
    "compute_ranking_concordance",
    "evaluate_ssvc",
    "compute_risk_interval",
    "simulate_fair_loss",
    "simulate_portfolio_fair_loss",
    "calibrate_scoring_weights",
    "load_calibrated_weights",
]
