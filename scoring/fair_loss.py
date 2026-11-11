"""
AEGIS-AI: FAIR-Style Quantitative Loss Quantification Engine.

Implements probabilistic Monte Carlo risk quantification:
- Threat Event Frequency (TEF) / Vulnerability derived from FIRST.org EPSS & Exposure
- Loss Magnitude modeled via configurable loss distribution scaled by Asset Criticality
- Reproducible seeded Monte Carlo simulation
- Generates Expected Annual Loss (ALE) and 90% Confidence Intervals [5th, 95th percentile]

Inspired by:
- The Open Group (2013), "Open FAIR Risk Analysis Standard (O-RA)", The Open Group Standard.
  (Flag: verify before publishing)
- Hubbard & Seiersen (2016), "How to Measure Anything in Cybersecurity Risk", John Wiley & Sons.
  (Flag: verify before publishing)

DISCLAIMER:
All dollar projections are illustrative, user-supplied assumptions based on user-configured
loss parameters. They do not constitute financial, legal, or actuarial guarantees.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np

# Default illustrative dollar assumptions (user-configurable via environment)
DEFAULT_FAIR_SIMULATIONS = int(os.getenv("FAIR_SIMULATIONS", "1000"))
DEFAULT_FAIR_SEED = int(os.getenv("FAIR_SEED", "42"))
DEFAULT_LOSS_MIN = float(os.getenv("FAIR_LOSS_MIN", "5000.0"))
DEFAULT_LOSS_MODE = float(os.getenv("FAIR_LOSS_MODE", "25000.0"))
DEFAULT_LOSS_MAX = float(os.getenv("FAIR_LOSS_MAX", "150000.0"))

DISCLAIMER_TEXT = "illustrative, user-supplied assumptions (not actuarial advice)"


def simulate_fair_loss(
    epss_prob: float,
    exposure_factor: float = 1.0,
    business_criticality: float = 5.0,
    simulations: int = DEFAULT_FAIR_SIMULATIONS,
    seed: int = DEFAULT_FAIR_SEED,
    loss_min: Optional[float] = None,
    loss_mode: Optional[float] = None,
    loss_max: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Run a reproducible seeded Monte Carlo simulation to compute Expected Annual Loss.

    Args:
        epss_prob: EPSS probability of weaponization in [0.0, 1.0].
        exposure_factor: Ingress exposure factor in [0.0, 1.0].
        business_criticality: Asset criticality rating in [1.0, 10.0].
        simulations: Number of Monte Carlo iterations (default: 1000).
        seed: Deterministic random seed for reproducibility.
        loss_min: Minimum per-incident loss magnitude.
        loss_mode: Most likely per-incident loss magnitude.
        loss_max: Maximum per-incident loss magnitude.

    Returns:
        Structured dictionary with ale_mean, ale_median, ci_90, ale_max, parameters.
    """
    p_min = loss_min if loss_min is not None else DEFAULT_LOSS_MIN
    p_mode = loss_mode if loss_mode is not None else DEFAULT_LOSS_MODE
    p_max = loss_max if loss_max is not None else DEFAULT_LOSS_MAX

    # Defensive validation
    if p_min <= 0 or p_mode < p_min or p_max < p_mode:
        p_min, p_mode, p_max = 5000.0, 25000.0, 150000.0

    # Scale loss magnitude by asset criticality (baseline 5.0 = 1.0x scale)
    crit_scale = max(0.2, business_criticality / 5.0)
    scaled_min = p_min * crit_scale
    scaled_mode = p_mode * crit_scale
    scaled_max = p_max * crit_scale

    # Annualized exploit event probability proxy:
    # EPSS provides 30-day weaponization probability; compound/scale defensively
    p_exploit = min(1.0, max(0.0001, float(epss_prob) * float(exposure_factor)))

    # Seeded RNG for strict determinism
    rng = np.random.default_rng(seed)

    # 1. Simulate Threat Event occurrence (Bernoulli trials)
    events = rng.random(size=simulations) < p_exploit

    # 2. Simulate Loss Magnitude for occurring events via Triangular / PERT distribution
    losses = np.zeros(simulations, dtype=np.float64)
    num_events = int(np.sum(events))

    if num_events > 0:
        event_losses = rng.triangular(left=scaled_min, mode=scaled_mode, right=scaled_max, size=num_events)
        losses[events] = event_losses

    # 3. Compute Summary Statistics
    ale_mean = float(np.mean(losses))
    ale_median = float(np.median(losses))
    ci_5 = float(np.percentile(losses, 5.0))
    ci_95 = float(np.percentile(losses, 95.0))
    ale_max = float(np.max(losses))
    prob_of_loss = float(np.mean(losses > 0.0))

    return {
        "ale_mean": round(ale_mean, 2),
        "ale_median": round(ale_median, 2),
        "ci_90": [round(ci_5, 2), round(ci_95, 2)],
        "ale_max": round(ale_max, 2),
        "loss_probability": round(prob_of_loss, 4),
        "parameters": {
            "simulations": simulations,
            "seed": seed,
            "threat_event_prob": round(p_exploit, 4),
            "loss_magnitude_min": round(scaled_min, 2),
            "loss_magnitude_mode": round(scaled_mode, 2),
            "loss_magnitude_max": round(scaled_max, 2),
            "asset_criticality_factor": round(crit_scale, 2),
        },
        "assumption_disclaimer": DISCLAIMER_TEXT,
    }


def simulate_portfolio_fair_loss(
    findings: Sequence[Dict[str, Any]],
    simulations: int = DEFAULT_FAIR_SIMULATIONS,
    seed: int = DEFAULT_FAIR_SEED,
    loss_min: Optional[float] = None,
    loss_mode: Optional[float] = None,
    loss_max: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Run an aggregate Monte Carlo simulation across an entire portfolio of findings.
    
    Returns cumulative annualized loss distribution across all findings.
    """
    if not findings:
        return {
            "portfolio_ale_mean": 0.0,
            "portfolio_ale_median": 0.0,
            "portfolio_ci_90": [0.0, 0.0],
            "portfolio_ale_max": 0.0,
            "findings_modeled": 0,
            "assumption_disclaimer": DISCLAIMER_TEXT,
        }

    rng = np.random.default_rng(seed)
    total_portfolio_losses = np.zeros(simulations, dtype=np.float64)

    p_min = loss_min if loss_min is not None else DEFAULT_LOSS_MIN
    p_mode = loss_mode if loss_mode is not None else DEFAULT_LOSS_MODE
    p_max = loss_max if loss_max is not None else DEFAULT_LOSS_MAX

    for f in findings:
        epss = float(f.get("epss_probability", 0.005))
        if f.get("in_cisa_kev"):
            epss = max(epss, 0.75)

        s_exp = float(f.get("xai_formula", {}).get("s_exposure", 0.5))
        crit_scale = max(0.2, float(f.get("xai_formula", {}).get("s_crit", 0.5)) * 2.0)

        scaled_min = p_min * crit_scale
        scaled_mode = p_mode * crit_scale
        scaled_max = p_max * crit_scale

        p_exploit = min(1.0, max(0.0001, epss * s_exp))
        events = rng.random(size=simulations) < p_exploit
        num_events = int(np.sum(events))

        if num_events > 0:
            finding_losses = rng.triangular(left=scaled_min, mode=scaled_mode, right=scaled_max, size=num_events)
            total_portfolio_losses[events] += finding_losses

    ale_mean = float(np.mean(total_portfolio_losses))
    ale_median = float(np.median(total_portfolio_losses))
    ci_5 = float(np.percentile(total_portfolio_losses, 5.0))
    ci_95 = float(np.percentile(total_portfolio_losses, 95.0))
    ale_max = float(np.max(total_portfolio_losses))

    return {
        "portfolio_ale_mean": round(ale_mean, 2),
        "portfolio_ale_median": round(ale_median, 2),
        "portfolio_ci_90": [round(ci_5, 2), round(ci_95, 2)],
        "portfolio_ale_max": round(ale_max, 2),
        "findings_modeled": len(findings),
        "simulations": simulations,
        "seed": seed,
        "assumption_disclaimer": DISCLAIMER_TEXT,
    }
