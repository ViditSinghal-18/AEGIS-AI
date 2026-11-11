"""
Advisory Consistency Check between Public Vulnerability Databases (NVD vs. OSV).

Inspired by:
    Dong, Y., Guo, W., Chen, X., & Liu, P. "Towards the Detection of Inconsistencies
    in Public Vulnerability Repositories." In USENIX Security Symposium, 2019.

Research rationale:
    Public vulnerability disclosures (NVD, GitHub Security Advisories via OSV,
    vendor advisories) frequently diverge on affected software versions, fixed
    releases, and CVSS severity metrics. Flagging these discrepancies prevents false
    positives and attaches an explicit, evidence-grounded confidence badge to every
    prioritized finding.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from config import DATA_DIR
from schemas import CveRecord

logger = logging.getLogger(__name__)

CACHE_DIR = DATA_DIR / "cache" / "advisory_consistency"


@dataclass
class AdvisoryConsistencyResult:
    """Evaluation result comparing NVD and OSV vulnerability metadata."""

    cve_id: str
    confidence: str  # "high" | "medium" | "low"
    reason: str
    nvd_cvss: Optional[float] = None
    osv_cvss: Optional[float] = None
    cvss_delta: Optional[float] = None
    nvd_ranges: List[str] = field(default_factory=list)
    osv_ranges: List[str] = field(default_factory=list)
    is_consistent: bool = True
    discrepancy_details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_nvd_version_constraints(nvd_data: Any) -> List[str]:
    """Extract affected version interval strings from NVD CVE structure."""
    constraints: List[str] = []
    if not nvd_data:
        return constraints

    # If it's a CveRecord dataclass
    if isinstance(nvd_data, CveRecord):
        return [f"CPE-matched query: {nvd_data.source_query}"] if nvd_data.source_query else []

    # If it's raw NVD JSON payload
    configurations = nvd_data.get("configurations") or []
    for conf in configurations:
        nodes = conf.get("nodes") or []
        for node in nodes:
            cpe_matches = node.get("cpeMatch") or []
            for match in cpe_matches:
                parts = []
                start_inc = match.get("versionStartIncluding")
                start_exc = match.get("versionStartExcluding")
                end_inc = match.get("versionEndIncluding")
                end_exc = match.get("versionEndExcluding")
                criteria = match.get("criteria", "")

                if start_inc:
                    parts.append(f">={start_inc}")
                elif start_exc:
                    parts.append(f">{start_exc}")

                if end_inc:
                    parts.append(f"<={end_inc}")
                elif end_exc:
                    parts.append(f"<{end_exc}")

                if parts:
                    constraints.append(", ".join(parts))
                elif criteria:
                    # Parse version from CPE string: cpe:2.3:a:vendor:product:version:...
                    tokens = criteria.split(":")
                    if len(tokens) > 5 and tokens[5] not in ["*", "-"]:
                        constraints.append(f"=={tokens[5]}")

    return sorted(list(set(constraints)))


def _extract_osv_version_constraints(osv_data: Any) -> Tuple[List[str], Optional[float]]:
    """Extract affected version intervals and CVSS score from Google OSV JSON."""
    constraints: List[str] = []
    osv_cvss: Optional[float] = None

    if not osv_data:
        return constraints, osv_cvss

    # Extract CVSS if present
    severity_items = osv_data.get("severity") or []
    for item in severity_items:
        score_val = item.get("score")
        if isinstance(score_val, str) and score_val.startswith("CVSS:"):
            # CVSS Vector string, try parsing or lookup
            pass
        elif isinstance(score_val, (int, float)):
            osv_cvss = float(score_val)

    # Some advisories store CVSS in database_specific
    if osv_cvss is None:
        db_spec = osv_data.get("database_specific") or {}
        if "cvss" in db_spec:
            try:
                osv_cvss = float(db_spec["cvss"].get("score", 0.0))
            except Exception:
                pass

    # Extract ranges
    affected_list = osv_data.get("affected") or []
    for aff in affected_list:
        ranges = aff.get("ranges") or []
        for r in ranges:
            events = r.get("events") or []
            current_range = []
            for ev in events:
                if "introduced" in ev and ev["introduced"] != "0":
                    current_range.append(f">={ev['introduced']}")
                if "fixed" in ev:
                    current_range.append(f"<{ev['fixed']}")
                if "last_affected" in ev:
                    current_range.append(f"<={ev['last_affected']}")
            if current_range:
                constraints.append(", ".join(current_range))

        versions = aff.get("versions") or []
        if versions and len(versions) <= 8:
            constraints.append(f"versions: {', '.join(versions)}")

    return sorted(list(set(constraints))), osv_cvss


def check_advisory_consistency(
    cve_id: str,
    nvd_record: Any = None,
    osv_data: Optional[Dict[str, Any]] = None,
) -> AdvisoryConsistencyResult:
    """Compare affected version intervals and severity between NVD and OSV.

    Args:
        cve_id: Standard CVE identifier (e.g., 'CVE-2021-44228').
        nvd_record: CveRecord or raw NVD JSON dict from NVD lookup.
        osv_data: Optional OSV JSON payload (pre-fetched or queried).

    Returns:
        AdvisoryConsistencyResult with high/medium/low confidence badge and reason.
    """
    clean_id = cve_id.strip().upper()
    discrepancies: List[str] = []

    # 1. Resolve NVD information
    nvd_cvss: Optional[float] = None
    if isinstance(nvd_record, CveRecord):
        nvd_cvss = nvd_record.cvss_score
    elif isinstance(nvd_record, dict):
        nvd_cvss = nvd_record.get("cvss_score")
        if nvd_cvss is None and "metrics" in nvd_record:
            from correlation.nvd_lookup import _cvss_from_metrics
            nvd_cvss, _ = _cvss_from_metrics(nvd_record.get("metrics") or {})

    nvd_ranges = _extract_nvd_version_constraints(nvd_record)

    # 2. Resolve OSV information
    # If not provided, check if cached or if we should fetch
    if osv_data is None:
        try:
            from discovery.safe_fetch import safe_fetch
            url = f"https://api.osv.dev/v1/vulns/{clean_id}"
            resp = safe_fetch(url, timeout=3.0)
            if resp.status_code == 200:
                osv_data = resp.json()
        except Exception:
            osv_data = None

    osv_ranges, osv_cvss = _extract_osv_version_constraints(osv_data)

    # 3. Assess consistency
    # Case A: Only one source is available
    if not osv_data:
        # We only have NVD
        return AdvisoryConsistencyResult(
            cve_id=clean_id,
            confidence="medium",
            reason="Single advisory source available (NVD only); cross-repository validation unavailable.",
            nvd_cvss=nvd_cvss,
            osv_cvss=None,
            cvss_delta=None,
            nvd_ranges=nvd_ranges,
            osv_ranges=[],
            is_consistent=True,
            discrepancy_details=["OSV advisory record not indexed for this vulnerability."],
        )

    if nvd_record is None:
        # We only have OSV
        return AdvisoryConsistencyResult(
            cve_id=clean_id,
            confidence="medium",
            reason="Single advisory source available (OSV only); NVD record unavailable.",
            nvd_cvss=None,
            osv_cvss=osv_cvss,
            cvss_delta=None,
            nvd_ranges=[],
            osv_ranges=osv_ranges,
            is_consistent=True,
            discrepancy_details=["NVD CVE entry not populated or unparsed."],
        )

    # Case B: Both NVD and OSV data are available — run comparison!
    cvss_delta: Optional[float] = None
    if nvd_cvss is not None and osv_cvss is not None:
        cvss_delta = round(abs(nvd_cvss - osv_cvss), 2)
        if cvss_delta > 2.5:
            discrepancies.append(
                f"Severe CVSS divergence: NVD reports {nvd_cvss} while OSV reports {osv_cvss} (delta: {cvss_delta})"
            )
        elif cvss_delta > 1.0:
            discrepancies.append(
                f"Moderate CVSS difference: NVD={nvd_cvss} vs OSV={osv_cvss} (delta: {cvss_delta})"
            )

    # Compare version boundary bounds if present in both
    version_conflict = False
    if nvd_ranges and osv_ranges:
        # Check for conflicting fixed version markers
        nvd_fixed = [r for r in nvd_ranges if "<" in r]
        osv_fixed = [r for r in osv_ranges if "<" in r]
        if nvd_fixed and osv_fixed and nvd_fixed != osv_fixed:
            # Check if completely disjoint
            nvd_text = "; ".join(nvd_fixed)
            osv_text = "; ".join(osv_fixed)
            if not any(token in osv_text for token in nvd_fixed):
                version_conflict = True
                discrepancies.append(
                    f"Conflicting version bounds: NVD asserts [{nvd_text}] but OSV specifies [{osv_text}]"
                )

    # Decide confidence badge
    if version_conflict or (cvss_delta is not None and cvss_delta > 2.5):
        confidence = "low"
        is_consistent = False
        reason = f"Advisory conflict detected between NVD and OSV: {'; '.join(discrepancies)}"
    elif discrepancies:
        confidence = "medium"
        is_consistent = True
        reason = f"Minor advisory divergence between NVD and OSV: {'; '.join(discrepancies)}"
    else:
        confidence = "high"
        is_consistent = True
        reason = "NVD and OSV advisories agree on affected version boundaries and flaw severity."

    return AdvisoryConsistencyResult(
        cve_id=clean_id,
        confidence=confidence,
        reason=reason,
        nvd_cvss=nvd_cvss,
        osv_cvss=osv_cvss,
        cvss_delta=cvss_delta,
        nvd_ranges=nvd_ranges,
        osv_ranges=osv_ranges,
        is_consistent=is_consistent,
        discrepancy_details=discrepancies,
    )


def evaluate_findings_advisory_consistency(
    findings: List[Dict[str, Any]],
    nvd_cache_lookup: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Enrich a list of prioritized findings with advisory consistency badges."""
    nvd_lookup = nvd_cache_lookup or {}

    for f in findings:
        cves = f.get("related_cves") or []
        if not cves:
            continue

        # Evaluate the primary CVE
        primary_cve = cves[0]
        nvd_item = nvd_lookup.get(primary_cve)
        result = check_advisory_consistency(primary_cve, nvd_record=nvd_item)

        f["advisory_consistency"] = result.to_dict()
        f["advisory_confidence"] = result.confidence
        f["advisory_reason"] = result.reason

        # If consistency is low, mark discrepancy in finding context for uncertainty widening
        if result.confidence == "low":
            f["advisory_discrepancy"] = True
            f["confidence"] = "low"
        elif result.confidence == "high" and f.get("confidence") not in ["low", "medium"]:
            f["confidence"] = "high"

    return findings
