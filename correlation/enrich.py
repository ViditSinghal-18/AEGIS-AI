"""
Real-world exploitability enrichment via CISA KEV and FIRST EPSS.

Security terms explained for 3rd semester students:
- CISA KEV (Known Exploited Vulnerabilities): A catalog published by the US Cybersecurity &
  Infrastructure Security Agency listing vulnerabilities actively weaponized and exploited
  by real-world threat actors in the wild.
- EPSS (Exploit Prediction Scoring System): A data-driven model by FIRST.org that outputs a
  probability score between 0.0 and 1.0 (0% to 100%) predicting whether a CVE will be exploited
  in the next 30 days based on dark web activity, honeypot signals, and threat intel.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from config import DATA_DIR
from schemas import CveRecord

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = DATA_DIR / "cache"
KEV_CACHE_FILE = CACHE_DIR / "kev_catalog.json"
EPSS_CACHE_DIR = CACHE_DIR / "epss"

KEV_CACHE_TTL_SECONDS = 86400  # 24 hours
EPSS_CACHE_TTL_SECONDS = 86400  # 24 hours


def _load_cisa_kev_catalog() -> set[str]:
    """
    Fetch and cache the CISA KEV catalog for 24 hours.
    Returns a set of CVE IDs (e.g. {'CVE-2021-44228', 'CVE-2023-38606'}).
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()

    # Check if cached catalog is still fresh (< 24 hours)
    if KEV_CACHE_FILE.exists():
        try:
            mtime = KEV_CACHE_FILE.stat().st_mtime
            if now - mtime < KEV_CACHE_TTL_SECONDS:
                data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
                return set(data.get("cve_ids") or [])
        except (json.JSONDecodeError, OSError):
            pass

    # Fetch from CISA with strict timeout and context manager
    try:
        with requests.get(CISA_KEV_URL, timeout=15) as response:
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities") or []
            cve_ids = [v.get("cveID") for v in vulnerabilities if v.get("cveID")]
            
            # Save cache
            KEV_CACHE_FILE.write_text(
                json.dumps({"updated_at": now, "count": len(cve_ids), "cve_ids": cve_ids}),
                encoding="utf-8",
            )
            return set(cve_ids)
    except (requests.RequestException, json.JSONDecodeError, OSError, ValueError) as exc:
        # Graceful fallback: return empty set or stale cache if network unavailable
        if KEV_CACHE_FILE.exists():
            try:
                data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
                return set(data.get("cve_ids") or [])
            except (json.JSONDecodeError, OSError):
                pass
        return set()


def _get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Query the FIRST EPSS API for a batch of CVEs.
    Returns a mapping of {cve_id: epss_score}.
    """
    if not cve_ids:
        return {}

    EPSS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    results: dict[str, float] = {}
    missing_cves: list[str] = []
    now = time.time()

    # Check local cache first with TTL validation
    for cve_id in cve_ids:
        cache_file = EPSS_CACHE_DIR / f"{cve_id}.json"
        if cache_file.exists():
            try:
                mtime = cache_file.stat().st_mtime
                if now - mtime < EPSS_CACHE_TTL_SECONDS:
                    cached = json.loads(cache_file.read_text(encoding="utf-8"))
                    cached_at = cached.get("cached_at")
                    if cached_at and (now - cached_at > EPSS_CACHE_TTL_SECONDS):
                        cache_file.unlink(missing_ok=True)
                    else:
                        results[cve_id] = float(cached["epss"])
                        continue
                else:
                    cache_file.unlink(missing_ok=True)
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                cache_file.unlink(missing_ok=True)
        missing_cves.append(cve_id)

    if not missing_cves:
        return results

    # Query EPSS API for uncached CVEs in comma-separated chunks
    chunk_size = 50
    for i in range(0, len(missing_cves), chunk_size):
        chunk = missing_cves[i : i + chunk_size]
        query_param = ",".join(chunk)
        try:
            with requests.get(
                EPSS_API_URL,
                params={"cve": query_param},
                timeout=15,
            ) as response:
                response.raise_for_status()
                data = response.json().get("data") or []
                for item in data:
                    cid = item.get("cve")
                    score_str = item.get("epss")
                    if cid and score_str is not None:
                        score = float(score_str)
                        results[cid] = score
                        # Cache on disk
                        cache_file = EPSS_CACHE_DIR / f"{cid}.json"
                        try:
                            cache_file.write_text(
                                json.dumps({"cve": cid, "epss": score, "cached_at": now}),
                                encoding="utf-8",
                            )
                        except OSError:
                            pass
        except (requests.RequestException, json.JSONDecodeError, OSError, ValueError):
            # Network or API failure: fail gracefully, leave scores as None
            pass

    return results


def enrich_cves(cves: list[CveRecord], notes: list[str] | None = None) -> list[CveRecord]:
    """
    Enrich a list of CveRecords in-place with CISA KEV exploit status and EPSS scores.
    """
    if not cves:
        return cves

    cve_ids = [c.cve_id for c in cves if c.cve_id]
    if not cve_ids:
        return cves

    # 1. Enrich with CISA KEV
    try:
        kev_set = _load_cisa_kev_catalog()
        for record in cves:
            if record.cve_id in kev_set:
                record.kev = True
    except (requests.RequestException, OSError, ValueError) as exc:
        if notes is not None:
            notes.append(f"CISA KEV check skipped: {exc.__class__.__name__}")

    # 2. Enrich with EPSS scores
    try:
        epss_map = _get_epss_scores(cve_ids)
        for record in cves:
            if record.cve_id in epss_map:
                record.epss = epss_map[record.cve_id]
    except (requests.RequestException, OSError, ValueError) as exc:
        if notes is not None:
            notes.append(f"EPSS score check skipped: {exc.__class__.__name__}")

    return cves


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich an array of finding dictionaries with CISA KEV and EPSS intelligence."""
    if not findings:
        return findings

    cve_ids: list[str] = []
    for f in findings:
        for cve in f.get("related_cves", []):
            if cve and cve not in cve_ids:
                cve_ids.append(cve)

    kev_catalog: set[str] = set()
    try:
        kev_catalog = _load_cisa_kev_catalog()
    except Exception:
        pass

    epss_scores: dict[str, float] = {}
    if cve_ids:
        try:
            epss_scores = _get_epss_scores(cve_ids)
        except Exception:
            pass

    for f in findings:
        f_cves = f.get("related_cves", [])
        is_kev = any(c in kev_catalog for c in f_cves)
        max_epss = max([epss_scores.get(c, 0.0) for c in f_cves], default=0.0)
        f["kev"] = is_kev
        f["in_cisa_kev"] = is_kev
        f["epss"] = max_epss
        f["epss_score"] = max_epss
        f["epss_probability"] = max_epss
        if is_kev:
            f["cisa_kev_status"] = "Actively Exploited In Wild"
        if max_epss > 0:
            f["epss_percentile"] = f"{round(max_epss * 100, 1)}%"
        else:
            f["epss_percentile"] = "0.0%"
    return findings


load_cisa_kev_catalog = _load_cisa_kev_catalog
fetch_epss_scores = _get_epss_scores



