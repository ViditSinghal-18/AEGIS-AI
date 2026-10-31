"""
AEGIS-AI: Real-world Exploitability & Threat Intelligence Enrichment.
Enriches discovered CVEs using:
- CISA KEV (Known Exploited Vulnerabilities - BOD 22-01)
- FIRST.org EPSS (Exploit Prediction Scoring System v3)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import config
from discovery.safe_fetch import safe_fetch

CACHE_DIR = config.DATA_DIR / "cache"
KEV_CACHE_FILE = CACHE_DIR / "kev_catalog.json"
EPSS_CACHE_DIR = CACHE_DIR / "epss"
KEV_CACHE_TTL = 86400 * 7  # 7 days
EPSS_CACHE_TTL = 86400 * 3  # 3 days

# Baseline offline KEV catalog fallback (well-known CVEs)
BASELINE_KEV = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2023-38606",  # WebKit
    "CVE-2024-29041",  # Express open redirect in phishing
    "CVE-2024-3400",   # PAN-OS
    "CVE-2023-22515",  # Confluence
    "CVE-2021-26855",  # Exchange ProxyLogon
}


def load_cisa_kev_catalog() -> Set[str]:
    """Fetch and cache CISA KEV catalog of actively weaponized CVEs."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()

    if KEV_CACHE_FILE.exists():
        try:
            mtime = KEV_CACHE_FILE.stat().st_mtime
            if now - mtime < KEV_CACHE_TTL:
                data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
                return set(data.get("cve_ids", []))
        except Exception:
            pass

    try:
        resp = safe_fetch(config.CISA_KEV_FEED, timeout=8.0)
        if resp.status_code == 200:
            payload = resp.json()
            vulns = payload.get("vulnerabilities", [])
            cve_ids = [v.get("cveID") for v in vulns if v.get("cveID")]
            if cve_ids:
                KEV_CACHE_FILE.write_text(
                    json.dumps({"updated_at": now, "count": len(cve_ids), "cve_ids": cve_ids}),
                    encoding="utf-8"
                )
                return set(cve_ids)
    except Exception:
        pass

    # Fallback to cached or baseline
    if KEV_CACHE_FILE.exists():
        try:
            data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
            return set(data.get("cve_ids", []))
        except Exception:
            pass

    return set(BASELINE_KEV)


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Fetch EPSS probabilities and percentiles from FIRST.org API with disk caching.
    Returns: {cve_id: {"epss": float, "percentile": float, "date": str}}
    """
    cleaned = [c for c in cve_ids if c and c.startswith("CVE-")]
    if not cleaned:
        return {}

    EPSS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Dict[str, Any]] = {}
    missing_cves: List[str] = []
    now = time.time()

    for cve in cleaned:
        cache_path = EPSS_CACHE_DIR / f"{cve}.json"
        if cache_path.exists():
            try:
                if now - cache_path.stat().st_mtime < EPSS_CACHE_TTL:
                    cached_data = json.loads(cache_path.read_text(encoding="utf-8"))
                    results[cve] = cached_data
                    continue
            except Exception:
                pass
        missing_cves.append(cve)

    if missing_cves:
        try:
            # Batch in chunks of 30
            for i in range(0, len(missing_cves), 30):
                chunk = missing_cves[i:i+30]
                query_str = ",".join(chunk)
                url = f"{config.FIRST_EPSS_API}?cve={query_str}"
                resp = safe_fetch(url, timeout=6.0)
                if resp.status_code == 200:
                    payload = resp.json()
                    for row in payload.get("data", []):
                        cid = row.get("cve")
                        epss_val = float(row.get("epss", 0.005))
                        perc_val = float(row.get("percentile", 0.40))
                        entry = {
                            "cve": cid,
                            "epss": epss_val,
                            "percentile": perc_val,
                            "date": row.get("date", time.strftime("%Y-%m-%d")),
                            "source": "FIRST.org Live API"
                        }
                        results[cid] = entry
                        try:
                            (EPSS_CACHE_DIR / f"{cid}.json").write_text(
                                json.dumps(entry, indent=2), encoding="utf-8"
                            )
                        except Exception:
                            pass
        except Exception:
            pass

    # Provide safe fallback for any remaining CVEs
    for cve in cleaned:
        if cve not in results:
            results[cve] = {
                "cve": cve,
                "epss": 0.005,
                "percentile": 0.40,
                "date": time.strftime("%Y-%m-%d"),
                "source": "EPSS Baseline Default"
            }

    return results


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich raw security findings with CISA KEV and EPSS data.
    """
    kev_set = load_cisa_kev_catalog()
    all_cves = []
    for f in findings:
        for cve in f.get("related_cves", []):
            if cve.startswith("CVE-"):
                all_cves.append(cve)

    epss_map = fetch_epss_scores(list(set(all_cves)))

    enriched = []
    for f in findings:
        item = dict(f)
        cves = [c for c in item.get("related_cves", []) if c.startswith("CVE-")]
        item_kev = any(c in kev_set for c in cves)
        item["in_cisa_kev"] = item_kev
        item["cisa_kev_status"] = "KNOWN EXPLOITED (CISA KEV)" if item_kev else "Not Listed in CISA KEV"

        # Pick highest EPSS score among CVEs
        max_epss = 0.005
        max_perc = 0.40
        for c in cves:
            if c in epss_map:
                if epss_map[c]["epss"] > max_epss:
                    max_epss = epss_map[c]["epss"]
                    max_perc = epss_map[c]["percentile"]

        item["epss_probability"] = round(max_epss, 5)
        item["epss_percentile"] = round(max_perc, 4)
        enriched.append(item)

    return enriched
