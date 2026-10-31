"""
AEGIS-AI: NVD & OSV Vulnerability Intelligence Lookup Engine.
Queries the National Vulnerability Database (NVD API 2.0) and Google Open Source Vulnerabilities (OSV)
with multi-tier disk caching and rate limiting.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config
from discovery.safe_fetch import safe_fetch, SafeFetchError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = config.DATA_DIR / "cache" / "nvd"
CACHE_TTL_SECONDS = 86400 * 3  # 72 hours cache


def _get_cache(key: str) -> Optional[List[Dict[str, Any]]]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{key}.json"
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if time.time() - data.get("cached_at", 0) > CACHE_TTL_SECONDS:
            cache_file.unlink(missing_ok=True)
            return None
        return data.get("records")
    except Exception:
        return None


def _set_cache(key: str, records: List[Dict[str, Any]]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{key}.json"
    try:
        cache_file.write_text(
            json.dumps({"cached_at": time.time(), "records": records}, indent=2),
            encoding="utf-8"
        )
    except Exception:
        pass


def _extract_cvss_score(metrics: Dict[str, Any]) -> Tuple[float, str]:
    """Extract CVSS v3.1 / v3.0 / v2 base score and severity string."""
    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        items = metrics.get(metric_key, [])
        if items:
            cvss_data = items[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = items[0].get("baseSeverity") or cvss_data.get("baseSeverity") or ""
            if score is not None:
                return float(score), str(severity).title()
    return 5.0, "Medium"


def query_nvd_by_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query NVD API 2.0 for a specific CVE identifier."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return None

    cache_key = f"cve_{cve_id}"
    cached = _get_cache(cache_key)
    if cached is not None and cached:
        return cached[0]

    headers = {"User-Agent": "AEGIS-AI-Security-Tool/1.0"}
    nist_key = getattr(config, "NIST_API_KEY", "") or os.getenv("NIST_API_KEY", "")
    if nist_key:
        headers["apiKey"] = nist_key

    url = f"{NVD_URL}?cveId={cve_id}"
    try:
        resp = safe_fetch(url, headers=headers, timeout=8.0)
        if resp.status_code == 200:
            payload = resp.json()
            vulns = payload.get("vulnerabilities", [])
            if vulns:
                cve_obj = vulns[0].get("cve", {})
                descriptions = cve_obj.get("descriptions", [])
                desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
                cvss_score, severity = _extract_cvss_score(cve_obj.get("metrics", {}))

                record = {
                    "cve_id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "source": "NVD API 2.0",
                    "references": [r.get("url") for r in cve_obj.get("references", [])[:5]]
                }
                _set_cache(cache_key, [record])
                return record
    except Exception:
        pass

    return None


def query_osv_package(package_name: str, ecosystem: str = "npm") -> List[Dict[str, Any]]:
    """Query Google OSV API for a component's known vulnerabilities."""
    cache_key = f"osv_{ecosystem}_{hashlib.sha256(package_name.lower().encode()).hexdigest()[:16]}"
    cached = _get_cache(cache_key)
    if cached is not None:
        return cached

    payload = {
        "package": {
            "name": package_name.lower(),
            "ecosystem": ecosystem
        }
    }

    results = []
    try:
        resp = safe_fetch(
            config.OSV_QUERY_API,
            method="POST",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=8.0
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("vulns", []):
                vuln_id = item.get("id", "UNKNOWN")
                summary = item.get("summary") or item.get("details", "")
                aliases = item.get("aliases", [])
                cve_aliases = [a for a in aliases if a.startswith("CVE-")]

                # Extract CVSS
                cvss_score = 5.0
                severity_str = "Medium"
                for sev in item.get("severity", []):
                    if "CVSS" in sev.get("type", ""):
                        score_str = sev.get("score", "")
                        # Try parsing vector or decimal
                        import re
                        m = re.search(r'([0-9]+\.[0-9]+)', score_str)
                        if m:
                            cvss_score = float(m.group(1))
                            if cvss_score >= 9.0:
                                severity_str = "Critical"
                            elif cvss_score >= 7.0:
                                severity_str = "High"
                            elif cvss_score >= 4.0:
                                severity_str = "Medium"
                            else:
                                severity_str = "Low"
                        break

                results.append({
                    "vuln_id": vuln_id,
                    "cve_aliases": cve_aliases,
                    "package": package_name,
                    "ecosystem": ecosystem,
                    "summary": summary[:300],
                    "cvss_score": cvss_score,
                    "severity": severity_str,
                    "source": "Google OSV API"
                })
        _set_cache(cache_key, results)
    except Exception:
        pass

    return results
