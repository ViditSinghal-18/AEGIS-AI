"""
Look up publicly known CVEs on the NVD (National Vulnerability Database).

Security terms explained for 3rd semester students:
- CVE (Common Vulnerabilities and Exposures): A standardized dictionary of known security flaws.
- CVSS (Common Vulnerability Scoring System): A 0.0 - 10.0 scale measuring flaw severity.
- CPE (Common Platform Enumeration): A structured naming scheme (e.g. cpe:2.3:a:apache:http_server:2.4.49)
  used to identify specific application software and hardware versions unambiguously.
- Confidence: CPE matches guarantee product+version match ("high" confidence).
  Keyword searches match text loosely and may produce false positives ("low" confidence).
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import requests

from config import DATA_DIR, NVD_API_KEY
from schemas import CveRecord

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "ai-attack-surface-tool/1.0 (academic EL project)"
CACHE_DIR = DATA_DIR / "cache" / "nvd"
CACHE_TTL_SECONDS = 60 * 60 * 72  # 72 hours — NVD updates ~daily


def _get_cache(cache_key: str) -> list[dict[str, Any]] | None:
    """Read cached NVD JSON from disk if present, valid, and not stale.

    Returns ``None`` for missing, corrupt, or expired cache entries so
    the caller always falls back to a fresh NVD query.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{cache_key}.json"
    if not cache_file.exists():
        return None
    try:
        wrapper = json.loads(cache_file.read_text(encoding="utf-8"))
        # Validate expected structure
        if not isinstance(wrapper, dict) or "cached_at" not in wrapper or "records" not in wrapper:
            cache_file.unlink(missing_ok=True)  # Delete corrupt entry
            return None
        age = time.time() - float(wrapper["cached_at"])
        if age > CACHE_TTL_SECONDS:
            cache_file.unlink(missing_ok=True)  # Delete stale entry
            return None
        records = wrapper["records"]
        if not isinstance(records, list):
            cache_file.unlink(missing_ok=True)
            return None
        return records
    except (json.JSONDecodeError, OSError, ValueError, KeyError):
        cache_file.unlink(missing_ok=True)  # Delete corrupt entry
        return None


def _set_cache(cache_key: str, data: list[dict[str, Any]]) -> None:
    """Write NVD results to disk cache with a creation timestamp."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{cache_key}.json"
    wrapper = {"cached_at": time.time(), "records": data}
    try:
        cache_file.write_text(json.dumps(wrapper, indent=2), encoding="utf-8")
    except OSError:
        pass


def _cvss_from_metrics(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        data = items[0]
        cvss = data.get("cvssData") or {}
        score = cvss.get("baseScore")
        severity = (data.get("baseSeverity") or cvss.get("baseSeverity") or "").title()
        if score is not None:
            return float(score), severity or _severity_from_score(float(score))
    return None, "Unknown"


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _parse_nvd_payload(payload: dict, source_query: str, confidence: str) -> list[CveRecord]:
    records: list[CveRecord] = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or ""
        descriptions = cve.get("descriptions") or []
        english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        score, severity = _cvss_from_metrics(cve.get("metrics") or {})
        records.append(
            CveRecord(
                cve_id=cve_id,
                description=(english or "")[:500],
                cvss_score=score,
                severity=severity,
                source_query=source_query,
                confidence=confidence,
            )
        )
    return records


def _query_nvd_api(params: dict[str, str], query_identifier: str, confidence: str) -> list[CveRecord]:
    # Check disk cache first
    cache_key = hashlib.sha256(query_identifier.encode("utf-8")).hexdigest()[:16]
    cached = _get_cache(cache_key)
    if cached is not None:
        return [
            CveRecord(
                cve_id=c["cve_id"],
                description=c["description"],
                cvss_score=c["cvss_score"],
                severity=c["severity"],
                source_query=c["source_query"],
                confidence=c.get("confidence", confidence),
                kev=c.get("kev", False),
                epss=c.get("epss"),
            )
            for c in cached
        ]

    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    def _fetch_once() -> dict:
        with requests.get(NVD_URL, headers=headers, params=params, timeout=30) as resp:
            resp.raise_for_status()
            return resp.json()

    try:
        try:
            payload = _fetch_once()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 429:
                time.sleep(8)
                payload = _fetch_once()
            else:
                raise
    except requests.RequestException:
        raise  # Let caller handle the network failure

    records = _parse_nvd_payload(payload, query_identifier, confidence)

    # Save to disk cache
    _set_cache(cache_key, [r.__dict__ for r in records])
    time.sleep(0.7 if NVD_API_KEY else 4.0)
    return records


def lookup_cves(product: str, version: str = "", cpe: str = "") -> list[CveRecord]:
    """
    Search NVD using CPE match first (high confidence), falling back to keyword search (low confidence).
    """
    product = (product or "").strip()
    version = (version or "").strip()
    cpe = (cpe or "").strip()

    if not product and not cpe:
        return []

    # 1. Prefer structured CPE match if CPE string or product+version is available
    if not cpe and product and version:
        # Construct standard CPE 2.3 format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        safe_prod = product.lower().replace(" ", "_")
        cpe = f"cpe:2.3:a:{safe_prod}:{safe_prod}:{version}:*:*:*:*:*:*:*"

    if cpe:
        try:
            results = _query_nvd_api({"cpeName": cpe, "resultsPerPage": "5"}, cpe, confidence="high")
            if results:
                return results
        except requests.RequestException:
            pass  # Fall through to keyword search on network/parsing error

    # 2. Fallback to keyword search (marked as low confidence)
    keyword = f"{product} {version}".strip()
    try:
        results = _query_nvd_api({"keywordSearch": keyword, "resultsPerPage": "5"}, keyword, confidence="low")
    except requests.RequestException:
        if version:
            try:
                results = _query_nvd_api({"keywordSearch": product, "resultsPerPage": "5"}, product, confidence="low")
            except requests.RequestException:
                return []
        else:
            return []
    return results


def query_nvd_by_cve(cve_id: str) -> dict[str, Any] | None:
    """Look up a single CVE from NVD API 2.0 or local disk cache."""
    cve_id = cve_id.strip().upper()
    cache_key = f"cve_{cve_id}"
    cached = _get_cache(cache_key)
    if cached:
        return cached[0] if isinstance(cached, list) and cached else cached
    try:
        results = _query_nvd_api({"cveId": cve_id}, cve_id, confidence="verified")
        if results:
            as_dict = results[0].__dict__ if hasattr(results[0], "__dict__") else results[0]
            _set_cache(cache_key, [as_dict])
            return as_dict
    except Exception:
        pass
    return None


def query_osv_package(name: str, version: str = "", ecosystem: str = "npm") -> list[dict[str, Any]]:
    """Query OSV API for vulnerabilities in open source components."""
    if not name:
        return []
    payload: dict[str, Any] = {"package": {"name": name}}
    if ecosystem and ecosystem != "generic":
        payload["package"]["ecosystem"] = ecosystem
    if version and version != "unknown":
        payload["version"] = version
    try:
        from discovery.safe_fetch import safe_fetch
        import requests
        res = safe_fetch("https://api.osv.dev/v1/query", timeout=5.0)
        if res.status_code == 200:
            return res.json().get("vulns", [])
    except Exception:
        pass
    return []

