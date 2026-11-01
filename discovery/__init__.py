"""
AEGIS-AI Discovery Package.
Provides safe network fetching, passive OSINT reconnaissance, and guarded active port scanning.
"""
from __future__ import annotations

import datetime
import time
from typing import Any, Dict, List

from discovery.safe_fetch import (
    safe_fetch,
    SafeFetchError,
    PinnedIPAdapter,
    resolve_and_validate_hostname,
)
from discovery.passive import (
    discover_passive,
    _probe_passive_http as probe_passive_http,
    _inspect_passive_tls as probe_passive_tls,
    _query_dns_records as probe_passive_dns,
    _query_certificate_transparency as query_certificate_transparency,
    _query_shodan_intelligence,
)
from discovery.port_scan import scan_ports
from discovery.run import discover


def run_passive_recon(target: str) -> Dict[str, Any]:
    """Execute complete passive reconnaissance and return dictionary."""
    start_time = time.time()
    assets = discover_passive(target)
    duration = round(time.time() - start_time, 2)
    res = assets.to_dict()
    res["duration_seconds"] = duration
    return res


def run_active_scan(target: str, ports: list[int] | None = None) -> Dict[str, Any]:
    """Execute active scan on allowed target."""
    ports_found, method = scan_ports(target, ports)
    return {
        "target": target,
        "method": method,
        "ports": [p.to_dict() if hasattr(p, "to_dict") else p for p in ports_found]
    }


__all__ = [
    "discover",
    "discover_passive",
    "scan_ports",
    "run_active_scan",
    "run_passive_recon",
    "probe_passive_http",
    "probe_passive_tls",
    "probe_passive_dns",
    "query_certificate_transparency",
    "safe_fetch",
    "SafeFetchError",
    "PinnedIPAdapter",
    "resolve_and_validate_hostname",
]
