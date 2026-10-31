"""
AEGIS-AI Discovery Package.
Provides safe network fetching, passive OSINT reconnaissance, and guarded active port scanning.
"""

from discovery.safe_fetch import (
    safe_fetch,
    SafeFetchError,
    resolve_and_validate_hostname,
    is_public_ip,
    is_safe_url
)
from discovery.passive import (
    run_passive_recon,
    probe_passive_dns,
    probe_passive_tls,
    probe_passive_http,
    query_certificate_transparency,
    detect_waf_and_cdn
)
from discovery.port_scan import run_active_scan, TOP_PORTS

__all__ = [
    "safe_fetch",
    "SafeFetchError",
    "resolve_and_validate_hostname",
    "is_public_ip",
    "is_safe_url",
    "run_passive_recon",
    "probe_passive_dns",
    "probe_passive_tls",
    "probe_passive_http",
    "query_certificate_transparency",
    "detect_waf_and_cdn",
    "run_active_scan",
    "TOP_PORTS"
]
