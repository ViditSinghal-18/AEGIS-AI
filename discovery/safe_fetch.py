"""
AEGIS-AI Safe HTTP Transport & SSRF Defense Module.

Protects against Server-Side Request Forgery (SSRF), DNS rebinding,
cloud metadata access (169.254.169.254), redirect hijacking, and oversized payloads.
All external network communications in AEGIS-AI must route through safe_fetch.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from urllib3.poolmanager import PoolManager

from config import (
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    SAFE_FETCH_TIMEOUT,
)

# Suppress insecure request warnings for controlled testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# In-memory domain rate limiter {domain: last_timestamp}
_DOMAIN_RATE_LIMITS: dict[str, float] = {}
MIN_DOMAIN_INTERVAL = 0.5  # Minimum seconds between requests to the same domain


class SafeFetchError(Exception):
    """Raised when an outbound HTTP request violates SSRF or security constraints."""
    pass


class PinnedIPAdapter(requests.adapters.HTTPAdapter):
    """
    HTTPAdapter that forces TCP socket connections to a pre-validated IP address
    while keeping the original hostname for SNI, TLS certificate validation, and Host headers.
    This guarantees immunity against DNS rebinding attacks.
    """

    def __init__(self, hostname: str, pinned_ip: str, *args: Any, **kwargs: Any) -> None:
        self.hostname = hostname
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )

    def get_connection(self, url: str, proxies: Any = None) -> Any:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        pool_kwargs: dict[str, Any] = {}
        if parsed.scheme == "https":
            pool_kwargs["server_hostname"] = self.hostname
            pool_kwargs["assert_hostname"] = self.hostname

        conn = self.poolmanager.connection_from_host(
            self.pinned_ip,
            port=port,
            scheme=parsed.scheme,
            pool_kwargs=pool_kwargs,
        )
        if parsed.scheme == "https":
            conn.assert_hostname = self.hostname
        return conn

    def get_connection_with_tls_context(
        self,
        request: Any,
        verify: Any,
        proxies: Any = None,
        cert: Any = None,
    ) -> Any:
        parsed = urlparse(getattr(request, "url", "") or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            _, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        except Exception:
            pool_kwargs = {}
        if parsed.scheme == "https":
            pool_kwargs["server_hostname"] = self.hostname
            pool_kwargs["assert_hostname"] = self.hostname
        conn = self.poolmanager.connection_from_host(
            self.pinned_ip,
            port=port,
            scheme=parsed.scheme or "https",
            pool_kwargs=pool_kwargs,
        )
        if parsed.scheme == "https":
            conn.assert_hostname = self.hostname
        return conn


def is_ip_allowed_for_public_fetch(ip_str: str) -> bool:
    """
    Validate that an IP is globally routable and NOT private, loopback,
    link-local, cloud metadata, or reserved.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    # Block non-public / internal IP ranges
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    # Explicitly block AWS, Azure, GCP and OpenStack metadata IPs
    if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
        return False

    return True


def resolve_and_validate_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname via DNS and verify that ALL returned IP addresses are public.
    Fails closed if any resolved IP belongs to an internal, private, or metadata range.
    """
    clean_host = hostname.strip().lower().strip("[]")
    if not clean_host:
        raise SafeFetchError("Hostname is empty.")

    # Check if host is already an IP literal
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_ip_allowed_for_public_fetch(clean_host):
            raise SafeFetchError(
                f"Blocked SSRF attempt: Target IP '{clean_host}' is a private, loopback, or reserved address."
            )
        return [clean_host]
    except ValueError:
        pass  # Domain name, resolve via system DNS

    try:
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SafeFetchError(f"DNS resolution failed for '{clean_host}': {exc}")

    resolved_ips: list[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_addr = sockaddr[0]
        if not is_ip_allowed_for_public_fetch(ip_addr):
            raise SafeFetchError(
                f"Blocked SSRF attempt: Hostname '{clean_host}' resolved to internal/private IP '{ip_addr}'."
            )
        if ip_addr not in resolved_ips:
            resolved_ips.append(ip_addr)

    if not resolved_ips:
        raise SafeFetchError(f"No IP addresses resolved for hostname '{clean_host}'.")

    return resolved_ips


def safe_fetch(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | str | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    timeout: float = SAFE_FETCH_TIMEOUT,
    allow_loopback_for_testing: bool = False,
) -> requests.Response:
    """
    Execute a hardened HTTP request with strict anti-SSRF protections,
    DNS rebinding defense, body size enforcement, and redirect hop validation.
    """
    current_url = url.strip()
    redirect_count = 0
    req_headers = headers.copy() if headers else {}
    if not any(k.lower() == "user-agent" for k in req_headers):
        req_headers["User-Agent"] = "AEGIS-AI-Defense/2.4 (Security Posture Auditor; Passive OSINT)"

    while True:
        parsed = urlparse(current_url)

        # 1. Protocol Scheme: HTTP and HTTPS only
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise SafeFetchError(f"Disallowed protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

        # 2. Port Validation: Only ports 80 and 443 permitted for public internet fetches
        port = parsed.port
        if port is not None:
            if not allow_loopback_for_testing and port not in {80, 443}:
                raise SafeFetchError(f"Disallowed target port: {port}. External fetches restricted to ports 80 and 443.")

        hostname = parsed.hostname
        if not hostname:
            raise SafeFetchError(f"Invalid URL: Missing hostname in '{current_url}'.")

        # 3. Reject credentials embedded in URL (user:pass@host)
        if parsed.username or parsed.password:
            raise SafeFetchError("URLs with embedded user credentials are prohibited.")

        # 4. Resolve and Pin IP
        is_loopback_host = hostname in {"localhost", "127.0.0.1", "::1"}
        if not (allow_loopback_for_testing and is_loopback_host):
            validated_ips = resolve_and_validate_hostname(hostname)
            pinned_ip = validated_ips[0]
        else:
            pinned_ip = "127.0.0.1"

        # 5. Domain Request Interval
        now = time.time()
        last_req = _DOMAIN_RATE_LIMITS.get(hostname, 0.0)
        if now - last_req < MIN_DOMAIN_INTERVAL:
            time.sleep(MIN_DOMAIN_INTERVAL - (now - last_req))
        _DOMAIN_RATE_LIMITS[hostname] = time.time()

        # 6. Dispatch Request with Pinned IP
        try:
            session = requests.Session()
            session.max_redirects = 0  # Re-validate every redirect manually
            adapter = PinnedIPAdapter(hostname=hostname, pinned_ip=pinned_ip)
            session.mount("https://", adapter)
            session.mount("http://", adapter)

            if not any(k.lower() == "host" for k in req_headers):
                req_headers["Host"] = hostname

            response = session.request(
                method=method,
                url=current_url,
                headers=req_headers,
                data=data,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
                verify=True if not (allow_loopback_for_testing and is_loopback_host) else False,
            )
        except requests.RequestException as exc:
            raise SafeFetchError(f"Network connection to '{current_url}' failed: {exc.__class__.__name__}: {exc}")

        # 7. Safe Redirect Processing
        if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
            redirect_count += 1
            if redirect_count > MAX_REDIRECTS:
                raise SafeFetchError(f"Exceeded maximum allowed redirects ({MAX_REDIRECTS}).")

            location = response.headers.get("Location")
            if not location:
                break

            current_url = urljoin(current_url, location)
            continue

        # 8. Body Size Limiting
        content = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content.extend(chunk)
            if len(content) > max_bytes:
                raise SafeFetchError(f"Response body exceeded maximum allowed size ({max_bytes} bytes).")

        response._content = bytes(content)
        return response
