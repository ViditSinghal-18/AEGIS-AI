"""
SSRF and abuse protection helper for fetching public web content safely.

Security terms explained for 3rd semester students:
- SSRF (Server-Side Request Forgery): A vulnerability where a server is tricked into
  accessing internal or private network resources on behalf of an unauthorized user.
- Cloud Metadata Service (169.254.169.254): A special link-local IP in AWS/GCP/Azure
  that exposes sensitive IAM credentials and instance metadata.
- DNS Rebinding: An attack where a domain's DNS response rapidly changes from a public IP
  to an internal IP (like 127.0.0.1) between validation and connection.
- SNI (Server Name Indication): A TLS extension indicating which hostname the client
  is connecting to at the start of the TLS handshake.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from urllib.parse import urlparse, urljoin
from typing import Any

import requests
import urllib3
from urllib3.poolmanager import PoolManager

# Suppress insecure request warnings on loopback only
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MB maximum response body
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 6.0  # seconds

# Global rate limiting tracking: {domain_or_ip: last_request_timestamp}
_DOMAIN_RATE_LIMITS: dict[str, float] = {}
MIN_DOMAIN_INTERVAL = 1.0  # At least 1 second between requests to the same domain


class SafeFetchError(Exception):
    """Raised when an outbound request violates SSRF or security constraints."""
    pass


class PinnedIPAdapter(requests.adapters.HTTPAdapter):
    """
    Custom HTTP transport adapter that routes TCP connections to a validated IP
    while preserving the original hostname for SNI, TLS certificate validation, and Host header.
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
        """
        requests 2.32+ uses this hook instead of get_connection.
        Keep the TCP peer pinned to the pre-validated IP while TLS still
        verifies the original hostname.
        """
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
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Disallow all non-public / internal IP ranges
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    # Explicit check for Cloud Metadata addresses (AWS/Azure/GCP: 169.254.169.254)
    if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
        return False

    return True


def resolve_and_validate_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname via DNS and ensure ALL returned IP addresses are public.
    Fails closed if any resolved IP is private or reserved.
    """
    clean_host = hostname.strip().lower().strip("[]")
    if not clean_host:
        raise SafeFetchError("Hostname is empty.")

    # Check if host is already a direct IP literal
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_ip_allowed_for_public_fetch(clean_host):
            raise SafeFetchError(
                f"Blocked SSRF attempt: IP literal '{clean_host}' is a private, loopback, or reserved address."
            )
        return [clean_host]
    except ValueError:
        pass  # It is a domain name, resolve via DNS

    # DNS Resolution
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
        raise SafeFetchError(f"No IP addresses found for hostname '{clean_host}'.")

    return resolved_ips


def safe_fetch(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | str | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    allow_loopback_for_testing: bool = False,
) -> requests.Response:
    """
    Execute a secure HTTP request protected against SSRF, DNS rebinding,
    oversized payloads, and redirect abuse with strict IP connection pinning.
    """
    current_url = url.strip()
    redirect_count = 0
    req_headers = headers.copy() if headers else {}
    if "User-Agent" not in req_headers:
        req_headers["User-Agent"] = "AI-Attack-Surface-Tool/2.0 (Defensive Security Scanner; Academic Project)"

    while True:
        parsed = urlparse(current_url)

        # 1. Protocol validation: Only http and https
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise SafeFetchError(f"Disallowed protocol scheme: '{scheme}'. Only HTTP and HTTPS are permitted.")

        # Embedded credentials check
        if parsed.username or parsed.password:
            raise SafeFetchError("URL contains embedded credentials which is forbidden.")

        # 2. Port validation: Only standard web ports
        port = parsed.port
        if port is not None and port not in {80, 443, 8080, 8443}:
            raise SafeFetchError(f"Disallowed target port: {port}. Only standard web ports (80, 443, 8080, 8443) allowed.")

        hostname = parsed.hostname
        if not hostname:
            raise SafeFetchError(f"Invalid URL: Missing hostname in '{current_url}'.")

        # 3. Domain & IP validation + Pinning
        is_loopback_host = hostname in {"localhost", "127.0.0.1", "::1"}
        if not (allow_loopback_for_testing and is_loopback_host):
            validated_ips = resolve_and_validate_hostname(hostname)
            pinned_ip = validated_ips[0]
        else:
            pinned_ip = "127.0.0.1"

        # 4. Rate Limiting per domain
        now = time.time()
        last_req = _DOMAIN_RATE_LIMITS.get(hostname, 0.0)
        if now - last_req < MIN_DOMAIN_INTERVAL:
            time.sleep(MIN_DOMAIN_INTERVAL - (now - last_req))
        _DOMAIN_RATE_LIMITS[hostname] = time.time()

        # 5. Execute request pinned to validated IP
        try:
            session = requests.Session()
            session.max_redirects = 0  # Disable automatic redirects to re-validate on each hop
            adapter = PinnedIPAdapter(hostname=hostname, pinned_ip=pinned_ip)
            session.mount("https://", adapter)
            session.mount("http://", adapter)

            if not any(key.lower() == "host" for key in req_headers):
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
            raise SafeFetchError(f"Network request to '{current_url}' failed: {exc.__class__.__name__}: {exc}")

        # 6. Check for redirects and manually validate next hop
        if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
            redirect_count += 1
            if redirect_count > MAX_REDIRECTS:
                raise SafeFetchError(f"Exceeded maximum allowed redirects ({MAX_REDIRECTS}).")

            location = response.headers.get("Location")
            if not location:
                break  # No location header; return current response

            current_url = urljoin(current_url, location)
            continue

        # 7. Cap response body size to prevent memory exhaustion / zip bombs
        content = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content.extend(chunk)
            if len(content) > max_bytes:
                raise SafeFetchError(f"Response body exceeded maximum allowed size ({max_bytes} bytes).")

        # Populate response with capped content
        response._content = bytes(content)
        return response

