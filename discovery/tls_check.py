"""
TLS / certificate grading via SSL Labs API and direct local Python SSL socket inspection.

Security terms explained for 3rd semester students:
- TLS (Transport Layer Security): Cryptographic protocol providing privacy and data integrity over the network (HTTPS).
- Certificate Expiry: X.509 certificates have a validity window (notBefore to notAfter); expired certs break trust.
- Self-Signed Certificate: A cert signed by its own creator rather than a trusted Certificate Authority (CA).
- Deprecated TLS: TLS 1.0 and 1.1 are cryptographically broken; modern standards require TLS 1.2 or TLS 1.3.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import time
from typing import Any

import requests

from config import is_loopback, require_allowed_target
from schemas import TlsGrade

SSL_LABS_ANALYZE = "https://api.ssllabs.com/api/v3/analyze"


def inspect_local_tls(host: str, port: int = 443, timeout: float = 3.0) -> dict[str, Any]:
    """
    Perform direct local TLS handshake using Python's ssl module.
    Works on localhost, loopback, and lab containers without needing SSL Labs.
    """
    result: dict[str, Any] = {
        "reachable": False,
        "protocol": "",
        "issues": [],
        "subject": {},
        "issuer": {},
        "expires_on": "",
        "days_until_expiry": None,
    }

    ctx = ssl.create_default_context()
    # Allow self-signed / local certs for inspection purposes
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["reachable"] = True
                result["protocol"] = ssock.version() or ""
                
                # Check for deprecated TLS version
                if result["protocol"] in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}:
                    result["issues"].append("tls-deprecated-version: Legacy deprecated TLS protocol in use")

                # Get binary certificate for parsing
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    # Parse peer cert in decoded form
                    # Reconnect with unverified getpeercert to extract fields
                    pass
    except Exception:
        # Port is not running TLS or unreachable
        return result

    # Try to extract cert metadata if possible
    try:
        cert_dict = ssl.get_server_certificate((host, port))
        loaded_cert = ssl.PEM_cert_to_DER_cert(cert_dict)
    except Exception:
        pass

    return result


def check_tls(target: str, tls_port: int = 443) -> TlsGrade:
    host = require_allowed_target(target)
    
    # Check local TLS status first
    local_info = inspect_local_tls(host, port=tls_port)

    if is_loopback(host):
        reason = "SSL Labs only grades public hostnames, not localhost/Docker."
        if local_info["reachable"]:
            reason += f" Local TLS probe succeeded (protocol: {local_info['protocol']})."
        return TlsGrade(
            skipped=True,
            reason=reason,
            host=host,
            raw=local_info,
        )

    params = {"host": host, "fromCache": "on", "maxAge": 24, "all": "done"}
    try:
        response = requests.get(SSL_LABS_ANALYZE, params=params, timeout=20)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        return TlsGrade(
            skipped=True,
            reason=f"SSL Labs request failed: {exc.__class__.__name__}",
            host=host,
            raw=local_info,
        )

    status = payload.get("status", "")
    if status in {"DNS", "IN_PROGRESS"}:
        time.sleep(5)
        return TlsGrade(
            skipped=True,
            reason="SSL Labs assessment not cached yet; skipped to keep the lab run fast.",
            host=host,
            raw={"status": status, "local": local_info},
        )

    endpoints = payload.get("endpoints") or []
    grade = ""
    if endpoints:
        grade = str(endpoints[0].get("grade") or endpoints[0].get("gradeTrustIgnored") or "")
    return TlsGrade(skipped=False, host=host, grade=grade, raw={"status": status, "local": local_info})

