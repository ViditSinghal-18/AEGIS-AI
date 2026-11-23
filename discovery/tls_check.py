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


def inspect_local_tls(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    """
    Perform direct local TLS handshake using Python's ssl module.
    Works on localhost, loopback, and lab containers without needing SSL Labs.
    IPv4 is preferred; falls back to IPv6. 8-second handshake timeout.
    Returns probe_error key on failure so callers can skip failed probes.
    """
    result: dict[str, Any] = {
        "reachable": False,
        "protocol": "unavailable",
        "issues": [],
        "subject": {},
        "issuer": "unavailable",
        "expires_on": "",
        "days_until_expiry": None,
    }

    ctx = ssl.create_default_context()
    # Allow self-signed / local certs for inspection purposes
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Resolve with IPv4 preference, fall back to IPv6
    resolved_ip: str | None = None
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
            if infos:
                resolved_ip = infos[0][4][0]
                break
        except (socket.gaierror, OSError):
            continue

    connect_target = resolved_ip if resolved_ip else host

    try:
        with socket.create_connection((connect_target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)  # Explicit 8-second SSL handshake timeout
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["reachable"] = True
                result["protocol"] = ssock.version() or "unknown"

                # Check for deprecated TLS version
                if result["protocol"] in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}:
                    result["issues"].append("tls-deprecated-version: Legacy deprecated TLS protocol in use")

                # Get binary certificate for parsing
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    # Attempt structured cert decode via cryptography if available
                    decoded_ok = False
                    try:
                        from cryptography import x509
                        cert_obj = x509.load_der_x509_certificate(der_cert)
                        exp_dt = cert_obj.not_valid_after_utc
                        result["days_until_expiry"] = (exp_dt - datetime.datetime.now(datetime.timezone.utc)).days
                        result["expires_on"] = exp_dt.isoformat()
                        result["issuer"] = cert_obj.issuer.rfc4514_string()
                        result["subject"] = cert_obj.subject.rfc4514_string()
                        decoded_ok = True
                    except Exception:
                        decoded_ok = False

                    if not decoded_ok:
                        # Fallback to standard getpeercert decode
                        try:
                            ctx2 = ssl.create_default_context()
                            ctx2.check_hostname = False
                            ctx2.verify_mode = ssl.CERT_NONE
                            with socket.create_connection((connect_target, port), timeout=timeout) as sock2:
                                with ctx2.wrap_socket(sock2, server_hostname=host) as ssock2:
                                    cert = ssock2.getpeercert(binary_form=False) or {}
                                    if cert:
                                        not_after_str = cert.get("notAfter")
                                        if not_after_str:
                                            exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                                            result["days_until_expiry"] = (exp_dt - datetime.datetime.utcnow()).days
                                            result["expires_on"] = not_after_str
                                        issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                                        subject_dict = dict(x[0] for x in cert.get("subject", ()))
                                        result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "unavailable")
                                        result["subject"] = subject_dict
                        except Exception:
                            pass
    except Exception as exc:
        # TLS unreachable — return structured probe_error so callers can skip scoring
        result["probe_error"] = "tls_unreachable"
        result["probe_error_detail"] = str(exc)
        result["days_until_expiry"] = None
        result["protocol"] = "unavailable"
        result["issuer"] = "unavailable"
        return result

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

