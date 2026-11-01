"""
Port and service discovery for an allowlisted host.

Uses Nmap (-sV) when installed. -sV reads service banners (the text a port
sends when you connect) so we can later look up CVEs for that product/version.

If Nmap is missing (common on Windows until you install it), we fall back to
a short TCP connect on the configured ports — we learn "open vs closed" only.
"""

from __future__ import annotations

import socket
from typing import Iterable

from config import DEFAULT_PORTS, require_allowed_target, is_target_allowed
from schemas import OpenPort


def _tcp_probe(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _scan_with_nmap(host: str, ports: list[int]) -> tuple[list[OpenPort], str]:
    import nmap  # type: ignore

    scanner = nmap.PortScanner()
    port_list = ",".join(str(p) for p in ports)
    # -sV: version/banner detection. -Pn: skip host discovery (localhost is up).
    scanner.scan(hosts=host, arguments=f"-sV -Pn -p {port_list}")
    found: list[OpenPort] = []
    for scanned_host in scanner.all_hosts():
        for proto in scanner[scanned_host].all_protocols():
            for port, meta in scanner[scanned_host][proto].items():
                if meta.get("state") != "open":
                    continue
                found.append(
                    OpenPort(
                        port=int(port),
                        protocol=str(proto),
                        state="open",
                        service=meta.get("name") or "",
                        product=meta.get("product") or "",
                        version=meta.get("version") or "",
                        extra=meta.get("extrainfo") or "",
                    )
                )
    return found, "nmap-sv"


def _scan_with_sockets(host: str, ports: list[int]) -> tuple[list[OpenPort], str]:
    found: list[OpenPort] = []
    for port in ports:
        if _tcp_probe(host, port):
            found.append(
                OpenPort(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service="unknown",
                    product="",
                    version="",
                    extra="tcp-connect-fallback (install Nmap for banners)",
                )
            )
    return found, "tcp-connect-fallback"


def scan_ports(target: str, ports: Iterable[int] | None = None) -> tuple[list[OpenPort], str]:
    host = require_allowed_target(target)
    port_list = list(ports) if ports is not None else list(DEFAULT_PORTS)
    try:
        return _scan_with_nmap(host, port_list)
    except Exception as exc:  # nmap binary missing, python-nmap error, etc.
        ports_found, method = _scan_with_sockets(host, port_list)
        return ports_found, f"{method}; nmap unavailable ({exc.__class__.__name__})"


def run_active_scan(target: str, ports: Iterable[int] | None = None) -> tuple[list[OpenPort], str]:
    """Execute active scan with Vercel serverless protection and allowlist gate."""
    import config
    if getattr(config, "IS_VERCEL", False):
        raise PermissionError("Active port scanning is disabled on Vercel serverless environments.")
    if not is_target_allowed(target):
        raise PermissionError("Scan rejected: target is unauthorized. Verify domain ownership or add to targets.allowlist.")
    return scan_ports(target, ports)

