"""
AEGIS-AI: Active Port Scanner & Service Fingerprinting Engine.
STRICT SAFETY ENFORCEMENT:
- Strictly disabled in Vercel serverless environment (no raw sockets / nmap binary).
- Strictly requires target domain ownership verification or allowlist inclusion.
- Probes only top safe perimeter ports unless user is verified owner.
"""

from __future__ import annotations

import os
import socket
import time
from typing import Any, Dict, List, Optional

import config
from security import is_target_allowlisted, determine_scan_mode
from discovery.safe_fetch import resolve_and_validate_hostname

# Standard top 20 web and network service ports
TOP_PORTS = [
    21,   # FTP
    22,   # SSH
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    143,  # IMAP
    443,  # HTTPS
    465,  # SMTPS
    587,  # Submission
    993,  # IMAPS
    995,  # POP3S
    3000, # Node / Dev HTTP
    3306, # MySQL
    3389, # RDP
    5432, # PostgreSQL
    8000, # Dev HTTP
    8080, # Alt HTTP
    8443, # Alt HTTPS
    9000  # Microservice
]


def run_active_scan(
    target: str,
    ports: Optional[List[int]] = None,
    client_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Execute active port and service discovery with strict verification gating.
    Raises PermissionError if target is unauthorized or if running on Vercel.
    """
    # 1. Serverless guardrail: Vercel does not allow raw socket scanning or nmap binaries
    if config.IS_VERCEL:
        raise PermissionError(
            "Active port scanning is disabled in Vercel serverless environments. "
            "Please run AEGIS locally or via Docker for active vulnerability assessments."
        )

    # 2. Authorization check: Domain verification or allowlist
    mode, can_active, rationale = determine_scan_mode(target, requested_active=True)
    if not can_active:
        raise PermissionError(
            f"Active port scanning rejected for '{target}'. "
            f"Rationale: {rationale}. "
            "Please verify domain ownership via /api/verify/start or add to targets.allowlist."
        )

    # 3. Resolve and validate public IP
    validated_ips = resolve_and_validate_hostname(target)
    target_ip = validated_ips[0]

    scan_ports = ports or TOP_PORTS
    discovered_assets: List[Dict[str, Any]] = []
    start_time = time.time()

    # Try python-nmap if installed and nmap binary is on PATH
    nmap_used = False
    try:
        import nmap
        nm = nmap.PortScanner()
        ports_str = ",".join(str(p) for p in scan_ports)
        # Safe banner scan without aggressive exploitation (-sV, -Pn, -T3, --open)
        nm.scan(target_ip, ports_str, arguments="-sV -Pn -T3 --open")
        nmap_used = True

        if target_ip in nm.all_hosts():
            host_data = nm[target_ip]
            for proto in host_data.all_protocols():
                p_dict = host_data[proto]
                for p, p_info in p_dict.items():
                    discovered_assets.append({
                        "ip": target_ip,
                        "port": int(p),
                        "state": p_info.get("state", "open"),
                        "service": p_info.get("name", "unknown"),
                        "product": p_info.get("product", ""),
                        "version": p_info.get("version", ""),
                        "extrainfo": p_info.get("extrainfo", ""),
                        "cpe": p_info.get("cpe", "")
                    })
    except Exception:
        # Graceful fallback to pure Python socket connect scan
        nmap_used = False
        for port in scan_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.7)
            try:
                res = s.connect_ex((target_ip, port))
                if res == 0:
                    # Try reading a basic service banner
                    banner = ""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80, 443, 3000, 8000, 8080, 8443] else b"\r\n")
                        banner = s.recv(512).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass

                    service_guess = "http" if port in [80, 8080, 8000, 3000] else ("https" if port in [443, 8443] else "unknown")
                    discovered_assets.append({
                        "ip": target_ip,
                        "port": port,
                        "state": "open",
                        "service": service_guess,
                        "banner": banner[:100] if banner else ""
                    })
            except Exception:
                pass
            finally:
                s.close()

    duration = round(time.time() - start_time, 2)

    return {
        "target": target,
        "resolved_ip": target_ip,
        "mode": "VERIFIED ACTIVE",
        "scanner": "nmap" if nmap_used else "socket_connect",
        "scanned_ports_count": len(scan_ports),
        "open_ports_count": len(discovered_assets),
        "duration_seconds": duration,
        "discovered_assets": discovered_assets
    }
