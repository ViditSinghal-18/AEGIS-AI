"""Combine port scan, HTTP probe, and TLS check into discovered_assets.json."""

from __future__ import annotations

from config import DEFAULT_PORTS, require_allowed_target
from discovery.http_probe import probe_http
from discovery.port_scan import scan_ports
from discovery.tls_check import check_tls
from schemas import DiscoveredAssets, HttpCheck
from storage import write_json


def discover(target: str, ports: list[int] | None = None) -> DiscoveredAssets:
    host = require_allowed_target(target)
    port_list = ports or list(DEFAULT_PORTS)
    open_ports, method = scan_ports(host, port_list)
    notes = [f"Scan method: {method}"]
    if "fallback" in method:
        notes.append("Nmap binary not found in PATH; used TCP connect fallback scan. CVE matching is limited because version banners could not be extracted.")

    http: HttpCheck | None = None
    http_ports = [p.port for p in open_ports if p.port in {80, 3000, 8000, 8080, 443}]
    if not http_ports and 3000 in port_list:
        http_ports = [3000]
    for port in http_ports:
        use_tls = port == 443
        probe = probe_http(host, port=port, use_tls=use_tls)
        if probe.reachable:
            http = probe
            break
    if http is None and http_ports:
        http = probe_http(host, port=http_ports[0], use_tls=http_ports[0] == 443)

    tls = check_tls(host)
    assets = DiscoveredAssets(
        target=host,
        scan_method=method,
        ports=open_ports,
        http=http,
        tls=tls,
        notes=notes,
    )
    write_json("discovered_assets.json", assets, target=host)
    return assets
