import json
import sys
import socket
import urllib.parse
from datetime import datetime, timezone
import nmap
import requests

def scan_target(target="127.0.0.1", ports="80,443,3000,8080"):
    try:
        nm = nmap.PortScanner()
        # -sV probes open ports to determine service/version info
        nm.scan(target, ports, arguments="-sV")
        discovered_assets = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    discovered_assets.append({
                        "host": host,
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                    })
        return discovered_assets
    except Exception as e:
        print(f"[!] Warning: Nmap port scan unavailable ({e}). Falling back to socket probe.")
        discovered_assets = []
        target_ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        for p in target_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.8)
                    state = "open" if s.connect_ex((target, p)) == 0 else "closed"
                    discovered_assets.append({
                        "host": target,
                        "port": p,
                        "protocol": "tcp",
                        "state": state,
                        "service": "http" if p in [80, 3000, 8080] else "https",
                        "product": "",
                        "version": ""
                    })
            except Exception:
                pass
        return discovered_assets

def fingerprint_http(url="http://localhost:3000"):
    try:
        resp = requests.get(url, timeout=5)
        return {
            "url": url,
            "status_code": resp.status_code,
            "server_header": resp.headers.get("Server", "None"),
            "powered_by": resp.headers.get("X-Powered-By", "None"),
        }
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}

if __name__ == "__main__":
    target_arg = sys.argv[1].strip() if len(sys.argv) > 1 and sys.argv[1].strip() else "127.0.0.1"
    
    # Extract host and port
    if ":" in target_arg and not target_arg.startswith("http"):
        parts = target_arg.split(":")
        scan_host = parts[0]
        probe_port = parts[1]
    elif target_arg.startswith("http://") or target_arg.startswith("https://"):
        parsed = urllib.parse.urlparse(target_arg)
        scan_host = parsed.hostname or "127.0.0.1"
        probe_port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
    else:
        scan_host = target_arg
        probe_port = "3000"

    print(f"[*] Scanning target ports on {scan_host}...")
    assets = scan_target(target=scan_host)
    
    http_target = f"http://{scan_host}:{probe_port}"
    print(f"[*] Probing HTTP headers on {http_target}...")
    http_info = fingerprint_http(http_target)

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": f"{scan_host}:{probe_port}" if probe_port else scan_host,
        "discovered_assets": assets,
        "http_fingerprint": http_info,
    }

    output_path = "discovery_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Scan report generated successfully: {output_path}")
    print(json.dumps(report, indent=2))