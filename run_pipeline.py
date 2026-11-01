"""Run discovery → NVD correlation → Bedrock (or fallback) ranking."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.service import build_scan_request, run_scan
from config import DEFAULT_PORTS, DEFAULT_TARGET, is_target_allowed


def run_target(host: str, ports: list[int], force_passive: bool = False) -> None:
    """Execute the defensive pipeline in either Active or Passive mode."""
    request = build_scan_request(host, ports, force_passive=force_passive, requested_by="cli")
    can_active = is_target_allowed(request.target) and not request.force_passive
    result_mode = "ACTIVE (Port scanning & banner correlation)"
    passive_mode = "PASSIVE OSINT (Read-only headers, DNS, TLS, CT logs)"

    print(f"\n=======================================================")
    print(f"[*] Starting Security Pipeline for Target: {request.target}")
    print(f"[*] Operational Mode: {result_mode if can_active else passive_mode}")
    if request.force_passive:
        print("[*] Passive mode forced by request.")
    elif not can_active:
        print(f"[*] Note: Target '{request.target}' is not in targets.allowlist and not verified.")
        print(f"    Running in 100% passive mode. (To authorize active scans: python -m verification start {request.target})")
    print(f"=======================================================")

    result = run_scan(request)
    print(f"[1/3] Discovery complete via {result.scan_method} ({result.mode.upper()})")
    print("[2/3] Correlation complete with NVD, CISA KEV, and FIRST EPSS")
    print(f"[3/3] Prioritization complete: findings={result.finding_count} llm={result.used_llm}")
    for note in result.notes:
        if "fallback" in note.lower() or "not allowlisted" in note.lower() or "nmap" in note.lower():
            print(f"      [NOTE] {note}")
    print(f"[+] Results written to {result.output_dir}")
    print(f"[+] Archived historical run to {Path(result.history_path).name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-assisted attack-surface correlation (allowlisted active scans + public passive scans)."
    )
    parser.add_argument("--target", default=None, help="Single host or domain to check")
    parser.add_argument("--targets", default=None, help="Comma-separated list of hosts or domains")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated TCP ports (used for active scans only)",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Force passive OSINT mode even if target is allowlisted or verified",
    )
    args = parser.parse_args()
    
    # Resolve targets list
    target_str = args.targets or args.target or DEFAULT_TARGET
    raw_targets = [t.strip() for t in target_str.split(",") if t.strip()]
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    for host in raw_targets:
        run_target(host, ports, force_passive=args.passive_only)

    print("\n[+] Scan complete. Data written to data/ and data/history/")
    print("[+] Dashboard: py -m streamlit run dashboard/app.py (or: python -m streamlit run dashboard/app.py)")


if __name__ == "__main__":
    main()
