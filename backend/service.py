"""Backend orchestration service for defensive scan requests.

This module is intentionally UI-agnostic. The CLI, Streamlit dashboard, and any
future API layer should call this service instead of reaching into discovery,
correlation, prioritization, and storage modules directly.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai.prioritize import prioritize
from config import DEFAULT_PORTS, is_target_allowed
from correlation.correlate import correlate
from discovery.passive import discover_passive
from discovery.run import discover
from storage import save_run_history, target_data_dir, write_json

_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$", re.IGNORECASE)
_MAX_PORTS_PER_SCAN = 32


@dataclass(frozen=True)
class ScanRequest:
    """Validated scan input accepted by the backend."""

    target: str
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    force_passive: bool = False
    requested_by: str = "dashboard"


@dataclass(frozen=True)
class ScanResult:
    """Structured scan outcome for UI, CLI, and future APIs."""

    target: str
    mode: str
    scan_method: str
    report_path: str
    history_path: str
    output_dir: str
    finding_count: int
    used_llm: bool
    notes: list[str]
    started_at: str
    completed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clean_target(raw_target: str) -> str:
    target = (raw_target or "").strip().lower().rstrip(".")
    if not target:
        raise ValueError("Target is required.")
    if "://" in target or "/" in target:
        from config import _normalize_host

        target = _normalize_host(target)
    if target in {"localhost", "127.0.0.1", "::1"}:
        return target
    if len(target) > 253:
        raise ValueError("Target hostname is too long.")
    if not _HOST_RE.match(target):
        raise ValueError("Target must be a hostname, IPv4 address, IPv6 loopback, or localhost.")
    return target


def parse_ports(raw_ports: str | list[int] | tuple[int, ...] | None) -> list[int]:
    """Parse and validate an active-scan port list.

    The backend caps the count to prevent accidental broad scans from the web UI.
    Active scanning is still separately restricted by allowlist/verification.
    """
    if raw_ports is None:
        ports = list(DEFAULT_PORTS)
    elif isinstance(raw_ports, str):
        ports = []
        for part in raw_ports.split(","):
            item = part.strip()
            if not item:
                continue
            if not item.isdigit():
                raise ValueError(f"Invalid port '{item}'. Ports must be numbers.")
            ports.append(int(item))
    else:
        ports = [int(p) for p in raw_ports]

    deduped = sorted(set(ports))
    if not deduped:
        raise ValueError("At least one port is required for active scans.")
    if len(deduped) > _MAX_PORTS_PER_SCAN:
        raise ValueError(f"Too many ports requested. Maximum is {_MAX_PORTS_PER_SCAN}.")
    invalid = [p for p in deduped if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"Invalid TCP port(s): {', '.join(str(p) for p in invalid)}.")
    return deduped


def build_scan_request(
    target: str,
    ports: str | list[int] | tuple[int, ...] | None = None,
    force_passive: bool = False,
    requested_by: str = "dashboard",
) -> ScanRequest:
    return ScanRequest(
        target=_clean_target(target),
        ports=parse_ports(ports),
        force_passive=bool(force_passive),
        requested_by=(requested_by or "dashboard").strip()[:64],
    )


def run_scan(request: ScanRequest) -> ScanResult:
    """Run discovery, correlation, prioritization, and persistence."""
    started_at = datetime.now(timezone.utc).isoformat()
    can_active = is_target_allowed(request.target) and not request.force_passive
    mode = "active" if can_active else "passive"

    if can_active:
        assets = discover(request.target, request.ports)
    else:
        assets = discover_passive(request.target)

    correlated = correlate(assets.to_dict())
    report = prioritize(correlated.to_dict())

    report_path = write_json("prioritized_report.json", report, target=request.target)
    write_json("discovered_assets.json", assets, target=request.target)
    write_json("correlated_findings.json", correlated, target=request.target)
    history_path = save_run_history(request.target, report.to_dict())
    output_dir = target_data_dir(request.target)

    notes = list(getattr(assets, "notes", []) or [])
    notes.extend(getattr(correlated, "notes", []) or [])
    notes.extend(getattr(report, "notes", []) or [])
    if mode == "passive" and not request.force_passive:
        notes.append("Target was not allowlisted or currently verified; backend selected passive OSINT mode.")

    completed_at = datetime.now(timezone.utc).isoformat()
    return ScanResult(
        target=request.target,
        mode=mode,
        scan_method=getattr(assets, "scan_method", mode),
        report_path=str(Path(report_path)),
        history_path=str(Path(history_path)),
        output_dir=str(Path(output_dir)),
        finding_count=len(getattr(report, "findings", []) or []),
        used_llm=bool(getattr(report, "used_llm", False)),
        notes=list(dict.fromkeys(notes)),
        started_at=started_at,
        completed_at=completed_at,
    )
