"""
Stable JSON contracts between pipeline stages.

Each later stage reads the previous stage's file; keep field names stable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra: str = ""


@dataclass
class HttpCheck:
    """Passive HTTP observations (headers / TLS presence / cookie flags). Not an exploit."""

    url: str
    reachable: bool
    status_code: int | None = None
    title: str = ""
    uses_tls: bool = False
    missing_security_headers: list[str] = field(default_factory=list)
    cookie_issues: list[str] = field(default_factory=list)
    cors_issues: list[str] = field(default_factory=list)
    version_disclosure_issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class TlsGrade:
    """SSL Labs grade (A+ to F) for public HTTPS. Skipped for localhost."""

    skipped: bool
    reason: str = ""
    host: str = ""
    grade: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveredAssets:
    target: str
    scan_method: str
    ports: list[OpenPort]
    http: HttpCheck | None
    tls: TlsGrade
    mode: str = "active"  # "active" or "passive"
    passive_meta: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CveRecord:
    """One public CVE from NVD, plus its CVSS score when present.
    
    Terms:
      - CVE: Common Vulnerabilities and Exposures (unique public vulnerability ID)
      - CVSS: Common Vulnerability Scoring System (0.0 to 10.0 severity score)
      - KEV: CISA Known Exploited Vulnerabilities catalog (actively exploited in the wild)
      - EPSS: Exploit Prediction Scoring System (probability 0.0 to 1.0 of exploitation in next 30 days)
      - Confidence: "high" if matched via exact CPE banner; "low" if matched via loose keyword search
    """

    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    source_query: str
    confidence: str = "high"
    kev: bool = False
    epss: float | None = None


@dataclass
class CorrelatedAsset:
    target: str
    port: int | None
    service: str
    product: str
    version: str
    exposure: str
    cves: list[CveRecord]
    config_issues: list[str]


@dataclass
class CorrelatedFindings:
    target: str
    assets: list[CorrelatedAsset]
    mode: str = "active"  # "active" or "passive"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PrioritizedFinding:
    rank: int
    title: str
    severity: str
    exploitability: str
    why_it_matters: str
    suggested_action: str
    related_cves: list[str]
    source: str


@dataclass
class PrioritizedReport:
    target: str
    summary: str
    top_risks: list[str]
    findings: list[PrioritizedFinding]
    model_id: str
    used_llm: bool
    mode: str = "active"  # "active" or "passive"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
