"""
Backport-Aware Vulnerability Matching for Linux Distributions.

Security problem:
    Enterprise Linux distributions (Debian, Ubuntu LTS, RHEL, CentOS, Rocky, Alpine)
    maintain stable package releases and backport security patches into older upstream
    version numbers without bumping the main upstream version string.
    
    For example:
        - 'nginx/1.18.0 (Ubuntu)' or 'nginx 1.18.0-0ubuntu1.4' on Ubuntu 20.04 LTS contains
          backported fixes for CVEs that affected upstream nginx 1.18.0.
        - An automated scanner that tests '1.18.0 < 1.20.0' asserts a critical vulnerability
          that is already patched, causing severe false positives and alert fatigue.

AEGIS-AI Principle:
    Transparent, evidence-grounded attribution. If a version or banner exhibits
    distribution-specific packaging conventions, mark findings 'possibly_backported'
    with lower confidence instead of falsely asserting an active vulnerability.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BackportVerdict:
    """Verdict detailing distribution packaging and backport likelihood."""

    is_backport_candidate: bool
    distro: Optional[str]
    upstream_version: str
    package_release: Optional[str]
    possibly_backported: bool
    banner_only: bool
    adjusted_confidence: str  # "high" | "medium" | "low"
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Regular expressions for identifying distribution-specific package versioning
# Ubuntu: 1.18.0-0ubuntu1.4, 2.4.41-4ubuntu3.14, 8.2p1-4ubuntu0.5
_UBUNTU_PKG_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)+)(?:[~+-].*?)?[-+]([0-9]+ubuntu[0-9]+(?:\.[0-9]+)*)$", re.IGNORECASE)

# Debian: 1.14.2-2+deb10u4, 2.4.38-3+deb10u7, 1.2.11.dfsg-1+deb9u1
_DEBIAN_PKG_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)+)(?:[~+-].*?)?[-+](?:[0-9]+)?\+deb([0-9]+u[0-9]+)$", re.IGNORECASE)

# RHEL / CentOS / Rocky / AlmaLinux: 2.4.37-43.module_el8.5.0, 1.20.1-1.el8_4, 1.14.1-9.el7
_RHEL_PKG_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)+)(?:[~+-].*?)?[-+]([0-9A-Za-z._+-]*?[._]el[0-9]+.*)$", re.IGNORECASE)

# Alpine: 1.20.2-r1, 2.4.53-r0
_ALPINE_PKG_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)+)-r([0-9]+)$", re.IGNORECASE)

# Amazon Linux: 2.4.54-1.amzn2
_AMZN_PKG_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)+)(?:[~+-].*?)?[-+]([0-9]+(?:\.[0-9]+)*\.amzn[0-9]+.*)$", re.IGNORECASE)

# Distro banners from HTTP Server headers or SSH banners
_BANNER_DISTRO_PATTERNS = [
    (re.compile(r"\bubuntu\b", re.IGNORECASE), "Ubuntu"),
    (re.compile(r"\bdebian\b", re.IGNORECASE), "Debian"),
    (re.compile(r"\b(?:red\s*hat|rhel|centos|rocky|almalinux)\b", re.IGNORECASE), "RHEL/CentOS"),
    (re.compile(r"\balpine(?:\s+linux)?\b", re.IGNORECASE), "Alpine"),
    (re.compile(r"\b(?:suse|opensuse)\b", re.IGNORECASE), "SUSE"),
    (re.compile(r"\bamazon(?:\s+linux)?\b", re.IGNORECASE), "Amazon Linux"),
]


def detect_backport(
    product: str = "",
    version_string: str = "",
    banner: str = "",
) -> BackportVerdict:
    """Analyze version strings and service banners for Linux distribution backport patterns.

    Args:
        product: Discovered software name (e.g. 'nginx', 'apache', 'openssh').
        version_string: Version extracted from probe or package manifest.
        banner: Raw service banner (e.g. 'Server: nginx/1.18.0 (Ubuntu)', 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5').

    Returns:
        BackportVerdict with backport candidate flag, distro name, and confidence adjustment.
    """
    version_clean = (version_string or "").strip()
    banner_clean = (banner or "").strip()

    # 1. Check exact package release string matches (high specificity)
    m_ubuntu = _UBUNTU_PKG_RE.match(version_clean)
    if m_ubuntu:
        upstream = m_ubuntu.group(1)
        pkg_rel = m_ubuntu.group(2)
        return BackportVerdict(
            is_backport_candidate=True,
            distro="Ubuntu",
            upstream_version=upstream,
            package_release=pkg_rel,
            possibly_backported=True,
            banner_only=False,
            adjusted_confidence="low",
            explanation=(
                f"Package '{product} {version_clean}' is a distribution package ({pkg_rel}) on Ubuntu. "
                f"Ubuntu LTS backports security patches into upstream {upstream} without bumping the upstream version. "
                "Vulnerability status cannot be reliably inferred without verifying the package changelog."
            ),
        )

    m_debian = _DEBIAN_PKG_RE.match(version_clean)
    if m_debian:
        upstream = m_debian.group(1)
        pkg_rel = m_debian.group(2)
        return BackportVerdict(
            is_backport_candidate=True,
            distro="Debian",
            upstream_version=upstream,
            package_release=pkg_rel,
            possibly_backported=True,
            banner_only=False,
            adjusted_confidence="low",
            explanation=(
                f"Package '{product} {version_clean}' is a Debian security build (deb{pkg_rel}). "
                f"Debian security teams backport upstream CVE fixes to {upstream}. "
                "Direct upstream version comparison causes false positives."
            ),
        )

    m_rhel = _RHEL_PKG_RE.match(version_clean)
    if m_rhel:
        upstream = m_rhel.group(1)
        pkg_rel = m_rhel.group(2)
        return BackportVerdict(
            is_backport_candidate=True,
            distro="RHEL/CentOS",
            upstream_version=upstream,
            package_release=pkg_rel,
            possibly_backported=True,
            banner_only=False,
            adjusted_confidence="low",
            explanation=(
                f"Package '{product} {version_clean}' is an Enterprise Linux build ({pkg_rel}). "
                f"Red Hat backports CVE remediations into {upstream}. "
                "Assess vulnerability using Red Hat Security Advisories (RHSA) rather than upstream CPEs."
            ),
        )

    m_alpine = _ALPINE_PKG_RE.match(version_clean)
    if m_alpine:
        upstream = m_alpine.group(1)
        pkg_rel = f"r{m_alpine.group(2)}"
        return BackportVerdict(
            is_backport_candidate=True,
            distro="Alpine",
            upstream_version=upstream,
            package_release=pkg_rel,
            possibly_backported=True,
            banner_only=False,
            adjusted_confidence="low",
            explanation=(
                f"Package '{product} {version_clean}' uses Alpine package release ({pkg_rel}). "
                "Alpine security patches are frequently backported to existing stable revisions."
            ),
        )

    m_amzn = _AMZN_PKG_RE.match(version_clean)
    if m_amzn:
        upstream = m_amzn.group(1)
        pkg_rel = m_amzn.group(2)
        return BackportVerdict(
            is_backport_candidate=True,
            distro="Amazon Linux",
            upstream_version=upstream,
            package_release=pkg_rel,
            possibly_backported=True,
            banner_only=False,
            adjusted_confidence="low",
            explanation=(
                f"Package '{product} {version_clean}' is an Amazon Linux build ({pkg_rel}). "
                "Patches are backported via ALAS advisories without upstream version increment."
            ),
        )

    # 2. Check banner text for distribution identifiers (banner-derived detection)
    target_text = f"{version_clean} {banner_clean}"
    for pattern, distro_name in _BANNER_DISTRO_PATTERNS:
        if pattern.search(target_text):
            # Extract basic upstream numbers if present
            v_match = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", version_clean or banner_clean)
            upstream = v_match.group(1) if v_match else version_clean
            return BackportVerdict(
                is_backport_candidate=True,
                distro=distro_name,
                upstream_version=upstream,
                package_release=None,
                possibly_backported=True,
                banner_only=True,
                adjusted_confidence="low",
                explanation=(
                    f"Banner discloses {distro_name} distribution ('{banner_clean or version_clean}'). "
                    f"{distro_name} regularly backports security fixes into upstream base versions ({upstream}). "
                    "This finding is marked 'possibly_backported' with reduced confidence to prevent false positive triage."
                ),
            )

    # 3. Not a backported distro build — standard upstream or unknown
    return BackportVerdict(
        is_backport_candidate=False,
        distro=None,
        upstream_version=version_clean,
        package_release=None,
        possibly_backported=False,
        banner_only=False,
        adjusted_confidence="high",
        explanation="Standard upstream version string; no distribution backport packaging patterns detected.",
    )


def apply_backport_checks_to_findings(
    findings: List[Dict[str, Any]],
    banner_context: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Enrich findings with backport detection and adjust confidence where appropriate."""
    banners = banner_context or {}

    for f in findings:
        product = str(f.get("affected_component") or f.get("product") or "")
        version = str(f.get("version") or f.get("affected_version") or "")
        banner = banners.get(product, "") or str(f.get("banner") or "")

        verdict = detect_backport(product=product, version_string=version, banner=banner)

        if verdict.possibly_backported:
            f["possibly_backported"] = True
            f["backport_verdict"] = verdict.to_dict()
            f["confidence"] = verdict.adjusted_confidence
            f["confidence_reason"] = verdict.explanation
            # Tag in notes or exploitability explanation for transparency
            if "exploitability" in f:
                f["exploitability"] = f"{f['exploitability']} (Note: Possibly backported by {verdict.distro})"
        else:
            f["possibly_backported"] = False
            f["backport_verdict"] = verdict.to_dict()

    return findings
