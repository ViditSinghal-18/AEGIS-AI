"""
Exposed Secret & Sensitive File Classifier.

Inspired by:
    Meli, M. R., McNiece, M. R., & Reaves, B. "How Bad Can It Git?
    Characterizing Secret Leakage in Public GitHub Repositories."
    In Network and Distributed System Security Symposium (NDSS), 2019.

NON-NEGOTIABLE AEGIS CONSTRAINT:
Never store, log, or echo raw secret values found during scans.
Store ONLY secret type, location, and a masked hint (e.g. 'AKIA****XYZ').
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from discovery.safe_fetch import safe_fetch, SafeFetchError


@dataclass
class ExposedSecretFinding:
    """Classified secret disclosure with masked hint."""

    secret_type: str
    location: str
    masked_hint: str
    severity: str  # "Critical", "High", "Medium"
    confidence: str  # "high", "medium"
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def mask_secret(secret_value: str) -> str:
    """Mask a secret string preserving only prefix and suffix hints.

    Examples:
        'AKIAIOSFODNN7EXAMPLE' -> 'AKIA****MPLE'
        'ghp_1234567890abcdef1234567890abcdef1234' -> 'ghp_****1234'
        'short' -> 'sh****rt'
    """
    s = (secret_value or "").strip()
    if len(s) <= 6:
        return "****"
    if len(s) <= 12:
        return f"{s[:2]}****{s[-2:]}"
    return f"{s[:4]}****{s[-4:]}"


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to distinguish random keys from dummy strings."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# High-precision patterns for credentials and access keys
SECRET_RULES: List[Dict[str, Any]] = [
    {
        "type": "AWS Access Key ID",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": "Critical",
        "min_entropy": 2.5,
        "remediation": "Rotate AWS IAM access key immediately in AWS IAM and inspect CloudTrail for unauthorized API calls.",
    },
    {
        "type": "AWS Secret Access Key",
        "pattern": re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})\b"),
        "severity": "Critical",
        "min_entropy": 4.0,
        "remediation": "Revoke the exposed AWS secret access key immediately.",
    },
    {
        "type": "GitHub Personal Access Token",
        "pattern": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,80})\b"),
        "severity": "Critical",
        "min_entropy": 3.0,
        "remediation": "Revoke this token under GitHub Settings > Developer Settings > Personal Access Tokens.",
    },
    {
        "type": "GitHub Fine-Grained Personal Access Token",
        "pattern": re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        "severity": "Critical",
        "min_entropy": 3.0,
        "remediation": "Revoke fine-grained PAT in GitHub security settings.",
    },
    {
        "type": "Slack Bot / User Token",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
        "severity": "High",
        "min_entropy": 3.0,
        "remediation": "Revoke Slack token in your Slack API App Management console.",
    },
    {
        "type": "Slack Incoming Webhook",
        "pattern": re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[A-Za-z0-9]{24})"),
        "severity": "High",
        "min_entropy": 3.0,
        "remediation": "Delete and regenerate this Slack incoming webhook URL.",
    },
    {
        "type": "RSA / OpenSSH Private Key Block",
        "pattern": re.compile(r"(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----)"),
        "severity": "Critical",
        "min_entropy": 0.0,
        "remediation": "Revoke the private key immediately, remove from authorized_keys, and generate a new keypair.",
    },
    {
        "type": "Google API / Firebase Key",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "severity": "High",
        "min_entropy": 3.0,
        "remediation": "Restrict or regenerate this API key in Google Cloud Console.",
    },
    {
        "type": "Stripe Live API Key",
        "pattern": re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,34})\b"),
        "severity": "Critical",
        "min_entropy": 3.0,
        "remediation": "Roll API keys immediately in the Stripe Dashboard > Developers > API keys.",
    },
]


def classify_secrets_in_text(text: str, location_source: str = "content") -> List[ExposedSecretFinding]:
    """Scan text buffer for credentials and return findings with masked hints."""
    findings: List[ExposedSecretFinding] = []
    if not text:
        return findings

    lines = text.splitlines()

    for rule in SECRET_RULES:
        for idx, line in enumerate(lines, 1):
            matches = rule["pattern"].findall(line)
            for m in matches:
                # If matched group is string
                secret_str = m if isinstance(m, str) else m[0]
                entropy = shannon_entropy(secret_str)

                if entropy < rule["min_entropy"]:
                    continue  # Ignore low-entropy placeholders like 'AKIAIOSFODNN7EXAMPLE'

                loc = f"{location_source}:line {idx}"
                masked = mask_secret(secret_str)

                # Special display for private key header
                if "BEGIN" in secret_str and "PRIVATE KEY" in secret_str:
                    masked = "[PRIVATE_KEY_BLOCK_DETECTED]"

                findings.append(
                    ExposedSecretFinding(
                        secret_type=rule["type"],
                        location=loc,
                        masked_hint=masked,
                        severity=rule["severity"],
                        confidence="high",
                        remediation=rule["remediation"],
                    )
                )

    return findings


def probe_exposed_files(base_url: str) -> List[ExposedSecretFinding]:
    """Single-GET safe inspection of common exposed configuration and VCS endpoints.

    Tests:
    - /.git/HEAD
    - /.env
    """
    clean_url = base_url.rstrip("/")
    findings: List[ExposedSecretFinding] = []

    # 1. Probe /.git/HEAD
    git_head_url = f"{clean_url}/.git/HEAD"
    try:
        resp = safe_fetch(git_head_url, timeout=3.5)
        if resp.status_code == 200 and resp.text:
            text = resp.text.strip()
            if text.startswith("ref: refs/heads/") or re.match(r"^[0-9a-f]{40}$", text):
                findings.append(
                    ExposedSecretFinding(
                        secret_type="Exposed Git Repository (/.git/HEAD)",
                        location=git_head_url,
                        masked_hint="ref: refs/heads/****",
                        severity="Critical",
                        confidence="high",
                        remediation="Deny public web server access to .git directories in Nginx/Apache configuration.",
                    )
                )
    except Exception:
        pass

    # 2. Probe /.env
    env_url = f"{clean_url}/.env"
    try:
        resp = safe_fetch(env_url, timeout=3.5)
        if resp.status_code == 200 and resp.text:
            env_text = resp.text
            # Look for common environment key definitions
            if any(k in env_text for k in ["DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY", "DATABASE_URL"]):
                classified = classify_secrets_in_text(env_text, location_source=env_url)
                if classified:
                    findings.extend(classified)
                else:
                    findings.append(
                        ExposedSecretFinding(
                            secret_type="Exposed Environment File (/.env)",
                            location=env_url,
                            masked_hint="ENV_VARIABLES_DISCLOSED",
                            severity="Critical",
                            confidence="high",
                            remediation="Block access to .env files and move sensitive secrets into a secret manager.",
                        )
                    )
    except Exception:
        pass

    return findings
