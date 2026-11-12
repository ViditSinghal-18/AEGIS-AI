"""
AEGIS-AI Cryptographic Domain Ownership Verification Module.

Enforces authorized testing boundaries. Users must prove administrative control over
a target domain via DNS TXT record (_aegis-verify.<domain>) or HTTP token challenge
(/.well-known/aegis-verify.txt) before active port scans are permitted.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

from config import DATA_DIR, VERIFICATION_TTL_SECONDS, normalize_host
from discovery.safe_fetch import safe_fetch, SafeFetchError

VERIFIED_TARGETS_FILE = DATA_DIR / "verified_targets.json"


def _load_verified_data() -> dict[str, dict[str, Any]]:
    """Load the verified targets store."""
    if not VERIFIED_TARGETS_FILE.exists():
        return {}
    try:
        return json.loads(VERIFIED_TARGETS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_verified_data(data: dict[str, dict[str, Any]]) -> None:
    """Save the verified targets store safely."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        VERIFIED_TARGETS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def is_domain_verified(domain: str) -> bool:
    """
    Check if a domain is currently verified and within its 30-day validity window.
    Fails closed if expired, unverified, or not found.
    """
    clean_domain = normalize_host(domain)
    if not clean_domain:
        return False

    data = _load_verified_data()
    record = data.get(clean_domain)
    if not record or not record.get("verified"):
        return False

    expires_at = record.get("expires_at", 0)
    if time.time() > expires_at:
        return False  # Expired after 30 days

    return True


def start_verification(domain: str) -> dict[str, str]:
    """
    Generate a cryptographic challenge token and return instructions
    for DNS TXT and HTTP .well-known verification.
    """
    clean_domain = normalize_host(domain)
    if not clean_domain:
        raise ValueError("Invalid target domain for verification.")

    data = _load_verified_data()
    existing = data.get(clean_domain, {})
    
    # Reuse valid token if one was created recently, or generate fresh
    token = existing.get("token") or secrets.token_urlsafe(24)

    record = {
        "domain": clean_domain,
        "token": token,
        "verified": False,
        "method": None,
        "created_at": time.time(),
        "verified_at": None,
        "expires_at": None,
    }
    data[clean_domain] = record
    _save_verified_data(data)

    txt_record_name = f"_aegis-verify.{clean_domain}"
    well_known_url = f"https://{clean_domain}/.well-known/aegis-verify.txt"

    return {
        "domain": clean_domain,
        "token": token,
        "dns_record": txt_record_name,
        "dns_value": token,
        "file_url": well_known_url,
        "file_content": token,
        "instructions": (
            f"Add a DNS TXT record named '{txt_record_name}' with value '{token}', OR "
            f"host a file at '{well_known_url}' containing the token."
        )
    }


def _check_dns_txt_record(domain: str, expected_token: str) -> bool:
    """
    Check DNS TXT record using Cloudflare DoH (works on serverless / Vercel),
    with fallback to local nslookup. Checks both _aegis-verify and legacy _attacksurface-verify prefixes.
    """
    candidate_hosts = [f"_aegis-verify.{domain}", f"_attacksurface-verify.{domain}"]

    for txt_host in candidate_hosts:
        # 1. Cloudflare DNS-over-HTTPS check (OS-independent and serverless safe)
        try:
            doh_url = f"https://cloudflare-dns.com/dns-query?name={txt_host}&type=TXT"
            resp = safe_fetch(doh_url, headers={"Accept": "application/dns-json"}, timeout=4.0)
            if resp.status_code == 200:
                answers = resp.json().get("Answer", [])
                for ans in answers:
                    data_val = str(ans.get("data", "")).strip('"')
                    if expected_token in data_val:
                        return True
        except Exception:
            pass

        # 2. Local nslookup fallback
        try:
            proc = subprocess.run(
                ["nslookup", "-type=TXT", txt_host],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if expected_token in proc.stdout:
                return True
        except Exception:
            pass

    return False


def _check_well_known_file(domain: str, expected_token: str) -> bool:
    """Fetch /.well-known verification file via safe_fetch."""
    candidate_urls = [
        f"https://{domain}/.well-known/aegis-verify.txt",
        f"https://{domain}/.well-known/attacksurface-verify.txt",
    ]
    for url in candidate_urls:
        try:
            response = safe_fetch(url, timeout=5.0)
            if response.status_code == 200:
                if expected_token in response.text.strip():
                    return True
        except (SafeFetchError, Exception):
            pass
    return False


def check_verification(domain: str) -> tuple[bool, str]:
    """
    Verify ownership by checking both DNS TXT and HTTP .well-known challenges.
    Returns (success: bool, message: str).
    """
    clean_domain = normalize_host(domain)
    data = _load_verified_data()
    record = data.get(clean_domain)

    if not record or not record.get("token"):
        return False, f"No verification challenge in progress for '{clean_domain}'. Start verification first."

    token = record["token"]

    # Check DNS TXT
    if _check_dns_txt_record(clean_domain, token):
        now = time.time()
        record["verified"] = True
        record["method"] = "dns-txt"
        record["verified_at"] = now
        record["expires_at"] = now + VERIFICATION_TTL_SECONDS
        data[clean_domain] = record
        _save_verified_data(data)
        return True, f"Domain '{clean_domain}' successfully verified via DNS TXT record! Active scanning authorized for 30 days."

    # Check HTTP .well-known
    if _check_well_known_file(clean_domain, token):
        now = time.time()
        record["verified"] = True
        record["method"] = "http-well-known"
        record["verified_at"] = now
        record["expires_at"] = now + VERIFICATION_TTL_SECONDS
        data[clean_domain] = record
        _save_verified_data(data)
        return True, f"Domain '{clean_domain}' successfully verified via HTTP .well-known token! Active scanning authorized for 30 days."

    return False, (
        f"Verification failed for '{clean_domain}'. Neither the DNS TXT record (_aegis-verify.{clean_domain}) "
        f"nor https://{clean_domain}/.well-known/aegis-verify.txt matched the expected token."
    )


def load_verified_targets() -> dict[str, dict[str, Any]]:
    """Return all currently active and non-expired verified target records."""
    data = _load_verified_data()
    return {k: v for k, v in data.items() if is_domain_verified(k)}


def generate_verification_token(domain: str) -> str:
    """Convenience alias: generate and store challenge token for a domain, returning token string."""
    info = start_verification(domain)
    return str(info.get("token", ""))


check_domain_verification = check_verification

