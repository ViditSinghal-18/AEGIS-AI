"""
AEGIS-AI Input Validation, Abuse Prevention & Security Guardrails.

Provides input sanitization, rate limiting, SSRF checks, prompt injection protection,
and server-side operational mode determination (Passive OSINT vs Verified Active).
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Any, Tuple

import config
from config import (
    RATE_LIMIT_PER_MINUTE,
    RATE_LIMIT_TARGET_PER_MINUTE,
    is_target_allowed_for_active_scan,
    normalize_host,
)

is_target_allowlisted = is_target_allowed_for_active_scan

# RFC 1123 compliant hostname regex (max 253 chars total, labels 1-63 chars)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# Dangerous shell or injection characters
_ILLEGAL_CHARS_RE = re.compile(r"[\s<>'\"`;&|$\\\x00-\x1f]")

# In-memory sliding window rate limiters: {key: [timestamps]}
_CLIENT_RATE_LIMITS: dict[str, list[float]] = {}
_TARGET_RATE_LIMITS: dict[str, list[float]] = {}


class ValidationError(ValueError):
    """Raised when user input violates validation or security rules."""
    pass


def validate_target_input(raw: Any) -> str:
    """
    Validate, sanitize, and normalize target input (domain, hostname, or IP).
    Rejects illegal characters, length violations, credentials in URLs, and malformed hosts.
    """
    if raw is None:
        raise ValidationError("Target is required.")
    
    val = str(raw).strip()
    if not val:
        raise ValidationError("Target hostname or IP address cannot be empty.")

    if len(val) > 253:
        raise ValidationError(f"Target length ({len(val)}) exceeds maximum permitted length of 253 characters.")

    if _ILLEGAL_CHARS_RE.search(val):
        raise ValidationError("Target contains prohibited control or special characters.")

    if "@" in val:
        raise ValidationError("URLs containing user credentials are not permitted.")

    normalized = normalize_host(val)
    if not normalized:
        raise ValidationError("Target could not be resolved to a valid hostname or IP address.")

    # Check if target is a valid IP address
    try:
        ip = ipaddress.ip_address(normalized)
        return ip.compressed
    except ValueError:
        pass

    # Validate hostname syntax
    if not _HOSTNAME_RE.match(normalized):
        raise ValidationError(f"Invalid hostname format: '{normalized}'. Must conform to standard domain naming rules.")

    return normalized


def determine_scan_mode(target: str, requested_active: bool = False) -> Tuple[str, bool, str]:
    """
    Server-side authoritative decision for operational scan mode.
    The client can NEVER force an active scan on an unauthorized target.

    Returns:
        (mode_name: str, can_active: bool, rationale: str)
    """
    normalized = validate_target_input(target)
    can_active = is_target_allowed_for_active_scan(normalized)

    if can_active and requested_active:
        mode_name = "VERIFIED ACTIVE"
        rationale = f"Active port probing authorized: '{normalized}' is allowlisted or ownership verified."
    elif can_active:
        mode_name = "PASSIVE OSINT"
        rationale = f"Passive OSINT mode selected. Active scanning is authorized for '{normalized}' if requested."
    else:
        mode_name = "PASSIVE OSINT"
        rationale = f"Zero port probing mode: '{normalized}' is not in allowlist and not ownership-verified. (Verify via /api/verify/start)"

    return (mode_name, can_active, rationale)


def check_rate_limits(client_ip: str, target: str) -> Tuple[bool, int, str]:
    """
    Check sliding-window rate limits per client IP and per target.
    Returns (is_allowed: bool, retry_after_seconds: int, error_message: str).
    """
    now = time.time()
    window = 60.0  # 1 minute window

    # 1. Clean old entries and check client IP rate
    ip_key = client_ip.strip() or "anonymous"
    timestamps = _CLIENT_RATE_LIMITS.setdefault(ip_key, [])
    _CLIENT_RATE_LIMITS[ip_key] = [t for t in timestamps if now - t < window]

    if len(_CLIENT_RATE_LIMITS[ip_key]) >= RATE_LIMIT_PER_MINUTE:
        earliest = _CLIENT_RATE_LIMITS[ip_key][0]
        retry_after = max(1, int(window - (now - earliest)))
        return False, retry_after, f"Rate limit exceeded. Maximum {RATE_LIMIT_PER_MINUTE} requests/min per IP."

    # 2. Clean old entries and check target rate
    norm_target = normalize_host(target) or target
    target_timestamps = _TARGET_RATE_LIMITS.setdefault(norm_target, [])
    _TARGET_RATE_LIMITS[norm_target] = [t for t in target_timestamps if now - t < window]

    if len(_TARGET_RATE_LIMITS[norm_target]) >= RATE_LIMIT_TARGET_PER_MINUTE:
        earliest = _TARGET_RATE_LIMITS[norm_target][0]
        retry_after = max(1, int(window - (now - earliest)))
        return False, retry_after, f"Target rate limit exceeded. Maximum {RATE_LIMIT_TARGET_PER_MINUTE} scans/min against '{norm_target}'."

    # Record current request
    _CLIENT_RATE_LIMITS[ip_key].append(now)
    _TARGET_RATE_LIMITS[norm_target].append(now)
    return True, 0, ""


def verify_api_token(request_headers: Any) -> bool:
    """
    Validate API token if configured. Returns True if token matches or if none is set.
    """
    active_token = getattr(config, "AEGIS_API_TOKEN", "").strip()
    if not active_token:
        return True  # Open access mode

    # Check X-Aegis-Token header
    token = request_headers.get("X-Aegis-Token")
    if token and token.strip() == active_token:
        return True

    # Check Authorization: Bearer <token>
    auth = request_headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token == active_token:
            return True

    return False


def sanitize_for_prompt(text: str, max_len: int = 500) -> str:
    """
    Strip control characters, prompt injection tags, and cap length
    before embedding untrusted target telemetry into an LLM prompt.
    """
    if not text:
        return ""
    # Strip non-printable ASCII characters except newline and tab
    cleaned = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
    # Neutralize XML boundary spoofing
    cleaned = cleaned.replace("<target_data>", "").replace("</target_data>", "")
    cleaned = cleaned.replace("```", "'''")
    return cleaned.strip()[:max_len]


def wrap_target_data(data: dict[str, Any]) -> str:
    """
    Wrap untrusted telemetry inside explicit defensive boundary tags.
    """
    serialized = json.dumps(data, indent=2, default=str)
    sanitized = sanitize_for_prompt(serialized, max_len=6000)
    return f"""<target_data>
{sanitized}
</target_data>
"""
