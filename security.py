"""
AEGIS-AI Input Validation, Abuse Prevention & Security Guardrails.

Provides input sanitization, rate limiting, SSRF checks, prompt injection protection,
and server-side operational mode determination (Passive OSINT vs Verified Active).
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
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
# Decoupled buckets so general telemetry/chat calls do not consume scan budgets
_RATE_LIMIT_LOCK = threading.Lock()
_SCAN_CLIENT_RATE_LIMITS: dict[str, list[float]] = {}
_API_CLIENT_RATE_LIMITS: dict[str, list[float]] = {}
_TARGET_RATE_LIMITS: dict[str, list[float]] = {}
_CLIENT_RATE_LIMITS = _SCAN_CLIENT_RATE_LIMITS  # Compatibility alias


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

    is_ip = False
    # Check if target is a valid IP address
    try:
        ip = ipaddress.ip_address(normalized)
        is_ip = True
        target_str = ip.compressed
    except ValueError:
        target_str = normalized
        # Validate hostname syntax
        if not _HOSTNAME_RE.match(normalized):
            raise ValidationError(f"Invalid hostname format: '{normalized}'. Must conform to standard domain naming rules.")

    # SSRF Guard:
    # If the target is NOT explicitly allowed for active scanning in allowlist/verified store,
    # run resolve_and_validate_hostname() to block loopback, private subnets, cloud metadata,
    # and DNS rebinding to internal IPs.
    if not is_target_allowed_for_active_scan(target_str):
        from discovery.safe_fetch import resolve_and_validate_hostname, SafeFetchError
        try:
            resolve_and_validate_hostname(target_str)
        except SafeFetchError as sfe:
            err_msg = str(sfe)
            if "DNS resolution failed" in err_msg:
                if is_ip or target_str.lower() in {"localhost", "localhost.localdomain"} or target_str.endswith(".local") or target_str.endswith(".internal"):
                    raise ValidationError(f"Target rejected (SSRF boundary violation): '{target_str}' is an internal address.")
                # Domain is syntactically valid but could not be resolved by current DNS (e.g. offline unit testing)
            else:
                raise ValidationError(f"Target rejected (SSRF boundary violation): {sfe}")

    return target_str


def determine_scan_mode(target: str, requested_active: bool = False) -> Tuple[str, bool, str]:
    """
    Server-side authoritative decision for operational scan mode.
    The client can NEVER force an active scan on an unauthorized target.

    Returns:
        (mode_name: str, can_active: bool, rationale: str)
    """
    normalized = validate_target_input(target)

    # Disable active mode entirely on public cloud deployments (Render, etc.)
    if getattr(config, "is_public_deployment", lambda: False)():
        if requested_active:
            return (
                "PASSIVE OSINT",
                False,
                "Active port scanning is disabled on public cloud hosting to prevent infrastructure abuse."
            )
        return (
            "PASSIVE OSINT",
            False,
            "Passive OSINT mode active. Active port scanning is disabled on public cloud hosting."
        )

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


def get_real_client_ip(req: Any) -> str:
    """
    Securely extract the client IP address behind reverse proxies (Render, AWS, etc.).
    Protects against IP spoofing:
    - Only trusts CF-Connecting-IP / True-Client-IP if TRUST_CLOUDFLARE_PROXIES is enabled.
    - If X-Forwarded-For contains multiple IPs, uses the last entry (the proxy-appended hop).
    - Falls back to request.remote_addr.
    """
    if not req:
        return "127.0.0.1"

    headers = getattr(req, "headers", {}) or {}

    # 1. Edge CDN headers (Cloudflare, etc.) - only if explicitly trusted
    if getattr(config, "TRUST_CLOUDFLARE_PROXIES", False):
        cf_ip = headers.get("CF-Connecting-IP")
        if cf_ip and cf_ip.strip():
            return cf_ip.strip()

        true_ip = headers.get("True-Client-IP")
        if true_ip and true_ip.strip():
            return true_ip.strip()

    # 2. X-Forwarded-For: Take the LAST entry to prevent client spoofing
    # Forward proxies prepend client headers; reverse proxies append the caller IP
    xff = headers.get("X-Forwarded-For")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]

    return getattr(req, "remote_addr", None) or "127.0.0.1"


def check_client_rate_limit(client_ip: str, max_per_minute: int = 30) -> Tuple[bool, int, str]:
    """Sliding-window rate limiter per client IP for general/LLM endpoints."""
    now = time.time()
    window = 60.0
    ip_key = client_ip.strip() or "anonymous"

    with _RATE_LIMIT_LOCK:
        if ip_key not in _API_CLIENT_RATE_LIMITS:
            _API_CLIENT_RATE_LIMITS[ip_key] = []

        _API_CLIENT_RATE_LIMITS[ip_key] = [t for t in _API_CLIENT_RATE_LIMITS[ip_key] if now - t < window]

        if len(_API_CLIENT_RATE_LIMITS[ip_key]) >= max_per_minute:
            oldest = _API_CLIENT_RATE_LIMITS[ip_key][0]
            retry_after = max(1, int(window - (now - oldest)))
            return False, retry_after, f"Too many requests from IP {ip_key}. Max {max_per_minute}/min. Retry in {retry_after}s."

        _API_CLIENT_RATE_LIMITS[ip_key].append(now)
        return True, 0, ""


def check_rate_limits(client_ip: str, target: str) -> Tuple[bool, int, str]:
    """
    Check sliding-window rate limits per client IP and per target.
    Returns (is_allowed: bool, retry_after_seconds: int, error_message: str).
    """
    now = time.time()
    window = 60.0  # 1 minute window

    ip_key = client_ip.strip() or "anonymous"
    norm_target = normalize_host(target) or target

    with _RATE_LIMIT_LOCK:
        # 1. Clean old entries and check client IP rate for scans
        timestamps = _SCAN_CLIENT_RATE_LIMITS.setdefault(ip_key, [])
        _SCAN_CLIENT_RATE_LIMITS[ip_key] = [t for t in timestamps if now - t < window]

        if len(_SCAN_CLIENT_RATE_LIMITS[ip_key]) >= RATE_LIMIT_PER_MINUTE:
            earliest = _SCAN_CLIENT_RATE_LIMITS[ip_key][0]
            retry_after = max(1, int(window - (now - earliest)))
            return False, retry_after, f"Rate limit exceeded. Maximum {RATE_LIMIT_PER_MINUTE} requests/min per IP."

        # 2. Clean old entries and check target rate
        target_timestamps = _TARGET_RATE_LIMITS.setdefault(norm_target, [])
        _TARGET_RATE_LIMITS[norm_target] = [t for t in target_timestamps if now - t < window]

        if len(_TARGET_RATE_LIMITS[norm_target]) >= RATE_LIMIT_TARGET_PER_MINUTE:
            earliest = _TARGET_RATE_LIMITS[norm_target][0]
            retry_after = max(1, int(window - (now - earliest)))
            return False, retry_after, f"Target rate limit exceeded. Maximum {RATE_LIMIT_TARGET_PER_MINUTE} scans/min against '{norm_target}'."

        # Record current request
        _SCAN_CLIENT_RATE_LIMITS[ip_key].append(now)
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
