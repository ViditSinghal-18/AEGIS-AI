"""
AEGIS-AI Central Configuration & Environment Management.

Enforces strict defense defaults, serverless compatibility, target validation,
and configurable threat intelligence parameters.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

# Load .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ROOT = Path(__file__).resolve().parent

# Server & Environment
ENV = os.getenv("AEGIS_ENV", os.getenv("FLASK_ENV", "production")).lower()
IS_VERCEL = bool(os.getenv("VERCEL") == "1" or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
DEBUG = os.getenv("AEGIS_DEBUG", "false").lower() in ("true", "1", "yes") and not IS_VERCEL
PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "127.0.0.1")
SECRET_KEY = os.getenv("SECRET_KEY", "aegis-defense-default-key-change-in-prod")

# Optional access control token for scan endpoints
AEGIS_API_TOKEN = os.getenv("AEGIS_API_TOKEN", "").strip()

# Path configuration with Serverless (/tmp) auto-detection
if IS_VERCEL:
    DATA_DIR = Path("/tmp/aegis_data")
else:
    DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", str(ROOT / "data")))

DATA_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_DATA_DIR = ROOT / "data" / "sample"
ALLOWLIST_PATH = ROOT / "targets.allowlist"

# Scanning & Target Defaults
DEFAULT_TARGET = os.getenv("DEFAULT_TARGET", "localhost")
DEFAULT_PORTS = [
    int(p.strip())
    for p in os.getenv("DEFAULT_PORTS", "80,443,3000,8000,8080").split(",")
    if p.strip().isdigit()
]
MAX_PORTS_PER_SCAN = 32

# Abuse Prevention & Timeouts
SAFE_FETCH_TIMEOUT = float(os.getenv("SAFE_FETCH_TIMEOUT", "6.0"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", str(1024 * 1024)))  # 1 MB
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "3"))

# Rate Limiting (per IP and per Target)
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))
RATE_LIMIT_TARGET_PER_MINUTE = int(os.getenv("RATE_LIMIT_TARGET_PER_MINUTE", "4"))

# Domain Verification
VERIFICATION_TTL_DAYS = int(os.getenv("VERIFICATION_TTL_DAYS", "30"))
VERIFICATION_TTL_SECONDS = VERIFICATION_TTL_DAYS * 86400

# Threat Intelligence APIs (Optional credentials)
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
FIRST_EPSS_API = os.getenv("FIRST_EPSS_API", "https://api.first.org/data/v1/epss")
CISA_KEV_FEED = os.getenv(
    "CISA_KEV_FEED",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
OSV_QUERY_API = os.getenv("OSV_QUERY_API", "https://api.osv.dev/v1/query")

# AI Copilot Backend (Optional LLM configuration)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").lower()  # auto, gemini, anthropic, openai, offline

# CORS
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")


def normalize_host(raw: str) -> str:
    """
    Turn URLs, host:port strings, bracketed IPv6, and trailing-dot hostnames
    into a canonical lowercase hostname or compressed IP address.
    """
    val = (raw or "").strip()
    if not val:
        return ""

    if "://" in val:
        try:
            parsed = urlparse(val)
            host = parsed.hostname or ""
        except Exception:
            host = ""
    elif "/" in val:
        try:
            parsed = urlparse(f"http://{val}")
            host = parsed.hostname or ""
        except Exception:
            host = ""
    else:
        if val.startswith("[") and "]" in val:
            bracket_end = val.find("]")
            host = val[1:bracket_end]
        elif ":" in val and val.count(":") == 1:
            host, _, _ = val.partition(":")
        else:
            host = val

    host = host.strip().lower().rstrip(".")
    if not host:
        return ""

    # Validate / compress IP addresses
    try:
        ip_obj = ipaddress.ip_address(host)
        return ip_obj.compressed
    except ValueError:
        pass

    return host


def load_allowlist() -> set[str]:
    """Read targets.allowlist and return normalized allowed targets."""
    if not ALLOWLIST_PATH.exists():
        # Fallback to local loopback if file doesn't exist
        return {"localhost", "127.0.0.1", "::1"}
    
    allowed: set[str] = set()
    for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            norm = normalize_host(line)
            if norm:
                allowed.add(norm)
    return allowed


def is_target_allowed_for_active_scan(target: str) -> bool:
    """
    Check if a target is authorized for active (port probing / Nmap) scans.
    Allowed only if the target is:
    1. In targets.allowlist (e.g. localhost, 127.0.0.1, internal test labs), OR
    2. Verified via cryptographic domain ownership verification.
    """
    normalized = normalize_host(target)
    if not normalized:
        return False

    # Check allowlist
    try:
        if normalized in load_allowlist():
            return True
    except Exception:
        if normalized in {"localhost", "127.0.0.1", "::1"}:
            return True

    # Check domain ownership verification store
    try:
        from verification.verify import is_domain_verified
        if is_domain_verified(normalized):
            return True
    except Exception:
        pass

    return False
