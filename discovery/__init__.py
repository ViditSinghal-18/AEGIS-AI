"""AEGIS-AI Network Discovery and Attack Surface Mapping Package."""
from discovery.safe_fetch import safe_fetch, SafeFetchError, is_ip_allowed_for_public_fetch, resolve_and_validate_hostname

__all__ = ["safe_fetch", "SafeFetchError", "is_ip_allowed_for_public_fetch", "resolve_and_validate_hostname"]
