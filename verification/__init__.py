"""AEGIS-AI Domain Ownership Verification Package."""
from verification.verify import (
    start_verification,
    check_verification,
    is_domain_verified,
    load_verified_targets,
)

__all__ = [
    "start_verification",
    "check_verification",
    "is_domain_verified",
    "load_verified_targets",
]
