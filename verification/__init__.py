"""AEGIS-AI Domain Ownership Verification Package."""
from verification.verify import (
    start_verification,
    check_verification,
    is_domain_verified,
    load_verified_targets,
    check_domain_verification,
    generate_verification_token,
)

__all__ = [
    "start_verification",
    "check_verification",
    "is_domain_verified",
    "load_verified_targets",
    "check_domain_verification",
    "generate_verification_token",
]
