"""
AEGIS-AI Remediation Package.
Provides automated configuration hardening and WAF rule generation.
"""

from remediation.code_gen import (
    generate_nginx_hardening,
    generate_apache_hardening,
    generate_caddy_hardening,
    generate_express_helmet_hardening,
    generate_flask_talisman_hardening
)
from remediation.waf_rules import (
    generate_cloudflare_waf_expression,
    generate_aws_waf_json,
    generate_modsecurity_rules
)


def generate_waf_rules(target: str = "example.com") -> dict:
    """Generate all WAF rule variations for a target."""
    return {
        "target": target,
        "cloudflare": generate_cloudflare_waf_expression(target),
        "aws_waf": generate_aws_waf_json(target),
        "modsecurity": generate_modsecurity_rules(target)
    }


def generate_remediation_bundle(target: str = "example.com") -> dict:
    """Bundle all hardening configs and WAF rules for a target."""
    return {
        "target": target,
        "nginx": generate_nginx_hardening(target),
        "apache": generate_apache_hardening(target),
        "caddy": generate_caddy_hardening(target),
        "express_helmet": generate_express_helmet_hardening(),
        "flask_talisman": generate_flask_talisman_hardening(),
        "waf": generate_waf_rules(target)
    }


__all__ = [
    "generate_nginx_hardening",
    "generate_apache_hardening",
    "generate_caddy_hardening",
    "generate_express_helmet_hardening",
    "generate_flask_talisman_hardening",
    "generate_cloudflare_waf_expression",
    "generate_aws_waf_json",
    "generate_modsecurity_rules",
    "generate_waf_rules",
    "generate_remediation_bundle"
]
