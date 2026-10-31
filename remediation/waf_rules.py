"""
AEGIS-AI: Web Application Firewall (WAF) Rule Exporter.
Generates ready-to-import AWS WAF JSON, Cloudflare WAF expressions, and ModSecurity CRS rules.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def generate_cloudflare_waf_expression(target: str = "example.com") -> str:
    """Generate Cloudflare Firewall Rule expression."""
    return (
        '(http.request.uri.path contains "/redirect" and http.request.uri.query contains "//") or '
        '(http.request.uri.query contains "<script>") or '
        '(http.request.uri.query contains "UNION+SELECT") or '
        '(http.request.uri.query contains "../..")'
    )


def generate_aws_waf_json(target: str = "example.com") -> Dict[str, Any]:
    """Generate AWS WAF WebACL rule set in native JSON format."""
    safe_name = target.replace(".", "-").replace(":", "-")
    return {
        "Name": f"AegisShield-{safe_name}",
        "Priority": 1,
        "Action": {"Block": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "AegisShieldPerimeterBlock"
        },
        "Statement": {
            "OrStatement": {
                "Statements": [
                    {
                        "ByteMatchStatement": {
                            "SearchString": "//",
                            "FieldToMatch": {"QueryString": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
                            "PositionalConstraint": "CONTAINS"
                        }
                    },
                    {
                        "SqliMatchStatement": {
                            "FieldToMatch": {"QueryString": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}]
                        }
                    },
                    {
                        "XssMatchStatement": {
                            "FieldToMatch": {"QueryString": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}]
                        }
                    }
                ]
            }
        }
    }


def generate_modsecurity_rules(target: str = "example.com") -> str:
    """Generate OWASP ModSecurity Core Rule Set (CRS) snippet."""
    return f"""# ==============================================================================
# AEGIS-AI ModSecurity CRS Virtual Patch Rules
# Target: {target}
# ==============================================================================

SecRuleEngine On

# 1. Block Open Redirect and Schema Relative Ingress
SecRule ARGS "@rx ^//[a-zA-Z0-9]" \\
    "id:1000001,phase:2,deny,status:403,log,msg:'AEGIS-AI Virtual Patch: Open Redirect Attempt Blocked'"

# 2. Block Cross-Site Scripting (XSS) Patterns in Query Arguments
SecRule ARGS "@rx <script.*?>.*?</script>" \\
    "id:1000002,phase:2,deny,status:403,log,msg:'AEGIS-AI Virtual Patch: XSS Pattern in Query String Blocked'"

# 3. Block Path Traversal
SecRule REQUEST_URI "@rx \\.\\./\\.\\." \\
    "id:1000003,phase:2,deny,status:403,log,msg:'AEGIS-AI Virtual Patch: Directory Traversal Blocked'"
"""
