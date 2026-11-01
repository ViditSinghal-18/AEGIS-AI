"""
Web Application Firewall (WAF) Rule Exporter.
Generates ready-to-import AWS WAF JSON, Cloudflare WAF expressions, and ModSecurity rules.
"""

from __future__ import annotations

import json
from typing import Any


def _norm_args(findings: Any, target: str) -> tuple[list[dict[str, Any]], str]:
    if isinstance(findings, str):
        return [], findings
    return findings or [], target


def generate_aws_waf_json(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate AWS WAF WebACL Custom Response Headers & Block Rule JSON."""
    findings, target = _norm_args(findings, target)
    rules = [
        {
            "Name": "EnforceSecurityHeadersAndMitigation",
            "Priority": 1,
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesCommonRuleSet",
                    "ExcludedRules": [],
                }
            },
            "OverrideAction": {"None": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "AWSCommonRulesMetric",
            },
        },
        {
            "Name": "BlockKnownExploitScanners",
            "Priority": 2,
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                }
            },
            "OverrideAction": {"None": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "BadInputsMetric",
            },
        },
        {
            "Name": "RateLimitShield",
            "Priority": 3,
            "Statement": {
                "RateBasedStatement": {
                    "Limit": 2000,
                    "AggregateKeyType": "IP",
                }
            },
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "RateLimitExceeded",
            },
        },
    ]
    web_acl = {
        "WebACL": {
            "Name": f"WAF-Protection-{target.replace('.', '-')}",
            "Scope": "REGIONAL",
            "DefaultAction": {"Allow": {}},
            "Description": f"Automated Defensive WAF Shield for {target}",
            "Rules": rules,
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "WebACLOverview",
            },
        }
    }
    return json.dumps(web_acl, indent=2)


def generate_cloudflare_waf_rules(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate Cloudflare Custom Firewall Rules expressions."""
    findings, target = _norm_args(findings, target)
    lines = [
        f"# ========================================================",
        f"# Cloudflare Custom WAF Expression Rules for: {target}",
        f"# Copy into Cloudflare Dashboard -> Security -> WAF -> Custom Rules",
        f"# ========================================================",
        "",
        "# Rule 1: Block Automated Bot Probing & Common Exploitation Scanners",
        "Expression:",
        '(http.user_agent contains "nikto" or http.user_agent contains "sqlmap" or http.user_agent contains "nmap" or http.user_agent contains "masscan")',
        "Action: Block",
        "",
        "# Rule 2: Shield Administrative and Diagnostic Endpoints",
        "Expression:",
        '(http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git" or http.request.uri.path contains "/wp-admin" or http.request.uri.path contains "/phpmyadmin")',
        "Action: Block",
        "",
        "# Rule 3: Enforce HTTPS & Challenge Insecure Legacy HTTP Clients",
        "Expression:",
        '(not ssl and http.host eq "' + target + '")',
        "Action: Dynamic Redirect -> 301 to https://" + target + "{http.request.uri.path}",
    ]
    return "\n".join(lines)


generate_cloudflare_waf_expression = generate_cloudflare_waf_rules


def generate_modsecurity_rules(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate ModSecurity / Coraza WAF .conf rules."""
    findings, target = _norm_args(findings, target)
    lines = [
        f"# ========================================================",
        f"# ModSecurity (OWASP CRS) Rules for: {target}",
        f"# Place in /etc/modsecurity/coraza.conf or custom_rules.conf",
        f"# ========================================================",
        "",
        "# 1. Enable Rule Engine",
        "SecRuleEngine On",
        "SecRequestBodyAccess On",
        "SecResponseBodyAccess Off",
        "",
        "# 2. Block Known Malicious Scanner User-Agents",
        'SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" \\',
        '    "id:100001,phase:1,deny,status:403,log,msg:\'Automated Vulnerability Scanner Blocked\'"',
        "",
        "# 3. Strip Sensitive Server Banners from Outbound Headers",
        'SecHeaderSetResponse X-Frame-Options "DENY"',
        'SecHeaderSetResponse X-Content-Type-Options "nosniff"',
        'SecHeaderSetResponse Referrer-Policy "strict-origin-when-cross-origin"',
        'SecHeaderSetResponse Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\';"',
        'SecHeaderRemove Server',
        'SecHeaderRemove X-Powered-By',
    ]
    return "\n".join(lines)


generate_cloudflare_waf_expression = generate_cloudflare_waf_rules
