"""
Automated Remediation & Hardening Code Generator.
Produces instant drop-in configuration snippets for Nginx, Apache, Caddy, Cloudflare,
Docker/Node.js, AWS WAF, DNS Records, and Linux Firewalls.
"""

from __future__ import annotations

from typing import Any


def _norm_args(findings: Any, target: str) -> tuple[list[dict[str, Any]], str]:
    if isinstance(findings, str):
        return [], findings
    return findings or [], target


def generate_nginx_hardening(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate production-ready Nginx hardening configuration block."""
    findings, target = _norm_args(findings, target)
    snippets = [
        f"# ========================================================",
        f"# NGINX DEFENSIVE SECURITY HARDENING FOR: {target}",
        f"# Place inside http {{ }} or server {{ }} block in /etc/nginx/nginx.conf",
        f"# ========================================================",
        "",
        "# 1. Information Disclosure Mitigation",
        "server_tokens off;",
        "more_clear_headers 'Server' 'X-Powered-By';",
        "",
        "# 2. Security Headers Suite",
        'add_header X-Frame-Options "DENY" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
        'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'; frame-ancestors \'none\'; object-src \'none\'; base-uri \'self\';" always;',
        'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
        "",
        "# 3. TLS / SSL Modern Cipher Hardening",
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "ssl_prefer_server_ciphers on;",
        "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;",
        "ssl_session_cache shared:SSL:10m;",
        "ssl_session_timeout 1d;",
        "ssl_session_tickets off;",
        "ssl_stapling on;",
        "ssl_stapling_verify on;",
    ]
    return "\n".join(snippets)


def generate_apache_hardening(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate production-ready Apache (.htaccess / httpd.conf) configuration."""
    findings, target = _norm_args(findings, target)
    snippets = [
        f"# ========================================================",
        f"# APACHE HTTPD SECURITY HARDENING FOR: {target}",
        f"# Place inside httpd.conf, virtual host, or .htaccess",
        f"# ========================================================",
        "",
        "# 1. Suppress Server Identification Banners",
        "ServerTokens Prod",
        "ServerSignature Off",
        "TraceEnable Off",
        "",
        "# 2. Security Headers (Requires mod_headers)",
        "<IfModule mod_headers.c>",
        '    Header always set X-Frame-Options "DENY"',
        '    Header always set X-Content-Type-Options "nosniff"',
        '    Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        '    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"',
        '    Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'; frame-ancestors \'none\'; object-src \'none\'; base-uri \'self\';"',
        '    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        "    Header unset X-Powered-By",
        "</IfModule>",
        "",
        "# 3. TLS Protocol & Cipher Suite Hardening (mod_ssl)",
        "<IfModule mod_ssl.c>",
        "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
        "    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128",
        "    SSLHonorCipherOrder on",
        "    SSLUseStapling on",
        "</IfModule>",
    ]
    return "\n".join(snippets)


def generate_caddy_hardening(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate Caddyfile configuration."""
    findings, target = _norm_args(findings, target)
    snippets = [
        f"# Caddyfile Hardening Block for {target}",
        f"{target} {{",
        "    header {",
        '        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        '        X-Content-Type-Options "nosniff"',
        '        X-Frame-Options "DENY"',
        '        Referrer-Policy "strict-origin-when-cross-origin"',
        '        Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"',
        '        Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'; frame-ancestors \'none\'; object-src \'none\'; base-uri \'self\';"',
        "        -Server",
        "        -X-Powered-By",
        "    }",
        "    tls {",
        "        protocols tls1.2 tls1.3",
        "    }",
        "    reverse_proxy localhost:8080",
        "}",
    ]
    return "\n".join(snippets)


def generate_cloudflare_rules(findings: list[dict[str, Any]] | str | None = None, target: str = "example.com") -> str:
    """Generate Cloudflare Transform Rules or Worker Snippet."""
    findings, target = _norm_args(findings, target)
    snippets = [
        f"// Cloudflare Worker / Transform Rule for HTTP Security Response Headers",
        f"// Target: {target}",
        "",
        "export default {",
        "  async fetch(request, env, ctx) {",
        "    const response = await fetch(request);",
        "    const newHeaders = new Headers(response.headers);",
        "",
        "    // Defensive Security Headers",
        '    newHeaders.set("X-Frame-Options", "DENY");',
        '    newHeaders.set("X-Content-Type-Options", "nosniff");',
        '    newHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");',
        '    newHeaders.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");',
        '    newHeaders.set("Content-Security-Policy", "default-src \'self\'; frame-ancestors \'none\';");',
        '    newHeaders.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");',
        "",
        "    // Strip information disclosure headers",
        '    newHeaders.delete("server");',
        '    newHeaders.delete("x-powered-by");',
        "",
        "    return new Response(response.body, {",
        "      status: response.status,",
        "      statusText: response.statusText,",
        "      headers: newHeaders",
        "    });",
        "  }",
        "};",
    ]
    return "\n".join(snippets)


def generate_node_helmet(findings: list[dict[str, Any]] | str | None = None) -> str:
    """Generate Node.js Express + Helmet security middleware setup."""
    if isinstance(findings, str):
        findings = []
    findings = findings or []
    snippets = [
        "// Express.js Defense Setup using Helmet & Security Best Practices",
        "const express = require('express');",
        "const helmet = require('helmet');",
        "const app = express();",
        "",
        "// Disable Express disclosure banner",
        "app.disable('x-powered-by');",
        "",
        "// Enforce comprehensive HTTP security headers",
        "app.use(helmet({",
        "  contentSecurityPolicy: {",
        "    directives: {",
        "      defaultSrc: [\"'self'\"],",
        "      scriptSrc: [\"'self'\"],",
        "      styleSrc: [\"'self'\", \"'unsafe-inline'\"],",
        "      imgSrc: [\"'self'\", 'data:'],",
        "      frameAncestors: [\"'none'\"],",
        "      objectSrc: [\"'none'\"],",
        "    },",
        "  },",
        "  hsts: {",
        "    maxAge: 63072000,",
        "    includeSubDomains: true,",
        "    preload: true,",
        "  },",
        "  frameguard: { action: 'deny' },",
        "  noSniff: true,",
        "  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },",
        "}));",
    ]
    return "\n".join(snippets)


def generate_dns_hardening(target: str = "example.com") -> str:
    """Generate copyable DNS SPF and DMARC TXT records."""
    snippets = [
        f"; DNS Security Records for: {target}",
        f"; 1. SPF (Sender Policy Framework) - Protects against unauthorized email senders",
        f'{target}.    IN    TXT    "v=spf1 include:_spf.google.com ~all"',
        f"; Note: If this domain sends NO email at all, use the strict null SPF record:",
        f'{target}.    IN    TXT    "v=spf1 -all"',
        "",
        f"; 2. DMARC (Domain-based Message Authentication, Reporting, and Conformance)",
        f'_dmarc.{target}.    IN    TXT    "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc-reports@{target}"',
        "",
        f"; 3. CAA (Certificate Authority Authorization) - Restricts which CAs can issue certificates",
        f'{target}.    IN    CAA    0 issue "letsencrypt.org"',
        f'{target}.    IN    CAA    0 issue "digicert.com"',
        f'{target}.    IN    CAA    0 iodef "mailto:security@{target}"',
    ]
    return "\n".join(snippets)


def generate_firewall_rules(ports: list[int] | None = None) -> str:
    """Generate Linux UFW and iptables firewall rules."""
    exposed_ports = ports or [8080, 8000, 3000, 5000, 9000]
    snippets = [
        "# Linux UFW (Uncomplicated Firewall) Rules",
        "sudo ufw default deny incoming",
        "sudo ufw default allow outgoing",
        "sudo ufw allow 22/tcp comment 'SSH Authorized'",
        "sudo ufw allow 80/tcp comment 'HTTP'",
        "sudo ufw allow 443/tcp comment 'HTTPS'",
        "",
        "# Block / Close Non-Essential Exposed Ports:",
    ]
    for p in exposed_ports:
        if p not in [80, 443, 22]:
            snippets.append(f"sudo ufw deny {p}/tcp comment 'Close exposed port {p}'")
    
    snippets.extend([
        "",
        "# Enable Firewall",
        "sudo ufw enable",
        "sudo ufw status verbose",
    ])
    return "\n".join(snippets)


generate_express_helmet_hardening = generate_node_helmet


def generate_flask_talisman_hardening(findings: list[dict[str, Any]] | None = None) -> str:
    """Generate Flask-Talisman security headers configuration snippet."""
    return """from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\' \'unsafe-inline\'',
    'img-src': '\'self\' data:',
}
Talisman(app, content_security_policy=csp, force_https=True)
"""

