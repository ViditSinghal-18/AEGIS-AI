"""
AEGIS-AI: Automated Hardening & Remediation Code Generator.
Generates drop-in security configurations for Nginx, Apache, Caddy, Express (Helmet),
Python Flask (Talisman), and Docker containers tailored to observed perimeter findings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def generate_nginx_hardening(target: str = "example.com", findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """Generate production-ready Nginx reverse-proxy hardening snippet."""
    return f"""# ==============================================================================
# AEGIS-AI Automated Hardening Configuration for Nginx
# Target: {target}
# Standards: NIST CSF PR.DS-2, PCI-DSS 4.0 Req 6.4.1, OWASP Top 10 A05:2021
# ==============================================================================

server {{
    listen 80;
    server_name {target};
    # Enforce immediate 301 redirection to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {target};

    # Modern TLS configuration (TLS 1.2 & TLS 1.3 only, strong ciphers)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Defeat Information Disclosure & Server Fingerprinting (CWE-200)
    server_tokens off;
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;

    # HTTP Strict Transport Security (HSTS) - 1 Year with Subdomains & Preload
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Content-Security-Policy (CSP) - Mitigate Cross-Site Scripting (XSS / CWE-79)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    # Clickjacking Protection (CWE-1021)
    add_header X-Frame-Options "DENY" always;

    # MIME-Sniffing Prevention (CWE-79)
    add_header X-Content-Type-Options "nosniff" always;

    # Referrer Policy (Privacy & Data Leakage Prevention)
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Permissions-Policy (Hardware & Sensor Lockdown)
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;

    # Cross-Origin Isolation Policies
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    location / {{
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""


def generate_apache_hardening(target: str = "example.com") -> str:
    """Generate production-ready Apache (.htaccess / httpd.conf) security snippet."""
    return f"""# ==============================================================================
# AEGIS-AI Automated Apache Security Hardening (.htaccess / httpd.conf)
# Target: {target}
# ==============================================================================

# 1. Suppress Server Identification Banners
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# 2. Defensive Security Headers (mod_headers)
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';"
    Header unset X-Powered-By
    Header unset Server
</IfModule>

# 3. Modern SSL/TLS Hardening (mod_ssl)
<IfModule mod_ssl.c>
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128
    SSLHonorCipherOrder on
</IfModule>
"""


def generate_caddy_hardening(target: str = "example.com") -> str:
    """Generate modern Caddyfile configuration with automatic TLS."""
    return f"""# ==============================================================================
# AEGIS-AI Automated Caddyfile Configuration
# Target: {target}
# ==============================================================================

{target} {{
    # Automatic TLS with modern ciphers
    tls internal

    # Strip origin fingerprint headers & add security headers
    header {{
        -Server
        -X-Powered-By

        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }}

    reverse_proxy 127.0.0.1:8000
}}
"""


def generate_express_helmet_hardening() -> str:
    """Generate Node.js Express Helmet middleware configuration."""
    return """// ==============================================================================
// AEGIS-AI Automated Node.js Express Perimeter Hardening (Helmet)
// ==============================================================================

const express = require('express');
const helmet = require('helmet');

const app = express();

// 1. Disable server fingerprinting
app.disable('x-powered-by');

// 2. Apply Helmet suite
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                frameAncestors: ["'none'"],
                baseUri: ["'self'"],
                formAction: ["'self'"],
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
        },
        frameguard: { action: 'deny' },
        noSniff: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    })
);

module.exports = app;
"""


def generate_flask_talisman_hardening() -> str:
    """Generate Python Flask-Talisman security headers configuration."""
    return """# ==============================================================================
# AEGIS-AI Automated Python Flask Perimeter Hardening (Flask-Talisman)
# ==============================================================================

from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Enforce HTTPS, HSTS, CSP, and Framing restrictions
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', '\'unsafe-inline\''],
    'style-src': ['\'self\'', '\'unsafe-inline\''],
    'img-src': ['\'self\'', 'data:', 'https:'],
    'frame-ancestors': '\'none\''
}

talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    content_security_policy=csp,
    frame_options='DENY',
    content_security_policy_nonce_in=['script-src']
)
"""
