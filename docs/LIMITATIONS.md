# AEGIS-AI Operational Boundaries & System Limitations

This document provides transparent, honest disclosure of what AEGIS-AI can and cannot do, the structural boundaries of perimeter Risk-Based Vulnerability Management (RBVM), and technical platform constraints.

---

## 1. Code Reachability vs. Remote Network Exposure

- **Without Source Code Access:** Remote perimeter scans can ONLY observe network exposure (open ports, reachable HTTP services, missing security headers, TLS configuration, and public banners). When scanning a remote URL without source code, AEGIS-AI **honestly reports code reachability as `"unknown (no source provided)"`**.
- **With Source Code Access:** When provided with a local directory containing `requirements.txt`, `package.json`, and source files, AEGIS-AI parses the abstract syntax tree (`ast` in Python, regex/AST tokenization in JavaScript) to inspect whether imported vulnerable packages are invoked inside reachable HTTP route handlers or entry points.
- **Limitation:** AEGIS-AI does **not** claim to perform remote AST execution tracing over raw network packets.

---

## 2. Serverless Execution Constraints (Vercel)

- **Passive OSINT Only:** The Vercel deployment of AEGIS-AI operates strictly in **Passive OSINT Mode**.
- **No Nmap Binary:** Active TCP/UDP port probing (`nmap`) requires root socket capabilities and binary execution, neither of which exists in Vercel's serverless microVM environment.
- **Short Execution Timeouts:** Vercel functions have tight execution time limits (typically 10 to 60 seconds). All multi-stage scans are decomposed into fast discrete micro-stages (`/api/scan/dns`, `/tls`, `/headers`, `/ct`, `/intel`, `/prioritize`).
- **Ephemeral Filesystem:** The root filesystem on Vercel is strictly read-only. AEGIS routes runtime caches and reports to `/tmp/aegis_data` with an in-memory fallback. For durable enterprise scan history on Vercel, attach external Redis, Upstash, or Vercel KV via environment variables.

---

## 3. Third-Party Intelligence & Rate Limits

AEGIS-AI enriches findings against real, public cybersecurity datasets with local caching to protect rate quotas:

| Intelligence Source | Function | Rate Limit & Mitigation Strategy |
| :--- | :--- | :--- |
| **FIRST.org EPSS** | Exploit Prediction Scoring | Max 60 queries/min. AEGIS caches scores locally on disk for 24 hours. |
| **CISA KEV Catalog** | Known Exploited Vulnerabilities | Synced every 24 hours. Uses local catalog cache if GitHub/CISA API is unavailable. |
| **Google OSV / NVD** | Open Source Vulnerability queries | Cached per component/version. NVD requests throttled with backoff. |
| **Certificate Transparency** | Subdomain discovery via `crt.sh` | Free community API. Falls back to DNS SAN records if `crt.sh` times out. |
| **ip-api.com** | Geo-IP Telemetry | Free tier limited to 45 requests/min. Results cached per resolved IP. |

---

## 4. Passive OSINT vs. Dynamic Application Security Testing (DAST)

- **What AEGIS Observes:** Ingress network surface, public DNS records, TLS certificate hygiene, HTTP security headers, cookie flags, CORS policies, WAF/CDN presence, and correlated CVEs for exposed software banners.
- **What AEGIS Does NOT Do:**
  - **No Exploit Payload Delivery:** AEGIS strictly adheres to ethical scanning rules and does not deliver offensive payloads (e.g., SQL injection, SSTI, command injection, path traversal).
  - **No Authenticated Crawling:** AEGIS does not bypass authentication portals, perform session fuzzing, or inspect authenticated API routes behind login screens.
  - **No Client DOM Execution:** AEGIS does not run a headless browser engine; DOM-based XSS vulnerabilities requiring client-side script execution are out of scope.

---

## 5. Strict Anti-Exploitation Policy

AEGIS-AI is designed exclusively as a **Defensive Blue-Team SOC Assistant**.
- The AI Copilot incorporates hard guardrails that intercept and refuse requests to generate weaponized exploits, proof-of-concept scripts, Metasploit modules, or attack payloads.
- The platform exclusively generates defensive virtual patches, WAF rules, and server configuration hardening snippets.
