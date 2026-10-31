# 🛡️ AEGIS-AI: Continuous Threat Exposure Management & Explainable RBVM Platform
## Comprehensive Project Architecture, Telemetry Specifications & Production Guide (v3.0)

---

## 1. Executive Summary & Operational Mission

**AEGIS-AI** is an operational, real-time **Continuous Threat Exposure Management (CTEM)** and **Explainable Risk-Based Vulnerability Management (RBVM)** platform engineered to eliminate enterprise alert fatigue, bridge live network reconnaissance with vulnerability databases, and pinpoint the single true weaponized attack path in modern cloud and perimeter environments.

### The Core Problem: The Alert Fatigue Crisis
In modern DevSecOps, traditional vulnerability scanners (Nessus, OpenVAS, Trivy, Snyk) dump thousands of Common Vulnerabilities and Exposures (CVEs) on engineering teams, ranked solely by **raw CVSS base scores**. This approach has two catastrophic failure modes:
1. **False Urgency & Wasted Cycles**: A **CVSS 9.8 (Critical)** vulnerability located in a deeply buried, internal test dependency with no open ports or network ingress triggers emergency pagers and halts deployment sprints, wasting an average of 14.5 engineering hours per sprint.
2. **Ignored Weaponized Threats**: A **CVSS 5.8 (Moderate)** flaw sitting directly on a publicly reachable, unauthenticated port with an exploit actively weaponized by adversary groups in the wild is buried on page 30 of a PDF report and left unpatched.

### The AEGIS Solution: Explainable Multi-Factor Prioritization
AEGIS-AI introduces a multi-dimensional triage model that cross-references:
* **Real Network Reachability**: Active TCP socket probing via Nmap (authorized targets only) and passive OSINT (DNS, TLS, HTTP headers) determines whether the affected code is actually exposed to external packet traffic.
* **Live Exploit Intelligence**: Direct REST integration with the official **FIRST.org EPSS (Exploit Prediction Scoring System)** API queries real-time probability of weaponization in the next 30 days.
* **Federal Threat Directives**: Real-time cross-referencing against the **CISA KEV (Known Exploited Vulnerabilities)** catalog (BOD 22-01).
* **Explainable AI (XAI)**: A transparent, mathematically bounded formula with dynamic weight sensitivity that outputs an intuitive 1.0 – 10.0 score alongside runtime AST execution traces (when source code is supplied).

**Result**: **66.7% of false-urgency noise is suppressed**, allowing security operations centers (SOCs) to focus exclusively on real-world exploitable exposures.

---

## 2. End-to-End System Architecture

```mermaid
flowchart TD
    subgraph Target["1. Target Ingress & Safety Gate"]
        T[Target Input / URL] --> V[Input Validation & SSRF Guard\nRFC 1123 & Private IP Filter]
        V --> G{Authorization Gate}
        G -->|Unverified Public Target| P[Passive OSINT Pipeline\nDNS, TLS, Headers, CT Logs]
        G -->|Verified Domain / Allowlist| A[Verified Active Scan\nNmap TCP & Service Discovery]
    end

    subgraph Intel["2. Threat Intelligence & Correlation Pipeline"]
        P & A --> C[Perimeter Evidence Synthesis]
        C --> OSV[Google OSV API & NVD CPE]
        C --> EPSS[FIRST.org EPSS Exploit Probability]
        C --> KEV[CISA KEV Catalog BOD 22-01]
    end

    subgraph Engine["3. Contextual RBVM & Analysis"]
        OSV & EPSS & KEV --> Prioritize[Multi-Factor Contextual Risk Scoring\nCVSS + EPSS + Network Exposure + Criticality]
        Prioritize --> Compliance[Multi-Framework Compliance Scoring\nNIST CSF 2.0, PCI-DSS 4.0, ISO 27001, SOC 2]
        Prioritize --> Remediate[Automated Remediation Generator\nNginx, Apache, Caddy, Helmet, WAF Rules]
    end

    subgraph UI["4. Cyber SOC Dashboard & Copilot"]
        Prioritize --> Web[Modular Cyber SOC Dashboard\n3D Threat Globe, Exposure Matrix, Radar]
        Prioritize --> Copilot[Aegis AI Copilot\nMulti-Provider LLM + Grounding Guardrail]
        Prioritize --> Exports[Multi-Format Export Engine\nHTML CISO Report, CSV, CycloneDX SBOM, SIEM CEF/ECS]
    end
```

---

## 3. Mathematical Prioritization Model (Explainable AI)

The core prioritization engine computes the **Contextual Risk Score ($R$)** bounded within the domain $[1.0, 10.0]$:

$$R = \min\left(10.0, \max\left(1.0, (\alpha \cdot S_{\text{CVSS}}) + (\beta \cdot S_{\text{EPSS}}) + (\gamma \cdot S_{\text{Exposure}}) + (\delta \cdot S_{\text{Crit}})\right)\right)$$

### Default Balanced Weight Distribution:
$$\alpha = 0.35, \quad \beta = 0.30, \quad \gamma = 0.20, \quad \delta = 0.15 \quad \left(\sum = 1.00\right)$$

### Vector Definitions:
1. **$S_{\text{CVSS}}$ (Base Severity Vector, Scale $0.0 - 10.0$)**:
   Direct base CVSS v3 score from NVD / OSV advisories.

2. **$S_{\text{EPSS}}$ (Exploit Prediction Scoring System, Scale $0.0 - 10.0$)**:
   Derived directly from FIRST.org live probability:
   $$S_{\text{EPSS}} = \min(10.0, \text{EPSS} \times 10.0)$$

3. **$S_{\text{Exposure}}$ (Environmental Network Exposure Vector, Scale $0.0 - 10.0$)**:
   Evaluated dynamically against verified scan state:
   - **$8.5 - 10.0$**: Listening open port directly exposed on public network without WAF protection.
   - **$6.0 - 8.4$**: Listening open port fronted by Cloudflare or edge WAF reverse proxy.
   - **$2.5 - 5.0$**: Missing security hardening header or unencrypted HTTP transport.
   - **$1.0 - 2.4$**: Internal or secondary dependency with no listening ingress socket.

4. **$S_{\text{Crit}}$ (Asset Criticality Factor, Scale $0.0 - 10.0$)**:
   Calibrated to the crown-jewel classification of the affected infrastructure node (Default $= 7.5$).

### Priority Tier Classification:
* **P1 Critical ($R \ge 7.5$)**: Direct remote exploitability on listening ingress with active weaponization. Requires immediate patch or WAF lockdown.
* **P2 High ($6.0 \le R < 7.5$)**: Reachable on listening network socket with moderate weaponization probability.
* **P3 Medium ($4.0 \le R < 6.0$)**: Secondary exposure or hardening deficiency.
* **P4 Low ($R < 4.0$)**: Internal, unexposed dependency with no network route. Alert suppressed.

---

## 4. Key Visual Capabilities & Intelligence Modules

### 4.1. 🎯 Threat Exposure Matrix (4-Quadrant RBVM Bubble Plot)
Located on the Executive Dashboard:
* **X-Axis**: FIRST.org EPSS Exploit Weaponization Likelihood ($0\% \to 100\%$).
* **Y-Axis**: Base CVSS Severity Score ($0.0 \to 10.0$).
* **Bubble Size**: Proportional to **Contextual Risk Score** ($14\text{px}$ for critical weaponized exposures, $6\text{px}$ for suppressed internal items).
* **The 4 Operational Quadrants**:
  1. 🔴 **Q1: Active Attack Zone** *(High CVSS + High EPSS + Port Reachable)*: Immediate threat actor target.
  2. 🟡 **Q2: Theoretical Noise** *(High CVSS, but low EPSS or closed port)*: Where legacy tools panic; AEGIS de-prioritizes.
  3. 🟠 **Q3: Opportunistic Threat** *(Moderate CVSS, active weaponization code)*.
  4. 🟢 **Q4: Routine Hygiene** *(Low CVSS, low EPSS)*.

### 4.2. 🕸️ Multi-Vector Attack Radar (5-Axis Spider Chart)
A dual-polygon overlay comparing:
* **Dashed Slate Outline**: Traditional Scanner perspective (blind CVSS over-indexing).
* **Glowing Cyan/Rose Polygon**: AEGIS Contextual RBVM Score incorporating reachability, EPSS, and KEV threat intelligence.
* Supported by an interactive **Plain-English Explainer** translating metrics into conversational executive summaries.

### 4.3. 🌐 Universal Online Web Assessor (`scanner_online.py`)
Provides non-intrusive external perimeter auditing for **any internet domain or URL**:
* **SSL/TLS Telemetry**: Protocol verification (TLSv1.3/TLSv1.2), cipher suite rating, certificate lifespan.
* **HTTP Security Headers**: Automated checks for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
* **Infrastructure Intelligence**: Cloudflare / CDN reverse-proxy detection, Web Server fingerprinting, Geo-IP lookup, ASN routing, and round-trip ping latency.
* **Automated Posture Scoring**: Computes a dynamic letter grade ($A+$ to $F$) with point-deduction rationales.

### 4.4. 🤖 Aegis AI Copilot with Grounding Guardrail
Context-aware Blue-Team SOC Assistant:
* **Multi-Provider Architecture**: Anthropic Claude, Google Gemini, AWS Bedrock Converse, Local Ollama, and deterministic heuristic fallback.
* **Defensive Anti-Exploit Gate**: Hard refusal to generate offensive exploit payloads or attack scripts.
* **CVE Grounding Verification**: Enforces that all cited CVE IDs exist in the verified target telemetry, attaching a grounding notice for any unverified references.

---

## 5. Directory & File Manifest

| Path | Purpose & Description |
| :--- | :--- |
| **`app.py`** | Flask REST API controller serving web interface, multi-stage scans, and copilot endpoints. |
| **`security.py`** | Security gate, SSRF protection, target input validation, and sliding-window rate limiting. |
| **`config.py`** | Central configuration loader managing environment variables, Vercel detection, and ports. |
| **`storage.py`** | Storage layer with `/tmp` file backend on Vercel, memory fallback, run history, and diffing. |
| **`ast_analyzer.py`** | Abstract Syntax Tree source code reachability engine for Python and JavaScript. |
| **`discovery/`** | Passive OSINT (DNS, TLS, Headers, CT logs) and authorized active port scanning modules. |
| **`correlation/`** | NVD/OSV lookups, CISA KEV sync, EPSS enrichment, MITRE ATT&CK mapping, and compliance scoring. |
| **`remediation/`** | Production hardening generators for Nginx, Apache, Caddy, Helmet, Talisman, and WAF rules. |
| **`ai/`** | Multi-provider LLM Copilot interface, anti-exploit guardrails, and rank comparison engine. |
| **`verification/`** | Cryptographic domain ownership verification via DNS TXT and HTTP token challenge. |
| **`static/`** | Modular CSS (`styles.css`), JS modules (`app.js`, `globe.js`, `charts.js`, etc.), and vendor libraries. |
| **`templates/`** | Clean, accessible dashboard HTML with skip link, modal dialogs, and terminal console. |
| **`tests/`** | Automated test suite (59 unit/integration tests) and OWASP Juice Shop validation benchmark. |

---

## 6. Execution & Verification Guide

### Step 1: Environment Setup
```powershell
# Clone the repository
git clone https://github.com/ViditSinghal-18/AEGIS-AI.git
cd AEGIS-AI

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Run Automated Tests & Validation Benchmark
```powershell
# Run 59 automated unit and integration tests
python -m pytest tests/ -v

# Run OWASP Juice Shop benchmark evaluation
python tests/validate.py
```

### Step 3: Launch the Cyber SOC Portal
```powershell
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.
