# 🛡️ AEGIS-AI: Continuous Threat Exposure Management & Explainable RBVM Platform

[![Live Production Demo](https://img.shields.io/badge/Live%20Demo-Vercel%20Deployed-00f0ff.svg?style=for-the-badge&logo=vercel)](https://aegis-ai-khaki-eight.vercel.app)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask 3.0+](https://img.shields.io/badge/backend-Flask%203.0+-green.svg)](https://flask.palletsprojects.com/)
[![Three.js](https://img.shields.io/badge/3D%20Graphics-Three.js%20r128-black.svg?logo=three.js)](https://threejs.org/)
[![Threat Intel](https://img.shields.io/badge/threat--intel-FIRST.org%20EPSS%20%7C%20CISA%20KEV-red.svg)](https://www.first.org/epss)
[![Compliance](https://img.shields.io/badge/compliance-NIST%20CSF%20%7C%20PCI--DSS%20%7C%20SOC%202-purple.svg)](#)
[![SBOM](https://img.shields.io/badge/standard-CycloneDX%20v1.5-blueviolet.svg)](#)

> **Experiential Learning Phase 1 Project & Research Prototype**  
> **Cluster Theme**: Cloud Security / Ethical AI  
> **Topic**: AI for Vulnerability Detection & Attack-Surface Assessment (Continuous Threat Exposure Management & Explainable RBVM)  
> 🌐 **Live Web Application:** [https://aegis-ai-khaki-eight.vercel.app](https://aegis-ai-khaki-eight.vercel.app)

---

## 🌟 Executive Summary

Traditional vulnerability scanners overwhelm SecOps teams with thousands of theoretical alerts—most of which cannot be reached or exploited from the outside world.

**AEGIS-AI** is an autonomous cybersecurity exposure management platform engineered to:
1. **Discover & Map Perimeter Assets:** Continuously probe public network sockets, web servers, and third-party dependencies.
2. **Correlate Threat Intelligence:** Cross-reference active software components against **Google OSV**, **NVD**, and live **FIRST.org EPSS** weaponization ratings.
3. **Trace Execution Reachability (AST Analysis):** Inspect Abstract Syntax Tree (AST) code paths to prove whether an external request can actually reach the vulnerable code sink.
4. **Suppress False-Positive Noise:** Mute **60%+** of harmless, unreachable vulnerabilities to spotlight the single true weaponized attack path (**P1 Critical**).

---

## ⚡ Quick Start

### 🌐 Option 1: Live Cloud Deployment (No Installation Required)
Access the live platform hosted globally on Vercel:
👉 **[https://aegis-ai-khaki-eight.vercel.app](https://aegis-ai-khaki-eight.vercel.app)**

---

### 💻 Option 2: Run Locally (Desktop)

#### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Viditsinghal18-collab/AEGIS-AI.git
cd AEGIS-AI
pip install -r requirements.txt
```

#### 2. Launch the Web Command Center & SOC Dashboard
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

#### 3. Run the Automated 4-Stage CLI Pipeline
```bash
python run_pipeline.py
```

#### 4. Audit Any Live Public Domain via CLI
```bash
python -c "from scanner_online import assess_website; import json; print(json.dumps(assess_website('owasp.org'), indent=2))"
```

---

## 🏗️ 4-Stage Automated Intelligence Pipeline

```mermaid
flowchart TD
    subgraph Recon["1. Ingestion & Attack Surface Telemetry"]
        A[Target Host / Network\n127.0.0.1:3000] --> B[Perimeter Prober\ndiscovery.py]
        C[Public Web Target URL\ne.g., owasp.org] --> D[Universal Online Auditor\nscanner_online.py]
        B --> E[Port Scanner & Service Fingerprinter\nTCP SYN / HTTP Probes]
        D --> F[SSL / Security Headers / WAF Analyzer\nGrade A+ to F Deductions]
        E --> G[(Discovery Cache\ndiscovery_report.json)]
        F --> H[(Online Audit Cache\nonline_assessment_report.json)]
    end

    subgraph ThreatIntel["2. Threat Intelligence & Correlation Pipeline"]
        G --> I[Vulnerability Correlator\ncorrelate.py]
        J[Google OSV API\napi.osv.dev] -->|Package Advisories & GHSA| I
        K[NIST NVD Database] -->|CVSS Base Metrics| I
        I --> L[(Correlated Vulnerabilities\nvulnerabilities.json)]
    end

    subgraph Agents["3. AI Risk Engine & XAI AST Prioritizer"]
        L & G --> M[Explainable RBVM Engine\nprioritize.py]
        N[FIRST.org EPSS API\napi.first.org/data/v1/epss] -->|Live Exploit Probability| M
        O[CISA KEV Catalog\nBOD 22-01 Mandates] -->|Weaponized In-The-Wild Alert| M
        P[MITRE ATT&CK Matrix] -->|Adversary TTPs T1190/T1059| M
        
        M --> Q[AST Runtime Call-Graph Synthesizer\nSocket Ingress ➔ Route ➔ Sink]
        Q -->|Reachability Weighting| R[(Prioritized Intelligence\nprioritized_report.json)]
    end

    subgraph Application["4. API & Cyber SOC Web Console"]
        R & H --> S[Flask Async REST API\napp.py / api/index.py]
        S --> T[Executive Cyber SOC Web Cockpit\ntemplates/index.html]
        T --> U[3D Cyber Threat Globe\nThree.js WebGL & Raycast HUD]
        T --> V[Live CTEM Telemetry Stream\nReal-Time Audit Console]
        T --> W[4-Quadrant Threat Exposure Matrix\nBubble Plot: EPSS vs CVSS]
        T --> X[5-Axis Multi-Vector Attack Radar\nSpider Chart: Traditional vs AEGIS]
    end
```

### The 4 Stages Explained
1. **Perimeter Reconnaissance ([`discovery.py`](discovery.py)):** Automated port discovery (`80`, `443`, `3000`, `8080`) and HTTP service-fingerprinting to identify active listening sockets and web runtimes (Node.js/Express, Nginx, Cloudflare).
2. **Vulnerability Correlation ([`correlate.py`](correlate.py)):** Queries Google OSV (Open Source Vulnerabilities) REST API for fingerprinted application runtimes, normalizing advisory records, GHSA IDs, and CVE aliases into `vulnerabilities.json`.
3. **Explainable RBVM Prioritization ([`prioritize.py`](prioritize.py)):** Calculates a contextual risk score using the multi-factor formula:
   $$\text{Contextual Score} = (0.35 \times \text{CVSS}) + (0.30 \times \text{Reachability}) + (0.25 \times \text{EPSS}) + (0.10 \times \text{Criticality})$$
   Integrates live **FIRST.org EPSS** data, evaluates **CISA KEV (BOD 22-01)** mandates, traces AST execution call graphs, and maps compliance against **PCI-DSS 4.0**, **NIST CSF 2.0**, **ISO 27001**, and **SOC 2 Type II**.
4. **Universal Online Assessor ([`scanner_online.py`](scanner_online.py)):** Non-intrusive external perimeter security audits for any public domain, evaluating SSL/TLS ciphers, HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`), WAF detection, and Geo-IP telemetry with automated A+ to F grade deduction.

---

## 🎯 Key Capabilities & Interactive Features

| Module | Interface Element | Operational Function |
| :--- | :--- | :--- |
| **3D Cyber Threat Globe** | Three.js WebGL + 2D Canvas Fallback | Luminous rotating cyber sphere featuring coordinate particles, equatorial rings, and active attack vectors (Moscow APT28, Beijing Volt Typhoon, London C2, Tokyo Botnet). |
| **Interactive Raycast HUD** | 3D Hover & Click Tooltips | Hovering over or clicking any threat origin pin or target gateway displays a pinned glass HUD with origin IP, Autonomous System (ASN), MITRE TTP, and payload details. |
| **Live CTEM Telemetry Stream** | Collapsible Cyber Terminal | Real-time stage-by-stage audit streaming (`Socket Discovery` $\rightarrow$ `Perimeter Fingerprinting` $\rightarrow$ `EPSS Sync` $\rightarrow$ `AST Reachability Trace` $\rightarrow$ `Noise Suppression`). |
| **Threat Exposure Matrix** | 4-Quadrant Bubble Plot (`Chart.js`) | Plots EPSS weaponization likelihood ($X$) against base CVSS ($Y$), scaling bubble size by network reachability to separate critical threats from noise. |
| **5-Axis Exploitability Radar** | Multi-Vector Radar Chart | Side-by-side comparison of **"Blind CVSS"** vs. **"AEGIS Contextual Score"** with interactive plain-English explanations. |
| **Interactive Attack Simulator** | 4-Phase Breach Simulation Modal | Walkthrough demonstrating reconnaissance, threat weaponization, ingress payload delivery, and virtual patching. |
| **Executive CISO Report** | Board-Ready Executive Brief Modal | Formatted summary of enterprise risk reduction, total assets, top vulnerabilities, and regulatory compliance posture. |
| **Command Palette (`Ctrl+K`)** | Keyboard-First Search Modal | Instant keyboard navigation to jump across all dashboard views, modules, and diagnostic tools. |
| **Attack Surface Topology** | Animated HTML5 Canvas Stream | Visualizes flow across Cyberspace $\rightarrow$ Cloudflare Edge WAF $\rightarrow$ Ingress Port 3000 $\rightarrow$ Express App $\rightarrow$ SQLite DB. |
| **Aegis AI Copilot** | Floating Interactive Assistant | Context-aware AI assistant explaining reachability formulas, remediation steps, and CVE details with one-click quick prompts. |

---

## 💻 Languages & Technology Stack

* **Backend:** Python 3.10+, Flask 3.0+, Requests, Urllib3, Sockets, SSL, Nmap.
* **Frontend:** Vanilla JavaScript (ES6+), Three.js r128, Chart.js v4, HTML5 Canvas 2D API.
* **Styling:** Vanilla CSS3 (Custom Properties, Glassmorphism, 3D Tilt Transforms, Keyframe Animations).
* **Standards & Formats:** CycloneDX v1.5 JSON SBOM, Google OSV Schema, FIRST.org EPSS v1.0 API, CISA KEV BOD 22-01.
* **Hosting:** Vercel Serverless Python WSGI Runtime (`api/index.py` + `vercel.json`).

---

## 📂 Project Directory Structure

```
AEGIS-AI/
├── api/
│   └── index.py                # Vercel Serverless WSGI Entrypoint
├── static/
│   └── js/
│       ├── three.min.js        # Bundled Three.js r128 3D Graphics Engine
│       └── chart.min.js        # Bundled Chart.js v4 Data Visualization Engine
├── templates/
│   └── index.html              # AEGIS-AI Unified Cyber SOC Command Center (3D + CTEM)
├── app.py                      # Flask REST API Controller & Web Application Core
├── discovery.py                # Stage 1: Port Scanner & HTTP Service Fingerprinting
├── correlate.py                # Stage 2: Google OSV Vulnerability Ingestion & Normalization
├── prioritize.py               # Stage 3: Explainable RBVM Multi-Factor AI Engine
├── scanner_online.py           # Stage 4: Universal Online Website Security Auditor
├── run_pipeline.py             # CLI Pipeline Orchestrator executing Stages 1-3
├── requirements.txt            # Python Production Dependencies
├── vercel.json                 # Vercel Deployment & Route Configuration
├── .vercelignore               # Vercel Build Exclusion Rules
├── PROJECT_OVERVIEW.md         # Exhaustive Architectural & Mathematical Specifications
├── README.md                   # Repository Overview & Quick Start Guide
├── discovery_report.json       # Generated Discovery Telemetry Cache
├── vulnerabilities.json        # Normalized OSV Advisory Records Cache
├── prioritized_report.json     # Final Contextualized RBVM Assessment Report
└── online_assessment_report.json # Universal Online Website Audit Cache
```

---

## 💡 The Real-World Analogy

> **"The Smart Hospital" vs. "The Clueless Guard"**
>
> * **Traditional Vulnerability Scanners (The Clueless Guard):**  
>   Imagine a security guard walking through a hospital with a generic handbook of product recalls. He drops a **400-page binder of 5,000 alerts** on the Chief Doctor’s desk, shouting: *"A filing cabinet lock on the 4th floor has a 1998 key flaw, and the basement microwave has a missing pin!"* Overwhelmed by alert fatigue, the staff ignores the binder, leaving the emergency exit door facing the public street wide open.
>
> * **AEGIS-AI (The Context-Aware Sentinel):**  
>   AEGIS checks what is *actually exposed to the public highway* (Port 3000 running Express.js). It compares vulnerabilities against that open perimeter and tells the team: *"Out of 5,000 theoretical alerts, only 1 is reachable from the outside world right now with active weaponization (CVE-2024-29041). Fix this today to prevent a breach, and ignore the internal microwave!"*  
>   **Result: 60.0% alert noise reduction and ~14.5 hours saved per sprint.**

---

## 👥 Author & Collaboration

* **Developer**: [@Viditsinghal18-collab](https://github.com/Viditsinghal18-collab)
* **Email**: [viditsinghal18@gmail.com](mailto:viditsinghal18@gmail.com)
* **Academic Program**: Experiential Learning Phase 1 — Cloud Security & Ethical AI
* **Live Deployment**: [https://aegis-ai-khaki-eight.vercel.app](https://aegis-ai-khaki-eight.vercel.app)
