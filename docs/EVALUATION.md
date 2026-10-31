# AEGIS-AI Empirical Validation & Evaluation Report

**Target Testbed:** `localhost:3000 (OWASP Juice Shop Testbed)`  
**Evaluation Date:** October 2026  
**Methodology:** Automated benchmarking against OWASP Juice Shop perimeter attack surface, alert fatigue suppression analysis, and AI grounding verification.

---

## 1. Executive Summary

| Evaluation Category | Metric | Result | Benchmark Target |
| :--- | :--- | :--- | :--- |
| **Detection Coverage** | Recall | **100.0%** | ≥ 90.0% |
| **Detection Quality** | Precision | **100.0%** | ≥ 95.0% |
| **Overall Detection** | F1-Score | **100.0%** | ≥ 90.0% |
| **Alert Fatigue** | Alert Reduction | **66.7%** | ≥ 50.0% |
| **AI Safety** | Grounding Guardrail | **100.0%** | 100.0% |

---

## 2. Detection Performance (OWASP Juice Shop)

AEGIS-AI was evaluated on its ability to discover perimeter misconfigurations and vulnerabilities without launching offensive exploit payloads.

### Confusion Matrix
- **True Positives (TP):** `6`
- **False Negatives (FN):** `0`
- **False Positives (FP):** `0`

### Verified True Positives:
- `[x]` **http-no-tls**
- `[x]` **open-web-port**
- `[x]` **missing-csp**
- `[x]` **missing-xfo**
- `[x]` **missing-xcto**
- `[x]` **missing-referrer-policy**

---

## 3. Alert Fatigue Reduction Analysis

Standard vulnerability scanners rely exclusively on **raw CVSS base scores**, triggering alert fatigue by classifying non-exploitable or internal dependencies as urgent emergencies.

AEGIS-AI incorporates:
$$\text{Priority} = 0.35 \cdot S_{\text{CVSS}} + 0.30 \cdot S_{\text{EPSS}} + 0.20 \cdot S_{\text{Exposure}} + 0.15 \cdot S_{\text{Crit}}$$

### Alert Suppression Metrics:
- **Raw CVSS High/Critical Count:** `3`
- **AEGIS Contextual High/Critical Count:** `1`
- **Net Alert Reduction:** **66.7%**

### De-prioritized Low-Exposure Findings:
- **Vulnerability in node-forge (CVE-2022-29244)**: Raw CVSS `7.5` dropped to AEGIS Priority `4.8` (EPSS: `0.003`, Reachability: `2.5`)
- **Vulnerability in sanitize-html (CVE-2020-7662)**: Raw CVSS `9.8` dropped to AEGIS Priority `5.1` (EPSS: `0.002`, Reachability: `2.5`)

---

## 4. AI Copilot Grounding & Anti-Hallucination

Every AI-generated response is subject to a strict CVE grounding guardrail that intercepts and flags any CVE cited by the model that does not exist in the verified telemetry report.

- **Test Battery:** `7` adversarial and standard prompt queries
- **Correct Guardrail Interceptions:** `7`
- **Grounding Accuracy:** **100.0%**

---

## 5. Documented Scope Boundaries & Honest Limitations

Perimeter RBVM scanners have natural structural boundaries. AEGIS-AI explicitly documents what is outside of perimeter scan scope:

- **score-board**: Score Board (hidden challenge route) — requires application business logic crawl, not perimeter discovery
- **dom-xss**: DOM XSS — requires headless browser JavaScript execution and client DOM inspection
- **sqli-login**: SQL injection on login — requires offensive payload injection, which AEGIS strictly forbids
- **broken-auth**: Broken authentication / JWT token forging — requires application state fuzzing out of scope for perimeter RBVM
