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

## 3. Alert Fatigue Reduction & Unified Scoring Weights

Standard vulnerability scanners rely exclusively on **raw CVSS base scores**, triggering alert fatigue by classifying non-exploitable or internal dependencies as urgent emergencies.

### Unified Scoring Formulation

$$\text{Priority} = w_{\text{CVSS}} \cdot S_{\text{CVSS}} + w_{\text{EPSS}} \cdot S_{\text{EPSS}} + w_{\text{Exposure}} \cdot S_{\text{Exposure}} + w_{\text{Crit}} \cdot S_{\text{Crit}}$$

Where $\sum w_i = 1.0$, and single source of truth is declared in `config.py` and `prioritize.py`.

### Production vs. Calibrated Weight Sets

| Weight Parameter | Default Production (`config.py`) | Calibrated (`reports/calibration_20261112.json`) | Calibration Rationale |
| :--- | :--- | :--- | :--- |
| **$w_{\text{CVSS}}$ (Severity)** | **0.35** | **0.172** | Down-weighted: CVSS over-predicts in-the-wild exploitation |
| **$w_{\text{EPSS}}$ (Exploitability)** | **0.30** | **0.507** | Up-weighted: EPSS strongly separates active exploitation |
| **$w_{\text{Exposure}}$ (Attack Surface)** | **0.20** | **0.190** | Empirical network ingress / WAF / perimeter reachability |
| **$w_{\text{Crit}}$ (Asset Impact)** | **0.15** | **0.131** | Business criticality and crown-jewel data sensitivity |
| **Weight Sum** | **1.000** | **1.000** | Normalized probability conservation |

### Calibration Benchmark Metrics (Temporal Split on CISA KEV)

From the temporal validation benchmark (`split_year = 2023`, $N = 300$, $N_{\text{pos}} = 86$):
- **Precision@10:** 100.0% (calibrated) vs. 100.0% (default)
- **Precision@25:** 100.0% (calibrated) vs. 100.0% (default)
- **Precision@50:** 100.0% (calibrated) vs. 100.0% (default)
- **Recall@50:** 58.14% (calibrated) vs. 58.14% (default)
- **Recall@100:** 98.84% (calibrated) vs. 98.84% (default)

### Alert Suppression Metrics (OWASP Juice Shop Testbed):
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
