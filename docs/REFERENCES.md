# Academic & Research References (AEGIS-AI)

> **Notice:** The citations below reflect research concepts, algorithms, and methodologies that inspired components of AEGIS-AI.
> **Flag:** Verify before publishing (formal venue metadata, DOIs, and pagination should be verified against official publisher records).

---

## Phase 1: Scientifically Defensible Scoring & Risk Quantification

1. **Bozorgi et al., 2010**
   * *Citation:* Inspired by Bozorgi, M., Saul, L. K., Savage, S., & Voelker, G. M. "Beyond Heuristics: Learning to Classify Vulnerabilities and Predict Exploits." In *Proceedings of the 16th ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD)*, 2010.
   * *Usage in AEGIS:* Informs our empirical calibration methodology (`scoring/calibrate_weights.py`) that uses historical CVE telemetry and exploit labels to learn feature weights rather than relying on uncalibrated heuristic guesses.

2. **Jacobs et al., 2021 (FIRST EPSS)**
   * *Citation:* Inspired by Jacobs, J., Romanosky, S., Edwards, B., & Roytman, M. "Exploit Prediction Scoring System (EPSS)." *ACM Transactions on Privacy and Security / Digital Threats: Research and Practice*, 2021.
   * *Usage in AEGIS:* Direct integration with FIRST.org EPSS v1/v3 API data and time-based temporal evaluation splits for predictive exploitability modeling.

3. **Webber et al., 2010 (Rank-Biased Overlap)**
   * *Citation:* Inspired by Webber, W., Moffat, A., & Zobel, J. "A Similarity Measure for Indefinite Rankings." *ACM Transactions on Information Systems (TOIS)*, 28(4), 2010.
   * *Usage in AEGIS:* Implemented in `scoring/ranking_metrics.py` as `rank_biased_overlap()` (RBO@k) alongside Kendall $\tau$ and Spearman $\rho$ to quantify top-weighted agreement between deterministic and AI-assisted prioritization rankings.

4. **Spring et al., 2019 / CISA SSVC**
   * *Citation:* Inspired by Spring, J., Hatlebrekke, O., & Houle, K. "Prioritizing Vulnerability Response with a Stakeholder-Specific Vulnerability Categorization (SSVC)." *Carnegie Mellon University Software Engineering Institute (CMU/SEI-2019-TR-005)*, 2019.
   * *Usage in AEGIS:* Implemented in `scoring/ssvc.py` to produce a 4-tier actionable operational decision (`Track`, `Track*`, `Attend`, `Act`) derived from active exploitation, network exposure, automatability, and mission criticality.

5. **Angelopoulos & Bates, 2021 (Conformal Prediction / Uncertainty)**
   * *Citation:* Inspired by Angelopoulos, A. N., & Bates, S. "A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification." *arXiv preprint arXiv:2107.07511*, 2021.
   * *Usage in AEGIS:* Informs the residual dispersion and uncertainty interval calculation (`scoring/uncertainty.py`), outputting `risk_interval_90` around point scores with explicit penalties for banner-only matching, advisory divergence, and stale telemetry.

6. **Open FAIR & Hubbard / Seiersen, 2016**
   * *Citation:* Inspired by The Open Group. "Open FAIR Risk Taxonomy Standard (O-RT)." The Open Group Standard, 2013; and Hubbard, D. W., & Seiersen, R. "How to Measure Anything in Cybersecurity Risk." John Wiley & Sons, 2016.
   * *Usage in AEGIS:* Implemented in `scoring/fair_loss.py` via seeded Monte Carlo simulation producing Annual Loss Expectancy (ALE) distributions with a 90% confidence interval, calibrated to asset criticality and user-defined financial loss parameters.

---

## Phase 2: Advisory Consistency & Reachability

7. **Dong et al., 2019 (Advisory Consistency)**
   * *Citation:* Inspired by Dong, Y., Guo, W., Chen, X., & Liu, P. "Towards the Detection of Inconsistencies in Public Vulnerability Repositories." In *USENIX Security Symposium*, 2019.
   * *Usage in AEGIS:* Cross-verification of vulnerability metadata between NVD and Google OSV to attach confidence metrics.

8. **Ponta et al., 2018 (Eclipse Steady)**
   * *Citation:* Inspired by Ponta, S. E., Plate, H., & Sabetta, A. "Beyond Metadata: Code-Centric and Usage-Based Analysis of Known Vulnerabilities in Open-Source Software." In *IEEE International Conference on Software Maintenance and Evolution (ICSME)*, 2018.
   * *Usage in AEGIS:* Function-level AST call graph reachability matching specific vulnerable symbols in source code.

---

## Phase 3: Attack-Path Analysis

9. **Poolsappasit et al., 2012 (Bayesian Attack Graphs)**
   * *Citation:* Inspired by Poolsappasit, N., Dewri, R., & Ray, I. "Dynamic Security Risk Management Using Bayesian Attack Graphs." *IEEE Transactions on Dependable and Secure Computing (TDSC)*, 9(1), 2012.
   * *Usage in AEGIS:* Multi-path Bayesian compromise probability estimation and "what-if" patch simulation.

10. **Jha, Sheyner, & Wing, 2002 (Minimal Chokepoint Cut-Set)**
    * *Citation:* Inspired by Jha, S., Sheyner, O., & Wing, J. "Two Formal Analyses of Attack Graphs." In *IEEE Computer Security Foundations Workshop (CSFW)*, 2002.
    * *Usage in AEGIS:* Dijkstra shortest most-probable attack path ($-\log p$) and greedy minimal critical chokepoint cut-set computation.

---

## Phase 4: External Posture Intelligence

11. **Weichselbaum et al., 2016 / Roth et al., 2020 (CSP Grading)**
    * *Citation:* Inspired by Weichselbaum, L., Spagnuolo, M., Lekies, S., & Janc, A. "CSP Is Dead, Long Live CSP! On the Insecurity of Whitelists and the Future of Content Security Policy." In *ACM CCS*, 2016; and Roth, S., et al. "Complex Security Policies in the Wild." In *USENIX Security*, 2020.
    * *Usage in AEGIS:* AST parsing and defensive grading of Content-Security-Policy headers.

12. **Durumeric et al., 2015 (Email Security)**
    * *Citation:* Inspired by Durumeric, Z., et al. "Neither Snow Nor Rain Nor MITM... An Empirical Analysis of Email Delivery Security." In *ACM Internet Measurement Conference (IMC)*, 2015.
    * *Usage in AEGIS:* DMARC, MTA-STS, and TLS-RPT passive validation.

13. **Liu et al., 2016 / Borgolte et al., 2018 (Subdomain Takeover)**
    * *Citation:* Inspired by Liu, D., et al. "All Your DNS Records Point to Us: Understanding the Security Implications of Dangling DNS Records." In *ACM CCS*, 2016; and Borgolte, K., et al. "Cloud Strife: Analysis of Other People's Everyday Data in Third-Party Clouds." In *USENIX Security*, 2018.
    * *Usage in AEGIS:* CNAME dangling pointer resolution against fingerprint signatures.

14. **Meli et al., 2019 (Exposed Secrets)**
    * *Citation:* Inspired by Meli, M. R., McNiece, M. R., & Reaves, B. "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories." In *NDSS*, 2019.
    * *Usage in AEGIS:* High-entropy exposed secret classification and masking.

15. **Liu et al., 2015 (Breach-Propensity Heuristic)**
    * *Citation:* Inspired by Liu, Y., et al. "Cloudy with a Chance of Breach: Forecasting Cyber Security Incidents." In *USENIX Security*, 2015.
    * *Usage in AEGIS:* Heuristic external posture aggregation index.

---

## Phase 5 & 6: Copilot Trustworthiness & Temporal Dynamics

16. **Gao et al., 2023 (ALCE) & Lewis et al., 2020 (RAG Grounding)**
    * *Citation:* Inspired by Gao, T., et al. "Enabling Large Language Models to Generate Text with Citations." In *EMNLP*, 2023; and Lewis, P., et al. "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." In *NeurIPS*, 2020.
    * *Usage in AEGIS:* Claim-level citation extraction and entailment verification.

17. **Kuppa et al., 2021 (ATT&CK Mapping)**
    * *Citation:* Inspired by Kuppa, A., et al. "Multi-label Classification of Cyber Threat Intelligence using Transformer and Baseline Models." In *IEEE BigData*, 2021.
    * *Usage in AEGIS:* Machine-learned vs rule-based ATT&CK classification.

18. **Li & Paxson, 2017 (Vulnerability Lifetime Analytics)**
    * *Citation:* Inspired by Li, F., & Paxson, V. "A Large-Scale Empirical Study of Anonymity and Patching in Software Ecosystems." In *IEEE S&P*, 2017.
    * *Usage in AEGIS:* Kaplan–Meier patch-survival analytics, MTTR metrics, and SLA breach probability estimation.

19. **Page, 1954 / Adams & MacKay, 2007 (CUSUM & Change-Point Drift Detection)**
    * *Citation:* Inspired by Page, E. S. "Continuous Inspection Schemes." *Biometrika*, 41(1/2), 1954; and Adams, R. P., & MacKay, D. J. "Bayesian Online Changepoint Detection." *arXiv preprint arXiv:0710.3742*, 2007.
    * *Usage in AEGIS:* Statistical cumulative sum (CUSUM) drift detection and change-point analysis on longitudinal exposure scores.
