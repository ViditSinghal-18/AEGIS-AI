"""
Learned CVE & Finding to MITRE ATT&CK Technique Mapping Engine.

Inspired by:
    Kuppa, A., Grzonkowski, S., & Le-Khac, N. A.
    "Multi-label Classification of Cyber Threat Intelligence using Transformer and Baseline Models."
    In 2021 IEEE International Conference on Big Data (Big Data), pp. 4734-4743, 2021.

Trains a supervised TF-IDF + Linear Classifier baseline on curated cybersecurity
finding descriptions, advisory summaries, and MITRE technique definitions.
Compares against the deterministic rule-based mapper in correlation/mitre_attack.py.

NON-NEGOTIABLE AEGIS CONSTRAINTS:
- Keep rule-based mapper as the production default.
- Learned mapper is opt-in via AEGIS_MITRE_MAPPER=learned or config.
- Fully offline and deterministic with seeded RNG (random_state=42).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

logger = logging.getLogger(__name__)

# Curated reference training corpus mapping security descriptions to MITRE ATT&CK techniques
_TRAINING_CORPUS: List[Tuple[str, str]] = [
    # T1190: Exploit Public-Facing Application
    ("Remote code execution in Apache HTTP Server mod_proxy allows arbitrary code execution via crafted HTTP request", "T1190"),
    ("SQL injection vulnerability in public login portal allows unauthenticated database extraction", "T1190"),
    ("Buffer overflow in OpenSSL service allows remote unauthenticated memory corruption", "T1190"),
    ("Command injection in Nginx web gateway via URI parameter parsing flaw CVE-2021-23017", "T1190"),
    ("Unauthenticated path traversal vulnerability in web server allows reading arbitrary system files", "T1190"),
    ("Spring Framework RCE vulnerability allows remote threat actors to execute arbitrary code via HTTP POST", "T1190"),
    ("Open port running vulnerable Apache Tomcat server with default manager application", "T1190"),
    ("Log4j CVE-2021-44228 remote code execution in web application logging JNDI lookups", "T1190"),

    # T1596: Search Open Technical Databases (Reconnaissance)
    ("Subdomain discovery from public Certificate Transparency logs crt.sh and DNS records", "T1596"),
    ("Passive reconnaissance reveals DNS TXT and MX records pointing to legacy cloud mail providers", "T1596"),
    ("Historical DNS zone transfer records leaked on public threat intelligence feed", "T1596"),
    ("Certificate Transparency log enumeration mapped 14 internal staging hostnames", "T1596"),
    ("Passive OSINT search of technical certificate logs shows decommissioned staging endpoints", "T1596"),

    # T1595: Active Scanning (Port Scanning & Probing)
    ("Open TCP port 80 detected via active SYN probe scan", "T1595"),
    ("Active network scan identified open port 443 with TLS listener", "T1595"),
    ("Port scan probe identified open database listener on port 3306 MySQL", "T1595"),
    ("Nmap service probe detected open SSH daemon on port 22", "T1595"),
    ("Active SYN stealth scan identified open redis service on port 6379", "T1595"),

    # T1046: Network Service Discovery
    ("Server version disclosure: Apache/2.4.41 discloses exact software version in Server banner header", "T1046"),
    ("HTTP response header discloses X-Powered-By PHP/7.4.3 backend version details", "T1046"),
    ("Service version fingerprinting discovered OpenSSH 8.2p1 running on Debian Linux", "T1046"),
    ("Verbose HTTP error page exposes internal framework versions and file paths", "T1046"),
    ("Missing server_tokens off directive reveals nginx 1.18.0 server banner", "T1046"),

    # T1566.002: Phishing: Spearphishing Link / Spoofing
    ("Missing SPF Sender Policy Framework record allows unauthorized email spoofing", "T1566.002"),
    ("DMARC policy missing or set to p=none: domain susceptible to CEO fraud and spearphishing", "T1566.002"),
    ("Weak SPF qualifier ~all softfail permits spoofed email delivery into recipient mailboxes", "T1566.002"),
    ("Missing DMARC authentication policy allows attackers to spoof organizational identity in phishing campaigns", "T1566.002"),
    ("Insecure email transport lacks MTA-STS and TLS-RPT enforcement against SMTP MITM", "T1566.002"),

    # T1557: Adversary-in-the-Middle (MitM) / Weak Cryptography
    ("Weak TLS 1.0 or 1.1 enabled with deprecated CBC ciphers allows eavesdropping", "T1557"),
    ("Missing Strict-Transport-Security HSTS header allows SSL stripping downgrade attacks", "T1557"),
    ("Session cookie lacks Secure and HttpOnly flags allowing credential theft over plaintext HTTP", "T1557"),
    ("Self-signed or expired TLS certificate triggers browser warnings and risks man-in-the-middle interception", "T1557"),
    ("Unencrypted cleartext HTTP traffic allowed on port 80 without mandatory redirect to HTTPS", "T1557"),

    # T1189: Drive-by Compromise / Clickjacking / XSS Exposure
    ("Missing Content-Security-Policy CSP header allows client-side cross-site scripting script injection", "T1189"),
    ("Permissive CSP contains unsafe-inline without nonce allowing inline script execution", "T1189"),
    ("Missing X-Frame-Options header allows clickjacking UI redressing inside malicious iframes", "T1189"),
    ("CORS wildcard Access-Control-Allow-Origin: * exposes sensitive API endpoints to cross-origin abuse", "T1189"),
    ("Missing X-Content-Type-Options header allows MIME-type sniffing attacks in legacy browsers", "T1189"),

    # T1498: Network Denial of Service
    ("Critical remote denial of service vulnerability in HTTP request parser leads to daemon crash", "T1498"),
    ("Resource exhaustion flaw allows unauthenticated remote attacker to cause kernel panic", "T1498"),
    ("Slowloris vulnerability in web server worker pool allows connection exhaustion", "T1498"),
    ("Amplification denial of service vector identified in open recursive DNS service", "T1498"),

    # T1552: Unsecured Credentials / Exposed Secrets
    ("Exposed AWS Access Key ID AKIA found in public JavaScript bundle", "T1552"),
    ("Publicly accessible .git/HEAD directory exposes complete repository source and commit history", "T1552"),
    ("Exposed .env configuration file reveals database passwords and API tokens", "T1552"),
    ("Hardcoded GitHub personal access token ghp_ leaked in public static asset", "T1552"),

    # T1584: Compromise Infrastructure / Subdomain Takeover
    ("Dangling DNS CNAME points to unallocated Amazon S3 bucket allowing subdomain takeover", "T1584"),
    ("Subdomain points to unclaimed GitHub Pages endpoint allowing arbitrary content hosting", "T1584"),
    ("Orphaned CNAME record resolves to decommissioned Heroku application", "T1584"),
    ("Dangling DNS record points to unregistered Azure Web App service", "T1584"),
]


@dataclass
class LearnedMappingPrediction:
    """Prediction result from the learned classifier."""

    technique_id: str
    confidence: float
    features_used: str
    all_probabilities: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "confidence": round(self.confidence, 3),
            "features_used": self.features_used,
            "all_probabilities": {k: round(v, 3) for k, v in self.all_probabilities.items()},
        }


class LearnedAttackMapper:
    """Supervised TF-IDF + LogisticRegression baseline for mapping findings to MITRE ATT&CK techniques.

    Inspired by Kuppa et al. 2021.
    """

    def __init__(self, random_state: int = 42) -> None:
        self.random_state = random_state
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            max_features=600,
            sublinear_tf=True,
        )
        self.classifier = LogisticRegression(
            C=2.0,
            max_iter=300,
            random_state=self.random_state,
        )
        self._is_trained = False
        self._classes: List[str] = []
        self._train()

    def _train(self) -> None:
        """Fit vectorizer and classifier on the training corpus."""
        texts = [t[0] for t in _TRAINING_CORPUS]
        labels = [t[1] for t in _TRAINING_CORPUS]

        X = self.vectorizer.fit_transform(texts)
        self.classifier.fit(X, labels)
        self._classes = list(self.classifier.classes_)
        self._is_trained = True

    def predict(self, text_or_finding: Any) -> LearnedMappingPrediction:
        """Predict MITRE ATT&CK technique from raw text or finding dictionary."""
        if isinstance(text_or_finding, dict):
            # Extract combined features from finding
            title = text_or_finding.get("title") or ""
            desc = text_or_finding.get("description") or ""
            action = text_or_finding.get("suggested_action") or ""
            cves = " ".join(text_or_finding.get("related_cves") or [])
            source = text_or_finding.get("source") or ""
            query_text = f"{title} {desc} {action} {cves} {source}".strip()
        else:
            query_text = str(text_or_finding).strip()

        if not query_text:
            return LearnedMappingPrediction(
                technique_id="T1046",
                confidence=0.5,
                features_used="empty",
                all_probabilities={},
            )

        X_q = self.vectorizer.transform([query_text])
        probs = self.classifier.predict_proba(X_q)[0]
        best_idx = int(np.argmax(probs))
        best_technique = self._classes[best_idx]
        best_conf = float(probs[best_idx])

        all_probs = {cls_name: float(probs[i]) for i, cls_name in enumerate(self._classes)}

        return LearnedMappingPrediction(
            technique_id=best_technique,
            confidence=best_conf,
            features_used=query_text[:120],
            all_probabilities=all_probs,
        )

    def evaluate_against_rules(
        self,
        findings: List[Dict[str, Any]],
        rule_mapper_fn: Any = None,
    ) -> Dict[str, Any]:
        """Evaluate agreement between the learned classifier and the rule-based mapper.

        Inspired by Kuppa et al. 2021.
        """
        if rule_mapper_fn is None:
            from correlation.mitre_attack import map_finding_to_mitre
            rule_mapper_fn = map_finding_to_mitre

        y_true: List[str] = []
        y_pred: List[str] = []

        for f in findings:
            rule_res = rule_mapper_fn(f, mapper_mode="rule")
            rule_t = rule_res.get("technique_id")
            if rule_t:
                pred = self.predict(f)
                y_true.append(rule_t)
                y_pred.append(pred.technique_id)

        if not y_true:
            return {
                "evaluated_findings": 0,
                "agreement_rate": 1.0,
                "model_type": "TF-IDF + LogisticRegression (Kuppa et al. 2021)",
                "note": "No findings with matching rule techniques to compare against.",
            }

        agreement = accuracy_score(y_true, y_pred)
        return {
            "evaluated_findings": len(y_true),
            "agreement_rate": round(float(agreement), 4),
            "rule_labels": y_true,
            "predicted_labels": y_pred,
            "model_type": "TF-IDF + LogisticRegression (Kuppa et al. 2021)",
        }


# Singleton instance for efficient reuse
_INSTANCE: Optional[LearnedAttackMapper] = None


def get_learned_attack_mapper() -> LearnedAttackMapper:
    """Retrieve or initialize singleton LearnedAttackMapper."""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = LearnedAttackMapper(random_state=42)
    return _INSTANCE
