"""
Content Security Policy (CSP) Quality & Defense Grader.

Inspired by:
1. Weichselbaum, L., Spagnuolo, M., Lekies, S., & Janc, A. "CSP Is Dead, Long Live CSP!
   On the Insecurity of Whitelists and the Future of Content Security Policy."
   In Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security (CCS), 2016.
2. Roth, S., et al. "Complex Security Policies in the Wild."
   In USENIX Security Symposium, 2020.

Parses Content-Security-Policy headers into directive-source AST structures and evaluates:
- 'unsafe-inline' without nonces/hashes (XSS bypass)
- 'unsafe-eval' (DOM execution)
- Wildcard origins and insecure HTTP schemes in script-src
- 'data:' URIs in script-src
- Missing 'object-src' (Flash/plugin injection)
- Missing 'base-uri' (base tag injection)
- Missing 'frame-ancestors' (Clickjacking defense)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class CspGradeResult:
    """Evaluation result for an HTTP Content-Security-Policy header."""

    grade: str  # "A+", "A", "B", "C", "D", "F"
    score: int  # 0 to 100
    is_present: bool
    weaknesses: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    parsed_directives: Dict[str, List[str]] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_csp(csp_header: str) -> Dict[str, List[str]]:
    """Parse raw CSP header string into directive dictionary."""
    directives: Dict[str, List[str]] = {}
    if not csp_header or not csp_header.strip():
        return directives

    tokens = csp_header.split(";")
    for token in tokens:
        parts = token.strip().split()
        if not parts:
            continue
        d_name = parts[0].lower()
        d_sources = [s.strip() for s in parts[1:] if s.strip()]
        directives[d_name] = d_sources

    return directives


def grade_csp(csp_header: Optional[str]) -> CspGradeResult:
    """Assess Content-Security-Policy defense quality and assign an academic grade (0-100 / A-F).

    Inspired by Weichselbaum et al. 2016.
    """
    if not csp_header or not csp_header.strip():
        return CspGradeResult(
            grade="F",
            score=0,
            is_present=False,
            weaknesses=["Missing Content-Security-Policy header: Web application lacks defense-in-depth against XSS."],
            strengths=[],
            parsed_directives={},
            recommendations=[
                "Deploy a restrictive CSP, starting with: default-src 'self'; object-src 'none'; base-uri 'self';"
            ],
        )

    directives = parse_csp(csp_header)
    score = 100
    weaknesses: List[str] = []
    strengths: List[str] = []
    recommendations: List[str] = []

    # Identify primary script sources (script-src or default-src fallback)
    script_sources = directives.get("script-src", directives.get("default-src", []))
    script_lower = [s.lower() for s in script_sources]

    has_nonce = any(re.match(r"^'nonce-[A-Za-z0-9+/=]+'$", s, re.IGNORECASE) for s in script_sources)
    has_hash = any(re.match(r"^'(?:sha256|sha384|sha512)-[A-Za-z0-9+/=]+'$", s, re.IGNORECASE) for s in script_sources)

    # 1. 'unsafe-inline' check
    if "'unsafe-inline'" in script_lower:
        if has_nonce or has_hash:
            # Modern CSP2/3 browsers ignore 'unsafe-inline' when nonces/hashes are present (good fallback pattern)
            strengths.append("Nonces/hashes present alongside 'unsafe-inline' for backward compatibility.")
            score -= 5
        else:
            weaknesses.append("'unsafe-inline' enabled without cryptographic nonce/hash (allows arbitrary inline XSS).")
            score -= 30
            recommendations.append("Remove 'unsafe-inline' and use cryptographic nonces: script-src 'nonce-<random>'")
    elif has_nonce or has_hash:
        strengths.append("Strict cryptographic nonces or hashes enforced for scripts.")

    # 2. 'unsafe-eval' check
    if "'unsafe-eval'" in script_lower:
        weaknesses.append("'unsafe-eval' enabled (allows eval(), setTimeout(string), and DOM code execution).")
        score -= 15
        recommendations.append("Refactor application to eliminate eval() and remove 'unsafe-eval' from CSP.")

    # 3. Wildcard origins in script-src
    if "*" in script_lower or "http:" in script_lower or "https:" in script_lower:
        weaknesses.append("Wildcard host or plain scheme in script-src (allows loading scripts from untrusted domains).")
        score -= 25
        recommendations.append("Replace wildcard script origins with explicit domains or strict nonces.")

    # 4. 'data:' URI in script-src
    if "data:" in script_lower:
        weaknesses.append("'data:' URI scheme allowed in script-src (allows payload smuggling).")
        score -= 20
        recommendations.append("Disallow 'data:' in script-src directives.")

    # 5. object-src evaluation
    object_sources = directives.get("object-src", directives.get("default-src", []))
    object_lower = [s.lower() for s in object_sources]
    if "'none'" in object_lower:
        strengths.append("object-src set to 'none' (blocks legacy Flash/Java plugin execution).")
    else:
        weaknesses.append("object-src is not set to 'none' (risks plugin-based object injection).")
        score -= 15
        recommendations.append("Add directive: object-src 'none';")

    # 6. base-uri evaluation
    base_sources = directives.get("base-uri", [])
    base_lower = [s.lower() for s in base_sources]
    if "'none'" in base_lower or "'self'" in base_lower:
        strengths.append(f"base-uri restricted to {', '.join(base_sources)}.")
    else:
        weaknesses.append("base-uri is missing or unrestricted (allows base-tag injection to hijack relative URLs).")
        score -= 10
        recommendations.append("Add directive: base-uri 'self'; or base-uri 'none';")

    # 7. frame-ancestors evaluation
    if "frame-ancestors" in directives:
        strengths.append(f"frame-ancestors defined ({', '.join(directives['frame-ancestors'])}), mitigating clickjacking.")
    else:
        weaknesses.append("frame-ancestors directive missing (clickjacking defense left to legacy X-Frame-Options).")
        score -= 10
        recommendations.append("Add directive: frame-ancestors 'none'; or frame-ancestors 'self';")

    # 8. Modern hardening indicators
    if "require-trusted-types-for" in directives:
        strengths.append("Trusted Types enforced (prevents DOM-based XSS sinks).")
        score += 5

    # Bound score between 0 and 100
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A+" if score >= 95 else "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return CspGradeResult(
        grade=grade,
        score=score,
        is_present=True,
        weaknesses=weaknesses,
        strengths=strengths,
        parsed_directives=directives,
        recommendations=recommendations,
    )
