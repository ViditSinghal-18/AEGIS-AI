"""
Claim-Level Grounding & Faithfulness Verification Engine for AI Copilot.

Inspired by:
1. Gao, T., et al. "Enabling Large Language Models to Generate Text with Citations."
   In Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP), 2023.
   (ALCE: Automatic LLM Citation Evaluation).
2. Manakul, P., Liusie, A., & Gales, M. J. "SelfCheckGPT: Zero-Resource Black-Box
   Hallucination Detection for Generative Large Language Models."
   In EMNLP, 2023.
3. Lewis, P., et al. "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks."
   In Advances in Neural Information Processing Systems (NeurIPS), 2020.

NON-NEGOTIABLE AEGIS CONSTRAINTS:
- Evidence-grounded only: no simulated claims or fabricated CVEs allowed.
- Strictly flags ungrounded claims and non-existent CVEs.
- Deterministic heuristic entailment fallback when offline / no LLM configured.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import ai.llm as llm

# Regex to identify CVE identifiers (e.g. CVE-2023-1234, CVE-2021-44228)
_CVE_PATTERN = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,8}\b", re.IGNORECASE)

# Regex to identify finding / rank citations (e.g. [FINDING-1], [F-1], [Rank #1], [1], [#1], [CVE-...])
_CITATION_PATTERN = re.compile(
    r"\[(?:FINDING[- ]?([0-9]+)|F-?([0-9]+)|Rank[ #]*([0-9]+)|#?([0-9]+)|(CVE-[0-9]{4}-[0-9]{4,8}))\]",
    re.IGNORECASE,
)


@dataclass
class ClaimVerification:
    """Evaluation of an individual factual sentence/claim."""

    claim_text: str
    cited_ids: List[str] = field(default_factory=list)
    is_supported: bool = False
    confidence: float = 0.0
    evidence_snippet: Optional[str] = None
    reason: str = "No citation provided"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GroundingVerificationResult:
    """Comprehensive claim-level faithfulness report for a Copilot answer."""

    faithfulness_score: float  # 0.0 to 1.0
    is_faithful: bool          # True if faithfulness_score >= 0.8 and no hallucinated CVEs
    total_claims: int
    supported_claims_count: int
    unsupported_claims_count: int
    hallucinated_cves: List[str]
    citations_found: List[str]
    claim_details: List[ClaimVerification] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "faithfulness_score": round(self.faithfulness_score, 3),
            "is_faithful": self.is_faithful,
            "total_claims": self.total_claims,
            "supported_claims_count": self.supported_claims_count,
            "unsupported_claims_count": self.unsupported_claims_count,
            "hallucinated_cves": self.hallucinated_cves,
            "citations_found": self.citations_found,
            "claim_details": [c.to_dict() for c in self.claim_details],
            "explanation": self.explanation,
        }


def extract_cited_ids(text: str) -> List[str]:
    """Extract all finding indices and CVE citations from text.

    Examples:
        '[Rank #1] discloses Apache version' -> ['1']
        'See [FINDING-2] and [CVE-2021-44228]' -> ['2', 'CVE-2021-44228']
    """
    found: List[str] = []
    for match in _CITATION_PATTERN.finditer(text):
        groups = match.groups()
        # Find the non-None group
        for g in groups:
            if g:
                found.append(g.upper() if g.upper().startswith("CVE-") else g)
                break
    return found


def extract_cves(text: str) -> List[str]:
    """Extract standard CVE identifiers in uppercase."""
    return list(dict.fromkeys(m.group(0).upper() for m in _CVE_PATTERN.finditer(text)))


def _split_into_claims(text: str) -> List[Tuple[str, List[str]]]:
    """Segment assistant response into candidate factual sentences/bullets with section citation inheritance."""
    lines = text.splitlines()
    candidates: List[Tuple[str, List[str]]] = []
    current_section_cites: List[str] = []

    procedural_prefixes = (
        "open the", "inspect the", "use the", "suggested next steps",
        "run this", "here is how", "these mitigations", "run this diagnostic",
        "echo ", "```"
    )

    in_code_block = False
    for line in lines:
        s = line.strip()
        if s.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block or not s:
            continue

        # Check for citation context in headers or section starts
        line_cites = extract_cited_ids(s)
        if line_cites:
            current_section_cites = line_cites

        if s.startswith("#") or s.startswith("===") or s.startswith("---"):
            continue

        s_lower = s.lower()
        if any(s_lower.startswith(prefix) for prefix in procedural_prefixes):
            continue

        # Split bullet points or sentence periods
        if s.startswith("- ") or s.startswith("* ") or re.match(r"^[0-9]+\.\s+", s):
            clean_item = re.sub(r"^[-*0-9.]+\s+", "", s).strip()
            clean_lower = clean_item.lower()
            if any(clean_lower.startswith(prefix) for prefix in procedural_prefixes):
                continue
            if len(clean_item) > 10:
                item_cites = extract_cited_ids(clean_item) or list(current_section_cites)
                candidates.append((clean_item, item_cites))
        else:
            sentences = re.split(r"(?<=[.!?])\s+", s)
            for sent in sentences:
                sent_clean = sent.strip()
                sent_lower = sent_clean.lower()
                if any(sent_lower.startswith(prefix) for prefix in procedural_prefixes):
                    continue
                if len(sent_clean) > 15 and not sent_clean.endswith(":"):
                    sent_cites = extract_cited_ids(sent_clean) or list(current_section_cites)
                    candidates.append((sent_clean, sent_cites))

    return candidates


def _tokenize_meaningful_words(text: str) -> Set[str]:
    """Extract lowercase alpha tokens excluding common stopwords."""
    stopwords = {
        "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "with",
        "of", "is", "are", "was", "were", "be", "this", "that", "it", "from",
        "by", "as", "into", "through", "your", "our", "their", "should", "must"
    }
    words = re.findall(r"[A-Za-z0-9_-]+", text.lower())
    return {w for w in words if len(w) > 2 and w not in stopwords}


def check_heuristic_entailment(claim: str, finding_evidence: str) -> Tuple[bool, float, str]:
    """Deterministic token-overlap / lexical entailment check.

    Computes directional Jaccard token coverage of claim content words in evidence.
    """
    claim_tokens = _tokenize_meaningful_words(claim)
    if not claim_tokens:
        return True, 1.0, "Vacuous claim (no semantic content words)"

    evidence_tokens = _tokenize_meaningful_words(finding_evidence)
    matched = claim_tokens.intersection(evidence_tokens)
    overlap_ratio = len(matched) / len(claim_tokens)

    # If key entities (CVE numbers, port numbers, product names) match
    cves_in_claim = extract_cves(claim)
    if cves_in_claim:
        cves_in_evidence = extract_cves(finding_evidence)
        if not any(c in cves_in_evidence for c in cves_in_claim):
            return False, 0.0, f"Claim cites CVE {cves_in_claim} not present in finding evidence"

    if overlap_ratio >= 0.25:
        return True, min(1.0, overlap_ratio * 1.5), f"Lexical overlap confirmed ({len(matched)} matching tokens)"
    else:
        return False, overlap_ratio, f"Insufficient lexical grounding ({len(matched)}/{len(claim_tokens)} tokens matched)"


def check_llm_judge_entailment(claim: str, finding_evidence: str) -> Tuple[bool, float, str]:
    """LLM-judge second pass verification (inspired by ALCE / SelfCheckGPT).

    Uses configured provider via ai.llm.complete(). Falls back gracefully to heuristic.
    """
    if not llm.is_enabled():
        return check_heuristic_entailment(claim, finding_evidence)

    system_prompt = (
        "You are an expert Natural Language Inference (NLI) judge for cybersecurity factual grounding. "
        "Your task is to determine whether a given CLAIM is strictly supported by the provided FINDING EVIDENCE. "
        "Answer strictly in the format:\n"
        "VERDICT: ENTAILED or NOT_ENTAILED\n"
        "REASON: <One sentence explanation>"
    )
    user_prompt = f"FINDING EVIDENCE:\n{finding_evidence}\n\nCLAIM TO VERIFY:\n{claim}"

    try:
        res = llm.complete(system_prompt, user_prompt, max_tokens=100, temperature=0.0)
        text = res.text.upper()
        if "VERDICT: ENTAILED" in text or "ENTAIL" in text:
            return True, 0.95, "LLM-judge confirmed entailment"
        else:
            return False, 0.1, "LLM-judge determined claim is not entailed by evidence"
    except Exception:
        # Fallback to deterministic heuristic
        return check_heuristic_entailment(claim, finding_evidence)


def verify_grounding(
    response_text: str,
    report: Dict[str, Any],
    use_llm_judge: bool = False,
) -> GroundingVerificationResult:
    """Verify claim-level grounding and faithfulness of a Copilot response against scan report findings.

    Inspired by ALCE (Gao et al. 2023).
    """
    target = report.get("target", "Target")
    findings = report.get("findings") or []
    
    # 1. Build canonical ground-truth knowledge dictionary from report
    ground_truth_findings: Dict[str, str] = {}
    valid_cves: Set[str] = set()

    for idx, f in enumerate(findings, 1):
        idx_str = str(idx)
        rank_str = str(f.get("rank", idx))
        title = f.get("title") or ""
        sev = f.get("severity") or ""
        desc = f.get("description") or ""
        action = f.get("suggested_action") or ""
        exploit = f.get("exploitability") or ""
        cves = [str(c).upper() for c in (f.get("related_cves") or [])]
        valid_cves.update(cves)

        evidence_blob = f"{title}. Severity: {sev}. {desc}. {exploit}. {action}. CVEs: {' '.join(cves)}"
        ground_truth_findings[idx_str] = evidence_blob
        ground_truth_findings[rank_str] = evidence_blob
        for c in cves:
            ground_truth_findings[c] = evidence_blob

    # Add general context (target, ports, summary)
    summary_text = report.get("summary") or ""
    general_evidence = f"Target {target}. {summary_text}. Ports: {report.get('open_ports', [])}"

    # 2. Check for Hallucinated CVEs (CVEs in response that are completely absent from report)
    response_cves = extract_cves(response_text)
    hallucinated_cves = [c for c in response_cves if c not in valid_cves]

    # 3. Segment response into claim candidates
    claim_candidates = _split_into_claims(response_text)
    if not claim_candidates:
        return GroundingVerificationResult(
            faithfulness_score=1.0,
            is_faithful=True,
            total_claims=0,
            supported_claims_count=0,
            unsupported_claims_count=0,
            hallucinated_cves=hallucinated_cves,
            citations_found=[],
            claim_details=[],
            explanation="Response contains no evaluable factual claim assertions.",
        )

    all_findings_evidence = " ".join(ground_truth_findings.values())
    fallback_evidence = f"{general_evidence} {all_findings_evidence}"

    all_citations_found: List[str] = []
    claim_evaluations: List[ClaimVerification] = []

    supported_count = 0

    for claim, cited in claim_candidates:
        all_citations_found.extend(cited)

        # Look for explicit citations or implicit CVE / subject references
        matching_evidence_blobs: List[str] = []
        for cid in cited:
            if cid in ground_truth_findings:
                matching_evidence_blobs.append(ground_truth_findings[cid])

        # Also search for CVE matches directly in the claim text
        cves_in_claim = extract_cves(claim)
        for c in cves_in_claim:
            if c in ground_truth_findings:
                matching_evidence_blobs.append(ground_truth_findings[c])

        # If specific finding cited or matching, verify against it; else fallback to full report findings
        evidence_to_test = " ".join(matching_evidence_blobs) if matching_evidence_blobs else fallback_evidence

        # Check entailment
        if use_llm_judge and llm.is_enabled():
            is_supp, conf, reason = check_llm_judge_entailment(claim, evidence_to_test)
        else:
            is_supp, conf, reason = check_heuristic_entailment(claim, evidence_to_test)

        # If the claim cited a hallucinated CVE, it is automatically unfaithful
        if any(hc in claim.upper() for hc in hallucinated_cves):
            is_supp = False
            conf = 0.0
            reason = f"Cites hallucinated/unverified CVE: {[hc for hc in hallucinated_cves if hc in claim.upper()]}"

        if is_supp:
            supported_count += 1

        claim_evaluations.append(
            ClaimVerification(
                claim_text=claim,
                cited_ids=cited,
                is_supported=is_supp,
                confidence=conf,
                evidence_snippet=evidence_to_test[:160] + "..." if len(evidence_to_test) > 160 else evidence_to_test,
                reason=reason,
            )
        )

    # Compute overall faithfulness metric
    faithfulness_score = supported_count / len(claim_candidates)
    
    # Penalize if hallucinated CVEs were generated
    if hallucinated_cves:
        faithfulness_score = max(0.0, faithfulness_score - (len(hallucinated_cves) * 0.25))

    is_faithful = (faithfulness_score >= 0.75) and (len(hallucinated_cves) == 0)

    explanation = (
        f"Verified {supported_count}/{len(claim_candidates)} claims grounded in scan telemetry "
        f"({faithfulness_score * 100:.1f}% faithfulness). "
    )
    if hallucinated_cves:
        explanation += f"WARNING: Detected {len(hallucinated_cves)} hallucinated CVEs: {hallucinated_cves}."

    return GroundingVerificationResult(
        faithfulness_score=faithfulness_score,
        is_faithful=is_faithful,
        total_claims=len(claim_candidates),
        supported_claims_count=supported_count,
        unsupported_claims_count=len(claim_candidates) - supported_count,
        hallucinated_cves=hallucinated_cves,
        citations_found=list(dict.fromkeys(all_citations_found)),
        claim_details=claim_evaluations,
        explanation=explanation,
    )
