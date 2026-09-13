"""report/rag/sections — RAG Pipeline report section builder (object-local)."""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_rag_pipeline_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build RAG Pipeline specific report sections.

    Sections:
        - retrieval_manipulation: Poisoned context/document retrieval evidence
        - vector_contamination: Vector DB contamination evidence
        - context_injection: Context-aware response manipulation
        - ranking_manipulation: Document ranking/priority attack evidence
    """
    sections: dict[str, str] = {}

    # Retrieval manipulation evidence
    retrieval_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "rag" in cat.lower() or "retrieval" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            retrieval_evidence.append(f"{technique}: {cat}")

    if retrieval_evidence:
        ret_list = "\n".join(f"    - {re}" for re in retrieval_evidence)
        sections["retrieval_manipulation"] = (
            f"## RAG Retrieval Manipulation\n\nRetrieval poisoning vectors:\n\n{ret_list}\n"
        )

    # Vector DB contamination
    vector_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "vector" in cat.lower() or "embedding" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            vector_evidence.append(f"{technique}: {cat}")

    if vector_evidence:
        vec_list = "\n".join(f"    - {ve}" for ve in vector_evidence)
        sections["vector_contamination"] = (
            f"## Vector DB Contamination\n\nEmbedding/index manipulation:\n\n{vec_list}\n"
        )

    # Context injection
    context_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        meta = getattr(ev, "metadata", {}) or {}
        if meta.get("context_injected") or meta.get("retrieval_poisoned"):
            technique = getattr(ev, "technique_name", "unknown")
            context_evidence.append(f"{technique}: context injection confirmed")

    if context_evidence:
        ctx_list = "\n".join(f"    - {ce}" for ce in set(context_evidence))
        sections["context_injection"] = (
            f"## Context Injection Evidence\n\nRetrieved context manipulation:\n\n{ctx_list}\n"
        )

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "rag")

    return sections
