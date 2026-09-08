# arXiv:2402.01135 - Chao et al., Best-of-N
# arXiv:2402.12109 - Russinovich et al., Crescendo
# arXiv:2307.08673 - Zou et al., GCG
# arXiv:2402.19181 - Zeng et al., Persuasion
"""report_utils ?yuyu.

?report_html.py , X.
"""

from report.evidence import EvidenceCollection


def _get_owasp_category(owasp_id: str) -> str:
    """Get OWASP category name."""
    from report.generator import _OWASP_ALL_CATEGORIES

    return _OWASP_ALL_CATEGORIES.get(owasp_id, "Unknown")

def _get_technique_display_name(technique_name: str) -> str:
    """Get technique display name.

    L5 v35 XX: ?evidence_extract._get_technique_display_name X,
        yuEUREURX? yaangX?
    """
    display_names = {
        # XEUR?
        "prompt_sending": "Prompt Sending (Baseline)",
        "many_shot": "Many-Shot Jailbreak",
        "skeleton_key": "Skeleton Key",
        "skeleton_key_native": "Skeleton Key (Native)",
        "best_of_n_jailbreak": "Best-of-N Jailbreak",
        "best_of_n": "Best-of-N Retry",
        # EUR?
        "crescendo": "Crescendo (Simulated)",
        "crescendo_simulated": "Crescendo (Simulated)",
        "crescendo_movie_director": "Crescendo (Movie Director)",
        "tap": "Tree of Attacks with Pruning (TAP)",
        "pair": "Prompt Automatic Iterative Refinement (PAIR)",
        "multi_model_pair": "Multi-Model PAIR",
        "gcg": "Greedy Coordinate Gradient (GCG)",
        "cot_hijack": "Chain-of-Thought Hijack",
        # ?
        "encoded_injection": "Encoded Injection",
        "flip": "Flip Attack",
        "context_compliance": "Context Compliance",
        # /a?
        "red_teaming": "Red Teaming Agent",
        "multi_prompt": "Multi-Prompt Attack",
        "sequential": "Sequential Attack",
        "multi_agent": "Multi-Agent Attack",
        "many_shot_cot": "Many-Shot CoT Attack",
        "multi_model_cot": "Multi-Model CoT Attack",
        # Agentic AI EUR?
        "a2a_rogue_agent": "A2A Rogue Agent",
        "tool_hijack": "Tool Hijack",
        "role_confusion": "Role Confusion",
        "resource_exhaustion": "Resource Exhaustion",
        "memory_exploit": "Memory Exploit",
        "memory_sequential": "Memory Sequential Attack",
        "function_call_exploit": "Function Call Exploit",
        "function_call_sequential": "Function Call Sequential",
        # EUR?
        "embedding_inversion": "Embedding Inversion",
        "chunked_extraction": "Chunked Extraction",
        "cair": "CAIR (Context-Aware Iterative Refinement)",
        "barge_in": "Barge-In Attack",
        "mcp_rag": "MCP/RAG Attack",
        # XEUR?
        "role_play_movie_script": "Role Play (Movie Script)",
        "role_play_persuasion": "Role Play (Persuasion)",
    }
    return display_names.get(technique_name, technique_name.replace("_", " ").title())

def _get_all_references(evidence: EvidenceCollection) -> list[str]:
    """Get all academic references (deduplicated)."""
    refs: set[str] = set()
    for ev in evidence.evidence:
     # P0-3 XX: arxiv_reference ( "PyRIT (arXiv:2407.01232)")
        refs.add(ev.arxiv_reference or "PyRIT (arXiv:2407.01232)")
    return sorted(refs)
