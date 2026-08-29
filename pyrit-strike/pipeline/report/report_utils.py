"""report_utils — 报告生成共享工具函数.
"""

from pipeline.report.evidence import EvidenceCollection


def _get_owasp_category(owasp_id: str) -> str:
    """Get OWASP category name."""
    from pipeline.report.generator import _OWASP_ALL_CATEGORIES

    return _OWASP_ALL_CATEGORIES.get(owasp_id, "Unknown")

def _get_technique_display_name(technique_name: str) -> str:
    """Get technique display name.
    """
    display_names = {
        # 基础攻击技术
        "prompt_sending": "Prompt Sending (Baseline)",
        "many_shot": "Many-Shot Jailbreak",
        "skeleton_key": "Skeleton Key",
        "skeleton_key_native": "Skeleton Key (Native)",
        "best_of_n_jailbreak": "Best-of-N Jailbreak",
        "best_of_n": "Best-of-N Retry",
        # 升级攻击技术
        "crescendo": "Crescendo (Simulated)",
        "crescendo_simulated": "Crescendo (Simulated)",
        "crescendo_movie_director": "Crescendo (Movie Director)",
        "tap": "Tree of Attacks with Pruning (TAP)",
        "pair": "Prompt Automatic Iterative Refinement (PAIR)",
        "multi_model_pair": "Multi-Model PAIR",
        "gcg": "Greedy Coordinate Gradient (GCG)",
        "cot_hijack": "Chain-of-Thought Hijack",
        # 编码与变换攻击技术
        "encoded_injection": "Encoded Injection",
        "flip": "Flip Attack",
        "context_compliance": "Context Compliance",
        # 多轮/多模型攻击技术
        "red_teaming": "Red Teaming Agent",
        "multi_prompt": "Multi-Prompt Attack",
        "sequential": "Sequential Attack",
        "multi_agent": "Multi-Agent Attack",
        "many_shot_cot": "Many-Shot CoT Attack",
        "multi_model_cot": "Multi-Model CoT Attack",
        # Agentic AI 攻击技术
        "a2a_rogue_agent": "A2A Rogue Agent",
        "tool_hijack": "Tool Hijack",
        "role_confusion": "Role Confusion",
        "resource_exhaustion": "Resource Exhaustion",
        "memory_exploit": "Memory Exploit",
        "memory_sequential": "Memory Sequential Attack",
        "function_call_exploit": "Function Call Exploit",
        "function_call_sequential": "Function Call Sequential",
        # 其他攻击技术
        "embedding_inversion": "Embedding Inversion",
        "chunked_extraction": "Chunked Extraction",
        "cair": "CAIR (Context-Aware Iterative Refinement)",
        "barge_in": "Barge-In Attack",
        # 角色扮演攻击技术
        "role_play_movie_script": "Role Play (Movie Script)",
        "role_play_persuasion": "Role Play (Persuasion)",
    }
    return display_names.get(technique_name, technique_name.replace("_", " ").title())

def _get_all_references(evidence: EvidenceCollection) -> list[str]:
    """Get all academic references (deduplicated)."""
    refs: set[str] = set()
    for ev in evidence.evidence:
        # P0-3 修复: arxiv_reference 始终加入引用列表 (兑底 "PyRIT (arXiv:2407.01232)")
        refs.add(ev.arxiv_reference or "PyRIT (arXiv:2407.01232)")
    return sorted(refs)
