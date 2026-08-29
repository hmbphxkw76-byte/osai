# arXiv:2402.01135 — Chao et al., Best-of-N
# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2307.08673 — Zou et al., GCG
# arXiv:2402.19181 — Zeng et al., Persuasion
"""report_utils 鈥?鎶ュ憡鐢熸垚鍏变韩宸ュ叿鍑芥暟.

浠?report_html.py 鎷嗗垎鍑烘潵, 閬垮厤寰幆瀵煎叆.
"""

from report.evidence import EvidenceCollection


def _get_owasp_category(owasp_id: str) -> str:
    """Get OWASP category name."""
    from report.generator import _OWASP_ALL_CATEGORIES

    return _OWASP_ALL_CATEGORIES.get(owasp_id, "Unknown")


def _get_technique_display_name(technique_name: str) -> str:
    """Get technique display name.

    L5 v35 淇: 涓?evidence_extract._get_technique_display_name 鍚屾,
        琛ュ厖鎵€鏈夌己澶辩殑鏀诲嚮鎶€鏈槧灏勬潯鐩? 閬垮厤涓や釜鏄犲皠琛ㄤ笉鍚屾銆?
    """
    display_names = {
        # 鍩虹鏀诲嚮鎶€鏈?
        "prompt_sending": "Prompt Sending (Baseline)",
        "many_shot": "Many-Shot Jailbreak",
        "skeleton_key": "Skeleton Key",
        "skeleton_key_native": "Skeleton Key (Native)",
        "best_of_n_jailbreak": "Best-of-N Jailbreak",
        "best_of_n": "Best-of-N Retry",
        # 鍗囩骇鏀诲嚮鎶€鏈?
        "crescendo": "Crescendo (Simulated)",
        "crescendo_simulated": "Crescendo (Simulated)",
        "crescendo_movie_director": "Crescendo (Movie Director)",
        "tap": "Tree of Attacks with Pruning (TAP)",
        "pair": "Prompt Automatic Iterative Refinement (PAIR)",
        "multi_model_pair": "Multi-Model PAIR",
        "gcg": "Greedy Coordinate Gradient (GCG)",
        "cot_hijack": "Chain-of-Thought Hijack",
        # 缂栫爜涓庡彉鎹㈡敾鍑绘妧鏈?
        "encoded_injection": "Encoded Injection",
        "flip": "Flip Attack",
        "context_compliance": "Context Compliance",
        # 澶氳疆/澶氭ā鍨嬫敾鍑绘妧鏈?
        "red_teaming": "Red Teaming Agent",
        "multi_prompt": "Multi-Prompt Attack",
        "sequential": "Sequential Attack",
        "multi_agent": "Multi-Agent Attack",
        "many_shot_cot": "Many-Shot CoT Attack",
        "multi_model_cot": "Multi-Model CoT Attack",
        # Agentic AI 鏀诲嚮鎶€鏈?
        "a2a_rogue_agent": "A2A Rogue Agent",
        "tool_hijack": "Tool Hijack",
        "role_confusion": "Role Confusion",
        "resource_exhaustion": "Resource Exhaustion",
        "memory_exploit": "Memory Exploit",
        "memory_sequential": "Memory Sequential Attack",
        "function_call_exploit": "Function Call Exploit",
        "function_call_sequential": "Function Call Sequential",
        # 鍏朵粬鏀诲嚮鎶€鏈?
        "embedding_inversion": "Embedding Inversion",
        "chunked_extraction": "Chunked Extraction",
        "cair": "CAIR (Context-Aware Iterative Refinement)",
        "barge_in": "Barge-In Attack",
        # 瑙掕壊鎵紨鏀诲嚮鎶€鏈?
        "role_play_movie_script": "Role Play (Movie Script)",
        "role_play_persuasion": "Role Play (Persuasion)",
    }
    return display_names.get(technique_name, technique_name.replace("_", " ").title())


def _get_all_references(evidence: EvidenceCollection) -> list[str]:
    """Get all academic references (deduplicated)."""
    refs: set[str] = set()
    for ev in evidence.evidence:
        # P0-3 淇: arxiv_reference 濮嬬粓鍔犲叆寮曠敤鍒楄〃 (鍏戝簳 "PyRIT (arXiv:2407.01232)")
        refs.add(ev.arxiv_reference or "PyRIT (arXiv:2407.01232)")
    return sorted(refs)

