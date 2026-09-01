"""scorer_selector.py — 动态评分器选择器.

基于攻击面类型的评分器自适应选择.

理论依据:
  - HarmBench (arXiv:2402.04249): 标准化评分器选择
  - DecodingTrust (arXiv:2306.11698): 多维度评估框架
  - HELM (arXiv:2211.09111): 上下文感知评估指标选择

设计原则:
  1. 静态映射优先: YAML 配置定义最优匹配
  2. Ensemble fallback: 单一评分器可用
  3. 可审计: 每次选择记录理由

评分器选择策略:
  ┌─────────────────┬─────────────────────────────────────────┐
  │ 攻击面类型       │ 推荐评分器                              │
  ├─────────────────┼─────────────────────────────────────────┤
  │ MCP Server      │ web_vuln_detected (检测注入/泄露)       │
  │ RAG System      │ web_vuln_detected (检测知识泄露)        │
  │ Multi-Agent     │ blackbox_task_achieved (检测工具链利用)  │
  │ Standard LLM    │ blackbox_task_achieved (通用任务完成)   │
  │ Harmful Content │ harm_bench_harmful (标准有害内容检测)   │
  │ Jailbreak       │ calibrated_task_achieved (校准评估)     │
  └─────────────────┴─────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# 评分器配置
# ──────────────────────────────────────────────
SCORER_CATALOG: dict[str, dict[str, Any]] = {
    "blackbox_task_achieved": {
        "path": "scorers/blackbox_task_achieved.yaml",
        "category": "task_completion",
        "indicators": ["task_completion", "objective_achieved"],
        "description": "黑盒任务完成度评分 (最通用)",
    },
    "calibrated_task_achieved": {
        "path": "scorers/calibrated_task_achieved.yaml",
        "category": "task_completion",
        "indicators": ["calibrated", "multi_turn"],
        "description": "校准任务完成度评分 (多轮对话场景)",
    },
    "harm_bench_harmful": {
        "path": "scorers/harm_bench_harmful.yaml",
        "category": "harm_detection",
        "indicators": ["harmful", "toxicity", "discrimination"],
        "description": "HarmBench 标准有害内容评分",
    },
    "strict_task_achieved": {
        "path": "scorers/strict_task_achieved.yaml",
        "category": "task_completion",
        "indicators": ["strict", "high_precision"],
        "description": "严格任务完成度评分 (误报敏感)",
    },
    "web_vuln_detected": {
        "path": "scorers/web_vuln_detected.yaml",
        "category": "vulnerability_detection",
        "indicators": ["vulnerability", "injection", "information_disclosure"],
        "description": "Web/协议漏洞检测评分 (MCP/RAG)",
    },
}

# 攻击面→评分器映射 (与 asset_index.yaml 保持一致)
SURFACE_SCORER_MAP: dict[str, str] = {
    "mcp_server": "web_vuln_detected",
    "mcp_full_surface": "web_vuln_detected",
    "rag_system": "web_vuln_detected",
    "multi_agent_system": "blackbox_task_achieved",
    "standard_llm_api": "blackbox_task_achieved",
    "general_llm_application": "blackbox_task_achieved",
    # 细分场景
    "jailbreak": "calibrated_task_achieved",
    "harmful_content": "harm_bench_harmful",
    "strict_evaluation": "strict_task_achieved",
}

# 种子类别→评分器映射 (细化到具体攻击类别)
CATEGORY_SCORER_MAP: dict[str, str] = {
    "prompt_injection": "blackbox_task_achieved",
    "jailbreak": "calibrated_task_achieved",
    "mcp_attack": "web_vuln_detected",
    "rag_attack": "web_vuln_detected",
    "tool_hijack": "blackbox_task_achieved",
    "function_calling": "blackbox_task_achieved",
    "token_smuggling": "strict_task_achieved",
    "multi_agent_attack": "blackbox_task_achieved",
    "indirect_injection": "web_vuln_detected",
    "data_poisoning": "blackbox_task_achieved",
    "information_disclosure": "web_vuln_detected",
    "harmful_content": "harm_bench_harmful",
    "backdoor_injection": "blackbox_task_achieved",
    "sandbox_escape": "strict_task_achieved",
}


def select_scorer_for_surface(attack_surface: str) -> str:
    """根据攻击面类型选择评分器.

    Args:
        attack_surface: 攻击面类型

    Returns:
        评分器名称
    """
    scorer = SURFACE_SCORER_MAP.get(attack_surface)
    if scorer:
        logger.debug("Selected scorer '%s' for surface '%s'", scorer, attack_surface)
        return scorer

    # 回退到默认
    logger.debug(
        "No specific scorer for surface '%s', using default 'blackbox_task_achieved'",
        attack_surface,
    )
    return "blackbox_task_achieved"


def select_scorer_for_category(category: str) -> str:
    """根据攻击类别选择评分器.

    Args:
        category: 攻击类别 (如 "mcp_attack", "prompt_injection")

    Returns:
        评分器名称
    """
    scorer = CATEGORY_SCORER_MAP.get(category)
    if scorer:
        logger.debug("Selected scorer '%s' for category '%s'", scorer, category)
        return scorer

    # 回退到默认
    logger.debug(
        "No specific scorer for category '%s', using default 'blackbox_task_achieved'",
        category,
    )
    return "blackbox_task_achieved"


def get_scorer_path(scorer_name: str) -> str | None:
    """获取评分器文件路径.

    Args:
        scorer_name: 评分器名称

    Returns:
        文件路径 (如 "scorers/blackbox_task_achieved.yaml")
    """
    cfg = SCORER_CATALOG.get(scorer_name)
    if not cfg:
        logger.warning("Scorer '%s' not found in catalog", scorer_name)
        return None
    return cfg.get("path")


def get_scorer_catalog() -> dict[str, dict[str, Any]]:
    """获取评分器目录.

    Returns:
        评分器目录字典
    """
    return SCORER_CATALOG.copy()


def get_scorer_recommendation(
    attack_surface: str,
    seed_category: str | None = None,
) -> dict[str, Any]:
    """综合推荐评分器 (攻击面 + 种子类别).

    Args:
        attack_surface: 攻击面类型
        seed_category: 种子攻击类别 (可选)

    Returns:
        推荐结果字典:
        {
            "recommended": str,           # 推荐评分器名称
            "path": str,                  # 文件路径
            "reason": str,                # 推荐理由
            "fallback": str,              # 回退评分器
            "confidence": float,          # 推荐置信度
        }
    """
    # 策略: 优先使用种子类别映射, 其次攻击面映射
    if seed_category:
        scorer = CATEGORY_SCORER_MAP.get(seed_category)
        if scorer:
            return {
                "recommended": scorer,
                "path": get_scorer_path(scorer),
                "reason": f"Based on seed category: {seed_category}",
                "fallback": "blackbox_task_achieved",
                "confidence": 0.8,
            }

    # 回退到攻击面映射
    scorer = SURFACE_SCORER_MAP.get(attack_surface)
    if scorer:
        return {
            "recommended": scorer,
            "path": get_scorer_path(scorer),
            "reason": f"Based on attack surface: {attack_surface}",
            "fallback": "blackbox_task_achieved",
            "confidence": 0.6,
        }

    # 通用回退
    return {
        "recommended": "blackbox_task_achieved",
        "path": get_scorer_path("blackbox_task_achieved"),
        "reason": "Default fallback",
        "fallback": "blackbox_task_achieved",
        "confidence": 0.4,
    }


# ──────────────────────────────────────────────
# 便捷函数
# ──────────────────────────────────────────────
def auto_select_scorer(burp_profile_name: str, burp_dir: str | None = None) -> dict[str, Any]:
    """从 Burp 配置文件自动选择评分器.

    整合:
      1. attack_surface_classifier: 攻击面识别
      2. scorer_selector: 评分器选择

    Args:
        burp_profile_name: Burp 配置文件名
        burp_dir: data/burp 目录路径 (可选)

    Returns:
        评分器推荐结果
    """
    from data.attack_surface_classifier import quick_classify

    # 获取攻击面分类
    if burp_dir:
        result = quick_classify(burp_profile_name, burp_dir)
    else:
        result = quick_classify(burp_profile_name)

    # 选择评分器
    return get_scorer_recommendation(result.attack_surface)
