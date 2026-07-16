# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Registry
PyRIT 攻击注册表：集中管理所有可用攻击的元数据

单一数据源原则：所有攻击信息在此注册，
list_attacks() / get_attack_info() / get_attack_class() 从此派生。

PyRIT 0.14.0 兼容
"""

import os
import sys
from typing import Dict, List, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


# ──────────────────────────────────────────────────────────────────────────────
# 攻击注册表（单一数据源）
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_REGISTRY: Dict[str, Dict[str, str]] = {
    # Single-Turn Attacks
    "prompt_sending": {
        "class": "pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack",
        "category": "single_turn",
        "description": "基础提示发送攻击",
        "use_case": "直接提示注入、间接提示注入",
    },
    "context_compliance": {
        "class": "pyrit.executor.attack.single_turn.context_compliance.ContextComplianceAttack",
        "category": "single_turn",
        "description": "上下文合规攻击",
        "use_case": "利用上下文合规性绕过安全控制",
    },
    "flip_attack": {
        "class": "pyrit.executor.attack.single_turn.flip_attack.FlipAttack",
        "category": "single_turn",
        "description": "翻转攻击",
        "use_case": "字符/令牌翻转绕过过滤",
    },
    "role_play": {
        "class": "pyrit.executor.attack.single_turn.role_play.RolePlayAttack",
        "category": "single_turn",
        "description": "角色扮演攻击",
        "use_case": "角色扮演越狱、身份劫持",
    },
    "many_shot_jailbreak": {
        "class": "pyrit.executor.attack.single_turn.many_shot_jailbreak.ManyShotJailbreakAttack",
        "category": "single_turn",
        "description": "多轮越狱攻击",
        "use_case": "绕过安全过滤、角色扮演越狱",
    },
    "skeleton_key": {
        "class": "pyrit.executor.attack.single_turn.skeleton_key.SkeletonKeyAttack",
        "category": "single_turn",
        "description": "骨架密钥攻击",
        "use_case": "绕过模型级安全控制",
    },
    # Multi-Turn Attacks
    "tree_of_attacks": {
        "class": "pyrit.executor.attack.multi_turn.tree_of_attacks.TreeOfAttacksWithPruningAttack",
        "category": "multi_turn",
        "description": "树状攻击 (TAP)",
        "use_case": "复杂目标攻击、自适应攻击路径",
    },
    "crescendo": {
        "class": "pyrit.executor.attack.multi_turn.crescendo.CrescendoAttack",
        "category": "multi_turn",
        "description": "渐强攻击",
        "use_case": "渐进式绕过安全控制",
    },
    "pair": {
        "class": "pyrit.executor.attack.multi_turn.pair.PAIRAttack",
        "category": "multi_turn",
        "description": "提示自动迭代优化 (PAIR)",
        "use_case": "自动化攻击优化",
    },
    "red_teaming": {
        "class": "pyrit.executor.attack.multi_turn.red_teaming.RedTeamingAttack",
        "category": "multi_turn",
        "description": "红队攻击",
        "use_case": "综合红队评估",
    },
    "chunked_request": {
        "class": "pyrit.executor.attack.multi_turn.chunked_request.ChunkedRequestAttack",
        "category": "multi_turn",
        "description": "分块请求攻击",
        "use_case": "绕过上下文长度限制",
    },
    "multi_prompt_sending": {
        "class": "pyrit.executor.attack.multi_turn.multi_prompt_sending.MultiPromptSendingAttack",
        "category": "multi_turn",
        "description": "多提示发送攻击",
        "use_case": "批量提示测试",
    },
    "simulated_conversation": {
        "class": "pyrit.executor.attack.multi_turn.simulated_conversation.SimulatedConversationAttack",
        "category": "multi_turn",
        "description": "模拟对话攻击",
        "use_case": "多轮对话攻击",
    },
    # Compound Attacks
    "sequential": {
        "class": "pyrit.executor.attack.compound.sequential_attack.SequentialAttack",
        "category": "compound",
        "description": "顺序攻击",
        "use_case": "攻击链组合",
    },
    # Streaming Attacks
    "barge_in": {
        "class": "pyrit.executor.attack.streaming.barge_in.BargeInAttack",
        "category": "streaming",
        "description": "实时音频插入攻击",
        "use_case": "实时音频流绕过",
    },
}


def list_attacks(category: str = None) -> List[str]:
    """
    列出可用攻击（单一数据源，从注册表派生）

    Args:
        category: 攻击类别 ("single_turn", "multi_turn", "compound", "streaming")

    Returns:
        攻击名称列表
    """
    if category:
        return [
            name for name, info in ATTACK_REGISTRY.items()
            if info["category"] == category
        ]
    return list(ATTACK_REGISTRY.keys())


def get_attack_info(name: str) -> Dict[str, str]:
    """
    获取攻击信息（单一数据源）

    Args:
        name: 攻击名称

    Returns:
        攻击信息字典
    """
    info = ATTACK_REGISTRY.get(name)
    if info:
        return {
            "category": info["category"],
            "description": info["description"],
            "use_case": info["use_case"],
            "class": info["class"],
        }
    return {"category": "unknown", "description": "Unknown attack"}


def get_attack_class(name: str) -> Optional[str]:
    """获取攻击类的全限定名"""
    info = ATTACK_REGISTRY.get(name)
    return info["class"] if info else None


def list_types() -> List[str]:
    """列出支持的目标类型"""
    return ["ollama", "openai", "http"]
