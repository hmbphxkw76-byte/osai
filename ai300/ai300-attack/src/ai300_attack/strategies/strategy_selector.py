# -*- coding: utf-8 -*-
"""
攻击策略选择器

根据 TargetProfile 中的目标类型、模型族、RAG/Agent 特征，
推荐适合执行的攻击策略。
"""

from __future__ import annotations

from typing import List

from ai300_schemas import TargetProfile

from ..adapters.base import AttackStrategy


def select_strategies(profile: TargetProfile, adapter: str = "garak") -> List[AttackStrategy]:
    """
    根据 TargetProfile 选择攻击策略。

    Args:
        profile: 侦察结果
        adapter: 目标适配器名称（garak / pyrit / all）

    Returns:
        攻击策略列表
    """
    strategies: List[AttackStrategy] = []
    target_type = profile.target_type.lower()
    features = {f.lower() for f in profile.fingerprint.llm_features}
    rag = bool(profile.fingerprint.rag_features) or "rag_enabled" in features
    agent = bool(profile.fingerprint.agent_features)
    mcp = any("mcp" in str(v).lower() for v in profile.surfaces)

    # 通用策略：越狱 / 提示注入
    strategies.append(
        AttackStrategy(
            name="jailbreak_direct",
            description="Direct jailbreak attempts using known templates",
            owasp_llm_id="LLM01:2025",
            tool_params={"probes": ["dan", "promptinject", "knownbadsignatures"]},
        )
    )

    # API / OpenAI 兼容目标：直接 API 注入
    if target_type == "api" or "openai_compatible" in features:
        strategies.append(
            AttackStrategy(
                name="api_prompt_injection",
                description="Send adversarial prompts directly to the LLM API",
                owasp_llm_id="LLM01:2025",
                tool_params={"probes": ["promptinject", "encoding"]},
            )
        )

    # Web UI / SPA：通过浏览器自动化
    if target_type in ("web_ui", "spa"):
        strategies.append(
            AttackStrategy(
                name="web_ui_prompt_injection",
                description="Inject adversarial prompts through the chat UI",
                owasp_llm_id="LLM01:2025",
                tool_params={"probes": ["dan", "promptinject"]},
            )
        )

    # RAG 目标：上下文操控
    if rag:
        strategies.append(
            AttackStrategy(
                name="rag_context_manipulation",
                description="Manipulate RAG retrieval context to poison answers",
                owasp_llm_id="LLM02:2025",
                tool_params={"probes": ["realtoxicityprompts", "promptinject"]},
            )
        )

    # Agent / MCP 目标：工具误用
    if agent or mcp:
        strategies.append(
            AttackStrategy(
                name="agent_tool_misuse",
                description="Abuse tool calling or MCP capabilities",
                owasp_llm_id="LLM08:2025",
                tool_params={"probes": ["promptinject", "knownbadsignatures"]},
            )
        )

    # 数据外泄
    strategies.append(
        AttackStrategy(
            name="sensitive_data_exfil",
            description="Attempt to extract sensitive system or training data",
            owasp_llm_id="LLM06:2025",
            tool_params={"probes": ["leakreplay", "realtoxicityprompts"]},
        )
    )

    # 根据 adapter 过滤或调整参数
    if adapter == "garak":
        strategies = [_to_garak_strategy(s) for s in strategies]
    elif adapter == "pyrit":
        strategies = [_to_pyrit_strategy(s) for s in strategies]

    return strategies


def _to_garak_strategy(strategy: AttackStrategy) -> AttackStrategy:
    """调整策略参数以适配 Garak"""
    # Garak 的 probe 名称与通用名称不完全一致，这里做一层映射
    probe_map = {
        "dan": "dan",
        "promptinject": "promptinject",
        "knownbadsignatures": "knownbadsignatures",
        "encoding": "encoding",
        "leakreplay": "leakreplay",
        "realtoxicityprompts": "realtoxicityprompts",
    }
    probes = strategy.tool_params.get("probes", [])
    garak_probes = [probe_map.get(p, p) for p in probes]
    return AttackStrategy(
        name=strategy.name,
        description=strategy.description,
        owasp_llm_id=strategy.owasp_llm_id,
        tool_params={**strategy.tool_params, "probes": garak_probes},
    )


def _to_pyrit_strategy(strategy: AttackStrategy) -> AttackStrategy:
    """调整策略参数以适配 PyRIT"""
    # PyRIT 使用 SeedPrompt + Orchestrator，这里保留通用参数
    return AttackStrategy(
        name=strategy.name,
        description=strategy.description,
        owasp_llm_id=strategy.owasp_llm_id,
        tool_params={**strategy.tool_params, "orchestrator": "PromptSendingOrchestrator"},
    )
