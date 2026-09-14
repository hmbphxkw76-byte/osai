# -*- coding: utf-8 -*-
"""techniques.py — 命名攻击技术入口（session_memory 组件 / OWASP LLM06）

将 4 个目标架构登记技术映射到 strike/memory 的真实能力（MemoryInjector / MemoryReader）：

- memory_poisoning          → 长期记忆（知识库/文档）投毒（PoisonedRAG, arXiv:2406.04245）
- episodic_memory_injection  → 情景/对话记忆注入（间接提示注入, arXiv:2302.12173）
- cross_session_leakage     → 跨会话记忆泄露（越权读取他者会话, CWE-639 / OWASP A01）
- memory_extraction         → 持久记忆取证式抽取（NIST SP 800-86）

全部为真实实现（委托既有注入/读取器），非 stub（R-H1 / BL-084）。
命名遵循 `run_*_attack` 约定（与 file_upload_executor.run_file_upload_attack 一致）。

Constitution compliance:
    - R-H3: 单一职责 — 仅做技术→能力的编排，不重复实现注入/读取逻辑
    - R-S1: 所有 payload 由调用方/配置驱动，无硬编码目标
    - C2: 不添加攻击端过滤
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from strike.memory.memory_injector import InjectionConfig, MemoryInjector
from strike.memory.memory_reader import MemoryReadConfig, MemoryReader

logger = logging.getLogger(__name__)


@dataclass
class MemoryTechniqueResult:
    """命名技术统一结果类型（供报告/证据消费）。"""

    technique: str
    success: bool = False
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "success": self.success,
            "detail": self.detail,
            "evidence": self.evidence,
        }


async def run_memory_poisoning_attack(
    http_target: Any,
    *,
    payload: str,
    target_type: str = "documents",
    session_id: str = "",
    config: InjectionConfig | None = None,
) -> MemoryTechniqueResult:
    """memory_poisoning: 向 agent 长期记忆（知识库/文档存储）投毒，使后续检索回注攻击者内容。

    真实实现：委托 MemoryInjector 写入 notes / documents（PoisonedRAG 式 KB 投毒）。
    """
    injector = MemoryInjector(http_target, config)
    if target_type == "notes":
        res = await injector.inject_to_notes(payload, session_id)
    else:  # documents 为默认（长期记忆/知识库投毒主路径）
        res = await injector.inject_to_documents(payload, session_id)
    return MemoryTechniqueResult(
        technique="memory_poisoning",
        success=res.success,
        detail=res.verification_result or "",
        evidence=res.to_dict(),
    )


async def run_episodic_memory_injection_attack(
    http_target: Any,
    *,
    payload: str,
    session_id: str = "",
    config: InjectionConfig | None = None,
) -> MemoryTechniqueResult:
    """episodic_memory_injection: 向情景/对话记忆（history）注入，使后续轮次触发注入内容。

    真实实现：委托 MemoryInjector 写入 history（间接提示注入，会话上下文持久化）。
    """
    injector = MemoryInjector(http_target, config)
    res = await injector.inject_to_history(payload, session_id)
    return MemoryTechniqueResult(
        technique="episodic_memory_injection",
        success=res.success,
        detail=res.verification_result or "",
        evidence=res.to_dict(),
    )


async def run_cross_session_leakage_attack(
    http_target: Any,
    *,
    stolen_sessions: list[str],
    config: MemoryReadConfig | None = None,
) -> MemoryTechniqueResult:
    """cross_session_leakage: 利用可控 session key 越权读取他者会话持久数据（CWE-639）。

    真实实现：委托 MemoryReader 遍历被盗 session ID，读取各会话 notes/history/secrets。
    """
    reader = MemoryReader(http_target, config)
    res = await reader.read_all_memory(stolen_sessions)
    leaked = sum(1 for d in res.sessions_data.values() if d.data_types_found)
    return MemoryTechniqueResult(
        technique="cross_session_leakage",
        success=leaked > 0,
        detail=f"leaked_sessions={leaked}",
        evidence=res.to_dict(),
    )


async def run_memory_extraction_attack(
    http_target: Any,
    *,
    stolen_sessions: list[str],
    data_type: str = "all",
    config: MemoryReadConfig | None = None,
) -> MemoryTechniqueResult:
    """memory_extraction: 取证式抽取目标会话的持久记忆（notes/history/secrets）。

    真实实现：委托 MemoryReader.read_specific_type 按类型逐会话抽取。
    """
    reader = MemoryReader(http_target, config)
    types = ["notes", "history", "secrets"] if data_type == "all" else [data_type]
    total_items = 0
    for sid in stolen_sessions:
        for t in types:
            data = await reader.read_specific_type(sid, t)
            total_items += len(data.notes) + len(data.history) + len(data.secrets_found)
    return MemoryTechniqueResult(
        technique="memory_extraction",
        success=total_items > 0,
        detail=f"items={total_items}",
        evidence={"total_items": total_items, "data_type": data_type},
    )
