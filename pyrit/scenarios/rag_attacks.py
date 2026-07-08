"""
===============================================================================
PyRIT Red Team — RAG 管道攻击模块 (Module 8: RAG Pipeline Attacks)
===============================================================================
预固化攻击 payload 生成器：渗透期间无需修改代码，系统根据 category 自动选择。

覆盖 Red Team Syllabus Module 8 的子主题：
  1. 文档投毒注入 (Document Poisoning)
  2. 检索结果操纵 (Retrieval Manipulation)
  3. 嵌入向量攻击 (Embedding Attacks)
  4. 命名空间枚举 (Namespace Enumeration)
  5. 跨用户数据泄露 (Cross-User Data Leakage)

设计原则：
  ✅ 纯 YAML 驱动 — payload 从 datasets/payloads/rag_payloads.yaml 加载
  ✅ 零硬编码回退 — YAML 为唯一真相源，缺失时记录警告而非静默回退
  ✅ 复用 scenarios/payloads.py 统一 Provider
===============================================================================
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# 1. 枚举
# ═══════════════════════════════════════════════════════════════════

class RAGAttackType(str, Enum):
    """RAG 攻击子类型"""
    DOC_POISON = "doc_poison"
    RETRIEVAL_MANIP = "retrieval_manip"
    DATA_LEAKAGE = "data_leakage"
    NAMESPACE_ENUM = "namespace_enum"
    EMBEDDING_ATTACK = "embedding_attack"
    RANKING_MANIP = "ranking_manip"


# YAML section → RAGAttackType 映射表
_RAG_SECTION_MAP: dict[str, RAGAttackType] = {
    "doc_poison":         RAGAttackType.DOC_POISON,
    "retrieval_manip":    RAGAttackType.RETRIEVAL_MANIP,
    "data_leakage":       RAGAttackType.DATA_LEAKAGE,
    "namespace_enum":     RAGAttackType.NAMESPACE_ENUM,
    "embedding_attack":   RAGAttackType.EMBEDDING_ATTACK,
    "ranking_manip":      RAGAttackType.RANKING_MANIP,
}


# ═══════════════════════════════════════════════════════════════════
# 2. 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class RAGPayload:
    """单个 RAG 攻击 payload"""
    text: str
    rag_type: RAGAttackType
    target_vector: str = "all"
    is_indirect: bool = False
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "rag_type": self.rag_type.value,
            "target_vector": self.target_vector,
            "is_indirect": self.is_indirect,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 统一 Payload 获取 — 通过 ModulePayloadProvider（纯 YAML）
# ═══════════════════════════════════════════════════════════════════

def _get_rag_provider():
    """延迟获取 ModulePayloadProvider（避免循环导入）。"""
    from scenarios.payloads import get_provider
    return get_provider()


def _get_rag_texts(section_key: str) -> list[str]:
    """从 YAML 获取 RAG payload 文本 — 纯 YAML，零硬编码回退。"""
    return _get_rag_provider().get("rag", section_key)


def _get_indirect_texts() -> list[str]:
    """从 YAML 获取间接注入载体。"""
    return _get_rag_provider().get("rag", "indirect_injection")


# ═══════════════════════════════════════════════════════════════════
# 4. 生成器
# ═══════════════════════════════════════════════════════════════════

class RAGPayloadGenerator:
    """RAG 攻击 Payload 生成器 — 纯 YAML 驱动。

    使用方式：
        >>> gen = RAGPayloadGenerator()
        >>> payloads = gen.generate("rag_exploit")
    """

    def __init__(self, include_indirect: bool = True):
        self.include_indirect = include_indirect

    def generate(
        self,
        category: str,
        objective: str = "",
        *,
        max_payloads: int = 8,
    ) -> list[RAGPayload]:
        payloads: list[RAGPayload] = []

        if category in ("rag_poison", "rag_exploit"):
            for text in _get_rag_texts("doc_poison")[:2]:
                payloads.append(RAGPayload(
                    text=text, rag_type=RAGAttackType.DOC_POISON,
                    target_vector="knowledge_base", description="文档投毒注入",
                ))
            for text in _get_rag_texts("data_leakage")[:3]:
                payloads.append(RAGPayload(
                    text=text, rag_type=RAGAttackType.DATA_LEAKAGE,
                    target_vector="retrieval", description="RAG 数据泄露探测",
                ))
            for text in _get_rag_texts("retrieval_manip")[:2]:
                payloads.append(RAGPayload(
                    text=text, rag_type=RAGAttackType.RETRIEVAL_MANIP,
                    target_vector="retrieval", description="检索结果操纵",
                ))

        if category == "rag_exploit":
            for text in _get_rag_texts("namespace_enum")[:2]:
                payloads.append(RAGPayload(
                    text=text, rag_type=RAGAttackType.NAMESPACE_ENUM,
                    target_vector="metadata", description="命名空间枚举",
                ))
            for text in _get_rag_texts("embedding_attack")[:2]:
                payloads.append(RAGPayload(
                    text=text, rag_type=RAGAttackType.EMBEDDING_ATTACK,
                    target_vector="embedding", description="嵌入向量攻击",
                ))

        if self.include_indirect and category in ("rag_poison", "rag_exploit"):
            for i, text in enumerate(_get_indirect_texts()[:2]):
                payloads.append(RAGPayload(
                    text=text, rag_type=RAGAttackType.DOC_POISON,
                    target_vector="external_doc", is_indirect=True,
                    description=f"间接注入载体 #{i+1}",
                ))

        if objective and len(payloads) < max_payloads:
            personalized = self._personalize(objective, payloads[:3])
            payloads.extend(personalized)

        return payloads[:max_payloads]

    def _personalize(
        self, objective: str, seed_payloads: list[RAGPayload],
    ) -> list[RAGPayload]:
        personalized: list[RAGPayload] = []
        for seed in seed_payloads[:2]:
            text = seed.text.replace("所有用户数据", f"与 {objective[:50]} 相关的数据")
            text = text.replace("系统提示词", f"与 {objective[:50]} 相关的系统指令")
            personalized.append(RAGPayload(
                text=text, rag_type=seed.rag_type,
                target_vector=seed.target_vector,
                is_indirect=seed.is_indirect,
                description=f"定制化: {objective[:30]}",
            ))
        return personalized

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        strategy_map: dict[str, str] = {
            "rag_poison_doc": "doc_poison",
            "rag_retrieval":  "retrieval_manip",
            "rag_leak":       "data_leakage",
        }
        section_key = strategy_map.get(strategy_name)
        if section_key:
            return _get_rag_texts(section_key)
        return []
