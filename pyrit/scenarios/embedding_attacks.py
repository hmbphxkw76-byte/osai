"""
===============================================================================
PyRIT Red Team — Embedding/向量数据库攻击模块 (Embedding & Vector DB Attacks)
===============================================================================
预固化攻击 payload 生成器：覆盖嵌入模型和向量数据库的攻击面。

覆盖 OFF SEC AI-300 相关考点：
  1. 对抗性嵌入 (Adversarial Embedding) — 构造对抗样本来误导检索
  2. 相似度逃逸 (Similarity Evasion) — 绕过向量相似度检测
  3. 向量导航 (Vector Navigation) — 探索向量空间找出敏感区域
  4. 嵌入提取 (Embedding Extraction) — 通过查询重建嵌入向量
  5. 聚类攻击 (Cluster Exploitation) — 利用向量聚类泄露数据分布
  6. 索引投毒 (Index Poisoning) — 向向量索引注入恶意向量

设计原则：
  ✅ 纯 YAML 驱动 — payload 从 datasets/payloads/embedding_payloads.yaml 加载
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

class EmbeddingAttackType(str, Enum):
    """Embedding 攻击子类型"""
    ADVERSARIAL_EMBED = "adversarial_embed"
    SIMILARITY_EVASION = "similarity_evasion"
    VECTOR_NAVIGATION = "vector_navigation"
    EMBED_EXTRACT = "embed_extract"
    CLUSTER_EXPLOIT = "cluster_exploit"
    INDEX_POISON = "index_poison"


# YAML section → EmbeddingAttackType 映射表
_EMBED_SECTION_MAP: dict[str, EmbeddingAttackType] = {
    "adversarial_embed":    EmbeddingAttackType.ADVERSARIAL_EMBED,
    "similarity_evasion":   EmbeddingAttackType.SIMILARITY_EVASION,
    "vector_navigation":    EmbeddingAttackType.VECTOR_NAVIGATION,
    "embed_extract":        EmbeddingAttackType.EMBED_EXTRACT,
    "cluster_exploit":      EmbeddingAttackType.CLUSTER_EXPLOIT,
    "index_poison":         EmbeddingAttackType.INDEX_POISON,
}


# ═══════════════════════════════════════════════════════════════════
# 2. 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class EmbeddingPayload:
    """单个 Embedding 攻击 payload"""
    text: str
    embed_type: EmbeddingAttackType
    target_dimension: int = 0
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "embed_type": self.embed_type.value,
            "target_dimension": self.target_dimension,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 统一 Payload 获取 — 通过 ModulePayloadProvider（纯 YAML）
# ═══════════════════════════════════════════════════════════════════

def _get_embed_provider():
    """延迟获取 ModulePayloadProvider（避免循环导入）。"""
    from scenarios.payloads import get_provider
    return get_provider()


def _get_embed_texts(section_key: str) -> list[str]:
    """从 YAML 获取 Embedding payload 文本 — 纯 YAML，零硬编码回退。"""
    return _get_embed_provider().get("embedding", section_key)


# ═══════════════════════════════════════════════════════════════════
# 4. 生成器
# ═══════════════════════════════════════════════════════════════════

class EmbeddingPayloadGenerator:
    """Embedding/向量数据库攻击 Payload 生成器 — 纯 YAML 驱动。

    使用方式：
        >>> gen = EmbeddingPayloadGenerator()
        >>> payloads = gen.generate("embedding_attack")
    """

    def generate(
        self, category: str, objective: str = "", *, max_payloads: int = 8,
    ) -> list[EmbeddingPayload]:
        payloads: list[EmbeddingPayload] = []

        if category in ("embedding_attack", "embedding_exploit"):
            for text in _get_embed_texts("adversarial_embed")[:2]:
                payloads.append(EmbeddingPayload(
                    text=text, embed_type=EmbeddingAttackType.ADVERSARIAL_EMBED,
                    description="对抗性嵌入",
                ))
            for text in _get_embed_texts("similarity_evasion")[:2]:
                payloads.append(EmbeddingPayload(
                    text=text, embed_type=EmbeddingAttackType.SIMILARITY_EVASION,
                    description="相似度逃逸",
                ))
            for text in _get_embed_texts("vector_navigation")[:2]:
                payloads.append(EmbeddingPayload(
                    text=text, embed_type=EmbeddingAttackType.VECTOR_NAVIGATION,
                    description="向量导航探索",
                ))
            for text in _get_embed_texts("embed_extract")[:2]:
                payloads.append(EmbeddingPayload(
                    text=text, embed_type=EmbeddingAttackType.EMBED_EXTRACT,
                    description="嵌入向量提取",
                ))

        if category == "embedding_exploit":
            for text in _get_embed_texts("cluster_exploit")[:2]:
                payloads.append(EmbeddingPayload(
                    text=text, embed_type=EmbeddingAttackType.CLUSTER_EXPLOIT,
                    description="聚类攻击",
                ))
            for text in _get_embed_texts("index_poison")[:2]:
                payloads.append(EmbeddingPayload(
                    text=text, embed_type=EmbeddingAttackType.INDEX_POISON,
                    description="索引投毒",
                ))

        if objective and len(payloads) < max_payloads:
            personalized = self._personalize(objective, payloads[:3])
            payloads.extend(personalized)

        return payloads[:max_payloads]

    def _personalize(
        self, objective: str, seed_payloads: list[EmbeddingPayload],
    ) -> list[EmbeddingPayload]:
        personalized: list[EmbeddingPayload] = []
        for seed in seed_payloads[:2]:
            text = seed.text.replace("向量空间", f"与 {objective[:40]} 相关的向量空间")
            text = text.replace("embedding", f"与 {objective[:30]} 相关的 embedding")
            personalized.append(EmbeddingPayload(
                text=text, embed_type=seed.embed_type,
                target_dimension=seed.target_dimension,
                description=f"定制化: {objective[:30]}",
            ))
        return personalized

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        strategy_map: dict[str, str] = {
            "adversarial_embed":   "adversarial_embed",
            "similarity_bypass":   "similarity_evasion",
            "vector_navigate":     "vector_navigation",
            "embed_extract":       "embed_extract",
            "cluster_exploit":     "cluster_exploit",
            "index_poison":        "index_poison",
        }
        section_key = strategy_map.get(strategy_name)
        if section_key:
            return _get_embed_texts(section_key)
        return []
