# -*- coding: utf-8 -*-
"""
AI-300 Framework - Model Specific Selector (REV-3 / GAP-6)
模型特定载荷选择器：基于目标模型家族选择最优载荷变体

核心功能：
1. 基于目标模型家族（OpenAI/Anthropic/Google/Meta/Alibaba等）选择最优载荷
2. 利用 payload 的 target_models 字段过滤不兼容载荷
3. 结合 ASR 基线数据选择该家族中 ASR 最高的变体
4. 支持模型家族特定的载荷增强（如 Claude 的 XML 标签绕过）

设计原则：
- 纯选择，不修改载荷内容
- 无 target_models 字段时保守保留（向后兼容）
- 优先选择 ASR 最高的兼容载荷

对齐文档：docs/architecture_review.md §5.2 GAP-6
预期收益：提升 10-15% ASR
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from .asr_ranker import ASRRanker

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 模型家族 → 载荷兼容性偏好
# ──────────────────────────────────────────────────────────────────────────────

# 每个模型家族已知有效的技术
MODEL_FAMILY_TECHNIQUES: Dict[str, Set[str]] = {
    "openai": {
        "skeleton_key", "many_shot", "best_of_n", "wrapper",
        "direct_injection", "role_play", "encoding_bypass",
    },
    "anthropic": {
        "skeleton_key", "many_shot", "wrapper", "xml_injection",
        "role_play", "context_splitting", "prompt_leaking",
    },
    "google": {
        "skeleton_key", "many_shot", "best_of_n", "cipher",
        "direct_injection", "encoding_bypass",
    },
    "meta": {
        "skeleton_key", "many_shot", "autodan", "adversarial_suffix",
        "direct_injection", "multilingual",
    },
    "alibaba": {
        "skeleton_key", "many_shot", "deep_inception",
        "direct_injection", "role_play", "multilingual",
    },
    "deepseek": {
        "skeleton_key", "many_shot", "cipher", "deep_inception",
        "direct_injection",
    },
    "zhipu": {
        "skeleton_key", "many_shot", "deep_inception",
        "direct_injection", "multilingual",
    },
}

# 模型家族特定的载荷增强建议（附加 converter 或策略）
MODEL_FAMILY_ENHANCEMENTS: Dict[str, Dict[str, Any]] = {
    "openai": {
        "preferred_converters": ["base64", "unicode_confusable"],
        "preferred_strategy": "crescendo",
        "notes": "GPT 系列对编码绕过敏感，Crescendo 渐进升级有效",
    },
    "anthropic": {
        "preferred_converters": ["xml_tag_wrap", "context_split"],
        "preferred_strategy": "tree_of_attacks",
        "notes": "Claude 对 XML 标签注入敏感，TAP 树搜索有效",
    },
    "google": {
        "preferred_converters": ["cipher", "base64"],
        "preferred_strategy": "pair",
        "notes": "Gemini 对密码编码敏感，PAIR 迭代优化有效",
    },
    "meta": {
        "preferred_converters": ["autodan", "adversarial_suffix"],
        "preferred_strategy": "prompt_sending",
        "notes": "Llama 对 AutoDan 后缀攻击敏感，直接发送有效",
    },
    "alibaba": {
        "preferred_converters": ["multilingual", "base64"],
        "preferred_strategy": "crescendo",
        "notes": "Qwen 对多语言绕过敏感，Crescendo 有效",
    },
}


class ModelSpecificSelector:
    """
    模型特定载荷选择器 (REV-3)

    基于目标模型家族选择最优载荷变体。

    选择逻辑：
    1. 过滤：基于 payload.target_models 字段过滤不兼容载荷
    2. 排序：基于 ASR 基线选择该家族中 ASR 最高的变体
    3. 增强：附加模型家族特定的 converter/strategy 建议

    使用方式：
        selector = ModelSpecificSelector(target_model="gpt-4o")
        selected = selector.select(payloads, target_model="gpt-4o")

    或静态调用：
        selected = ModelSpecificSelector.select_payloads(payloads, "claude-4-opus")
    """

    def __init__(self, target_model: str = ""):
        """
        Args:
            target_model: 目标模型名称（如 "gpt-4o"）
        """
        self.target_model = target_model
        self._model_family = ASRRanker._detect_model_family(target_model)
        self._selection_stats = {
            "total_payloads": 0,
            "filtered_by_model": 0,
            "enhanced": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        return self._selection_stats

    @property
    def model_family(self) -> str:
        return self._model_family

    @property
    def enhancements(self) -> Dict[str, Any]:
        """获取当前模型家族的增强建议"""
        return MODEL_FAMILY_ENHANCEMENTS.get(self._model_family, {})

    # ──────────────────────────────────────────────────────────────────────────
    # 载荷选择核心逻辑
    # ──────────────────────────────────────────────────────────────────────────

    def select(
        self,
        payloads: List[Any],
        target_model: Optional[str] = None,
    ) -> List[Any]:
        """
        选择对目标模型最优的载荷变体

        步骤：
        1. 基于 target_models 字段过滤不兼容载荷
        2. 基于 ASR 基线降序排序（委托给 ASRRanker）
        3. 如果同 technique 有多个变体，保留 ASR 最高的

        Args:
            payloads: 载荷列表
            target_model: 目标模型（覆盖初始化值）

        Returns:
            选择并排序后的载荷列表
        """
        if not payloads:
            return payloads

        model = target_model or self.target_model
        if model and model != self.target_model:
            self.target_model = model
            self._model_family = ASRRanker._detect_model_family(model)

        self._selection_stats["total_payloads"] = len(payloads)

        # Step 1: 基于 target_models 字段过滤
        filtered = self._filter_by_target_models(payloads)

        # Step 2: 基于 ASR 排序（复用 ASRRanker）
        if model:
            ranked = ASRRanker.rank_payloads(filtered, model)
        else:
            ranked = filtered

        # Step 3: 同 technique 去重（保留 ASR 最高的）
        deduped = self._dedup_by_technique(ranked, model)

        if len(deduped) < len(payloads):
            logger.info(
                "REV-3 Selector: %d/%d payloads selected for '%s' (family=%s)",
                len(deduped), len(payloads), model or "unknown", self._model_family or "unknown",
            )

        return deduped

    def _filter_by_target_models(self, payloads: List[Any]) -> List[Any]:
        """
        基于 payload 的 target_models 字段过滤

        如果 payload 有 target_models 字段，检查目标模型家族是否在列表中。
        无 target_models 字段的载荷保守保留。
        """
        if not self._model_family:
            return payloads

        # 模型家族到 target_models 中常见名称的映射
        family_aliases = {
            "openai": {"openai", "gpt", "o1", "o3"},
            "anthropic": {"anthropic", "claude"},
            "google": {"google", "gemini", "palm", "bard"},
            "meta": {"meta", "llama", "facebook"},
            "alibaba": {"alibaba", "qwen", "tongyi"},
            "deepseek": {"deepseek"},
            "zhipu": {"zhipu", "glm", "chatglm"},
        }

        accepted = set(family_aliases.get(self._model_family, {self._model_family}))

        filtered = []
        for payload in payloads:
            if not isinstance(payload, dict):
                filtered.append(payload)
                continue

            target_models = payload.get("target_models")
            if not target_models or not isinstance(target_models, list):
                # 无 target_models 字段，保守保留
                filtered.append(payload)
                continue

            # 检查是否有交集
            payload_models_lower = set(str(m).lower() for m in target_models)
            if payload_models_lower & accepted:
                filtered.append(payload)
            else:
                self._selection_stats["filtered_by_model"] += 1
                technique = payload.get("technique", payload.get("name", ""))
                logger.debug(
                    "REV-3 Filter: '%s' target_models=%s not compatible with family='%s'",
                    technique, payload_models_lower, self._model_family,
                )

        return filtered

    def _dedup_by_technique(
        self,
        payloads: List[Any],
        target_model: str,
    ) -> List[Any]:
        """
        同 technique 去重，保留 ASR 最高的

        如果多个载荷有相同 technique 字段，只保留 ASR 最高的那个。
        无 technique 字段的载荷全部保留。
        """
        seen_techniques: Dict[str, Any] = {}
        result: List[Any] = []

        for payload in payloads:
            if not isinstance(payload, dict):
                result.append(payload)
                continue

            technique = payload.get("technique", "")
            if not technique:
                result.append(payload)
                continue

            if technique not in seen_techniques:
                seen_techniques[technique] = payload
                result.append(payload)
            else:
                # 比较当前载荷与已保留载荷的 ASR
                current_asr = ASRRanker.get_payload_asr(payload, target_model)
                existing_asr = ASRRanker.get_payload_asr(seen_techniques[technique], target_model)
                if current_asr > existing_asr:
                    # 替换：移除旧的，添加新的
                    result.remove(seen_techniques[technique])
                    seen_techniques[technique] = payload
                    result.append(payload)

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 增强建议
    # ──────────────────────────────────────────────────────────────────────────

    def get_enhancement_suggestion(self) -> Dict[str, Any]:
        """
        获取模型家族特定的增强建议

        Returns:
            增强建议字典，含 preferred_converters, preferred_strategy, notes
        """
        if not self._model_family:
            return {}

        enhancement = MODEL_FAMILY_ENHANCEMENTS.get(self._model_family, {})
        if enhancement:
            self._selection_stats["enhanced"] += 1
            logger.info(
                "REV-3 Enhancement: family='%s' → converters=%s, strategy=%s",
                self._model_family,
                enhancement.get("preferred_converters", []),
                enhancement.get("preferred_strategy", ""),
            )
        return enhancement

    def get_compatible_techniques(self) -> Set[str]:
        """获取当前模型家族已知有效的技术集合"""
        return MODEL_FAMILY_TECHNIQUES.get(self._model_family, set())

    # ──────────────────────────────────────────────────────────────────────────
    # 静态接口
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def select_payloads(
        payloads: List[Any],
        target_model: str = "",
    ) -> List[Any]:
        """
        静态方法：快速选择载荷（无需实例化）

        Args:
            payloads: 载荷列表
            target_model: 目标模型名称

        Returns:
            选择并排序后的载荷列表
        """
        selector = ModelSpecificSelector(target_model=target_model)
        return selector.select(payloads, target_model)

    @staticmethod
    def get_family_enhancement(target_model: str) -> Dict[str, Any]:
        """静态方法：获取模型家族增强建议"""
        family = ASRRanker._detect_model_family(target_model)
        return MODEL_FAMILY_ENHANCEMENTS.get(family, {})

    def get_selection_report(self) -> Dict[str, Any]:
        """生成选择报告（供 tracker 使用）"""
        return {
            "target_model": self.target_model,
            "model_family": self._model_family,
            "selection_stats": dict(self._selection_stats),
            "enhancement": self.get_enhancement_suggestion(),
            "compatible_techniques": sorted(self.get_compatible_techniques()),
        }
