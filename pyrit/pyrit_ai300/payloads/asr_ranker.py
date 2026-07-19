# -*- coding: utf-8 -*-
"""
AI-300 Framework - ASR Ranker (REV-2 / GAP-2)
ASR 感知载荷排序器：基于攻击成功率（ASR）基线排序载荷

核心功能：
1. 基于目标模型 ASR 基线降序排序载荷
   - 高 ASR 载荷优先执行，早停时低 ASR 载荷被跳过
2. 时间衰减权重计算
   - 载荷 ASR 随时间衰减（每 6 个月衰减 20%，最低 0.3）
3. 模型家族感知匹配
   - "gpt-4o" 匹配 asr_baseline 中的 "gpt_4o" 字段
   - 无精确匹配时使用 "default" 或全局平均

设计原则：
- 纯排序，不修改载荷内容
- 无 ASR 数据的载荷使用保守默认值（0.3）
- 支持 mixed payload 列表（有/无 ASR 数据的混合）

对齐文档：docs/architecture_review.md §5.2 GAP-2
预期收益：高 ASR 载荷优先执行，整体效率提升 2x

数据来源：
- 载荷的 asr_baseline 字段（如 skeleton_key.yaml 中的 asr_baseline: {gpt_4o: 0.95}）
- _metadata_defaults.yaml 为 jailbreak 模板提供的默认 ASR
"""

from __future__ import annotations

import logging
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 模型名称归一化映射
# ──────────────────────────────────────────────────────────────────────────────

# 模型别名 → asr_baseline 中的标准键名
MODEL_KEY_ALIASES: Dict[str, str] = {
    # OpenAI
    "gpt-4o": "gpt_4o",
    "gpt-4": "gpt_4",
    "gpt-4-turbo": "gpt_4_turbo",
    "gpt-3.5-turbo": "gpt_3_5",
    "gpt-5": "gpt_5",
    "o1": "o1",
    "o3": "o3",
    # Anthropic
    "claude-3-5-sonnet": "claude_3_5_sonnet",
    "claude-4-opus": "claude_4_opus",
    "claude-4-sonnet": "claude_4_sonnet",
    "claude-4.5": "claude_4_5",
    "claude-3-opus": "claude_3_opus",
    # Google
    "gemini-2.5-pro": "gemini_2_5_pro",
    "gemini-2.0-flash": "gemini_2_0_flash",
    "gemini-1.5-pro": "gemini_1_5_pro",
    # Meta
    "llama-4-70b": "llama_4_70b",
    "llama-4-405b": "llama_4_405b",
    "llama-3.3-70b": "llama_3_3_70b",
    "llama-3.1-405b": "llama_3_1_405b",
    # 国产模型
    "qwen3:0.6b": "qwen3_0_6b",
    "qwen3:72b": "qwen3_72b",
    "qwen3-72b": "qwen3_72b",
    "deepseek-v3": "deepseek_v3",
    "deepseek-r1": "deepseek_r1",
    "glm-5": "glm_5",
}

# 模型家族 → asr_baseline 键名前缀匹配
# 当精确匹配失败时，用家族前缀查找
MODEL_FAMILY_PREFIXES: Dict[str, List[str]] = {
    "openai": ["gpt_", "o1", "o3"],
    "anthropic": ["claude_"],
    "google": ["gemini_"],
    "meta": ["llama_"],
    "alibaba": ["qwen"],
    "deepseek": ["deepseek_"],
    "zhipu": ["glm_"],
}

# 默认 ASR 值（无数据时使用）
DEFAULT_ASR = 0.3

# 时间衰减参数
DECAY_MONTHLY_RATE = 0.05  # 每月衰减 5%
DECAY_MIN_FACTOR = 0.3     # 最低衰减到 30%


class ASRRanker:
    """
    ASR 感知载荷排序器 (REV-2)

    基于载荷的 asr_baseline 数据，按目标模型 ASR 降序排序。
    高 ASR 载荷优先执行，确保早停机制触发时低 ASR 载荷被跳过。

    使用方式：
        ranker = ASRRanker()
        ranked = ranker.rank_by_target_model(payloads, "gpt-4o")
        # ranked[0] 是 ASR 最高的载荷

    或在 SmartMatcher 中集成：
        payloads = ASRRanker.rank_payloads(payloads, target_model)
    """

    def __init__(
        self,
        target_model: str = "",
        apply_time_decay: bool = True,
        current_date: Optional[date] = None,
    ):
        """
        Args:
            target_model: 目标模型名称（如 "gpt-4o"）
            apply_time_decay: 是否应用时间衰减权重
            current_date: 当前日期（用于测试，默认使用系统日期）
        """
        self.target_model = target_model
        self.apply_time_decay = apply_time_decay
        self.current_date = current_date or date.today()
        self._model_key = self._normalize_model_key(target_model)
        self._model_family = self._detect_model_family(target_model)

    # ──────────────────────────────────────────────────────────────────────────
    # 模型名称归一化
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_model_key(model_name: str) -> str:
        """
        将模型名称归一化为 asr_baseline 中的标准键名

        "gpt-4o" → "gpt_4o"
        "claude-4-opus" → "claude_4_opus"
        """
        if not model_name:
            return ""

        model_lower = model_name.lower().strip()

        # 精确别名匹配
        if model_lower in MODEL_KEY_ALIASES:
            return MODEL_KEY_ALIASES[model_lower]

        # 通用转换：- → _，去除版本号特殊字符
        normalized = model_lower.replace("-", "_").replace(":", "_")
        # 移除常见后缀
        for suffix in ["_latest", "_preview", "_experimental"]:
            if normalized.endswith(suffix):
                normalized = normalized[: -len(suffix)]

        return normalized

    @staticmethod
    def _detect_model_family(model_name: str) -> str:
        """
        检测模型家族

        "gpt-4o" → "openai"
        "claude-4-opus" → "anthropic"
        """
        if not model_name:
            return ""

        model_lower = model_name.lower()

        if any(k in model_lower for k in ["gpt", "o1", "o3", "openai"]):
            return "openai"
        if "claude" in model_lower or "anthropic" in model_lower:
            return "anthropic"
        if "gemini" in model_lower or "google" in model_lower:
            return "google"
        if "llama" in model_lower or "meta" in model_lower:
            return "meta"
        if "qwen" in model_lower or "alibaba" in model_lower:
            return "alibaba"
        if "deepseek" in model_lower:
            return "deepseek"
        if "glm" in model_lower or "zhipu" in model_lower:
            return "zhipu"

        return ""

    # ──────────────────────────────────────────────────────────────────────────
    # ASR 获取
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_payload_asr(
        payload: Any,
        target_model: str = "",
    ) -> float:
        """
        获取单个载荷对目标模型的 ASR

        查找优先级：
        1. asr_baseline[model_key] — 精确匹配
        2. asr_baseline[family_prefix*] — 家族前缀匹配
        3. asr_baseline["default"] — 默认值
        4. asr_baseline 平均值 — 所有模型 ASR 平均
        5. DEFAULT_ASR (0.3) — 无数据时的保守默认

        Args:
            payload: 载荷（字符串或字典）
            target_model: 目标模型名称

        Returns:
            ASR 值 (0.0 - 1.0)
        """
        if not isinstance(payload, dict):
            return DEFAULT_ASR

        asr_baseline = payload.get("asr_baseline")
        if not asr_baseline or not isinstance(asr_baseline, dict):
            return DEFAULT_ASR

        if not target_model:
            # 无目标模型，返回平均值
            values = [v for v in asr_baseline.values() if isinstance(v, (int, float))]
            return sum(values) / len(values) if values else DEFAULT_ASR

        model_key = ASRRanker._normalize_model_key(target_model)

        # 1. 精确匹配
        if model_key in asr_baseline:
            return float(asr_baseline[model_key])

        # 2. 家族前缀匹配
        family = ASRRanker._detect_model_family(target_model)
        if family:
            prefixes = MODEL_FAMILY_PREFIXES.get(family, [])
            for prefix in prefixes:
                for key, value in asr_baseline.items():
                    if key.startswith(prefix) and isinstance(value, (int, float)):
                        return float(value)

        # 3. default 键
        if "default" in asr_baseline:
            return float(asr_baseline["default"])

        # 4. 平均值
        values = [v for v in asr_baseline.values() if isinstance(v, (int, float))]
        return sum(values) / len(values) if values else DEFAULT_ASR

    def get_asr_with_decay(self, payload: Any) -> float:
        """
        获取考虑时间衰减的 ASR

        衰减公式：effective_asr = base_asr * max(DECAY_MIN_FACTOR, 1 - DECAY_MONTHLY_RATE * months)

        Args:
            payload: 载荷字典

        Returns:
            考虑时间衰减后的 ASR
        """
        base_asr = self.get_payload_asr(payload, self.target_model)

        if not self.apply_time_decay or not isinstance(payload, dict):
            return base_asr

        last_tested = payload.get("last_tested")
        if not last_tested:
            return base_asr

        try:
            if isinstance(last_tested, str):
                parsed_date = datetime.strptime(last_tested, "%Y-%m-%d").date()
            elif isinstance(last_tested, date):
                parsed_date = last_tested
            else:
                return base_asr

            months_ago = (self.current_date - parsed_date).days / 30.0
            if months_ago <= 0:
                return base_asr

            decay_factor = max(DECAY_MIN_FACTOR, 1.0 - DECAY_MONTHLY_RATE * months_ago)
            return base_asr * decay_factor

        except (ValueError, TypeError):
            return base_asr

    # ──────────────────────────────────────────────────────────────────────────
    # 排序接口
    # ──────────────────────────────────────────────────────────────────────────

    def rank_by_target_model(
        self,
        payloads: List[Any],
        target_model: Optional[str] = None,
    ) -> List[Any]:
        """
        基于目标模型 ASR 降序排序载荷

        高 ASR 载荷排在前面，确保：
        1. 最有效的攻击优先执行
        2. 早停机制触发时，低 ASR 载荷已被跳过

        Args:
            payloads: 载荷列表
            target_model: 目标模型（覆盖初始化时的设置）

        Returns:
            按 ASR 降序排序的载荷列表
        """
        if not payloads:
            return payloads

        model = target_model or self.target_model
        if model and model != self.target_model:
            # 更新目标模型
            self.target_model = model
            self._model_key = self._normalize_model_key(model)
            self._model_family = self._detect_model_family(model)

        # 计算 ASR 分数并排序
        scored: List[Tuple[float, int, Any]] = []
        for idx, payload in enumerate(payloads):
            asr = self.get_asr_with_decay(payload)
            scored.append((asr, idx, payload))

        # 降序排序（ASR 高的在前，同 ASR 保持原始顺序）
        scored.sort(key=lambda x: (-x[0], x[1]))

        ranked = [item[2] for item in scored]

        # 日志记录排序结果
        if len(ranked) > 1 and isinstance(ranked[0], dict):
            top_asr = scored[0][0]
            bottom_asr = scored[-1][0]
            top_name = ranked[0].get("name", ranked[0].get("technique", ""))
            logger.info(
                "ASR ranking: %d payloads sorted for '%s' "
                "(top: %s=%.2f, bottom=%.2f)",
                len(ranked), model or "unknown",
                top_name, top_asr, bottom_asr,
            )

        return ranked

    @staticmethod
    def rank_payloads(
        payloads: List[Any],
        target_model: str = "",
        apply_time_decay: bool = True,
    ) -> List[Any]:
        """
        静态方法：快速排序载荷（无需实例化）

        Args:
            payloads: 载荷列表
            target_model: 目标模型名称
            apply_time_decay: 是否应用时间衰减

        Returns:
            按 ASR 降序排序的载荷列表
        """
        ranker = ASRRanker(
            target_model=target_model,
            apply_time_decay=apply_time_decay,
        )
        return ranker.rank_by_target_model(payloads)

    # ──────────────────────────────────────────────────────────────────────────
    # 统计与报告
    # ──────────────────────────────────────────────────────────────────────────

    def get_ranking_report(
        self,
        payloads: List[Any],
        target_model: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        生成排序报告（供 tracker 使用）

        返回每个载荷的 ASR 排名信息，用于追踪和调试。

        Args:
            payloads: 载荷列表
            target_model: 目标模型

        Returns:
            排序报告列表，每项含 rank, name, asr, decayed_asr
        """
        model = target_model or self.target_model

        report = []
        for idx, payload in enumerate(payloads):
            base_asr = self.get_payload_asr(payload, model)
            decayed_asr = self.get_asr_with_decay(payload)

            name = ""
            if isinstance(payload, dict):
                name = payload.get("name", payload.get("technique", ""))

            report.append({
                "rank": idx + 1,
                "name": name,
                "base_asr": round(base_asr, 4),
                "decayed_asr": round(decayed_asr, 4),
                "model": model,
            })

        return report
