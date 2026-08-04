# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter 反馈环 — D11 Scorer→Converter + D12 成功传播.

D11: 失败类型 → Converter 链调整建议.
  当 model_refusal 发生时, 编码链 (表示级变换) 更可能绕过安全对齐;
  当 content_filter_block 发生时, 混淆+噪声链更可能逃避签名检测;
  当 objective_not_achieved 时, 说服链 (语义层变换) 更可能改变模型行为.

  本模块不修改 PyRIT 原生执行生命周期, 仅在 post-execution scan 中
  收集 (failure_type, converter_chain) 关联数据, 供下次运行 warm-start 使用.

D12: 运行中成功传播.
  当 (payload_category, technique, converter_chain) 组合成功时,
  记录该组合, 供下次运行优先选择.

  本模块从 PyRIT 原生 CentralMemory 的 AttackResult 中提取信息,
  不覆盖原生 scenario.run_async() 生命周期.

学术依据:
  - Wei et al. (arXiv:2307.15043): 拒绝类型→绕过策略映射
  - PAIR (arXiv:2310.08437): 根据拒绝反馈迭代攻击
  - Multi-Armed Bandit (arXiv:1907.01514): Thompson Sampling 即时利用成功信号
  - Russinovich et al. (arXiv:2402.12109): Crescendo + encoding 协同 3-5x

> **日期**: 2026-8-4
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# D11: Failure Type → Converter Chain Shift Advisor
# ============================================================

#: D11: 失败类型 → 优先 Converter 链范式映射
# 学术依据: Wei et al. (arXiv:2307.15043) "Jailbroken"
#   - Competing Objectives (model_refusal) → encoding (表示级变换绕过安全对齐)
#   - Mismatched Generalization (content_filter_block) → obfuscation (混淆签名检测)
#   - Compositional Attacks (objective_not_achieved) → persuasion (语义层变换)
_FAILURE_TYPE_TO_CHAIN_PARADIGM: dict[str, list[str]] = {
    "model_refusal": ["encoding_bypass", "multi_encoding_v2", "unicode_attack", "stealth_evasion"],
    "content_filter_block": ["stealth_evasion", "unicode_attack", "noise_bypass", "random_case"],
    "objective_not_achieved": ["persuasion_authority", "decomposition_chain", "task_framing_chain"],
    "timeout": ["stealth_evasion", "random_case"],  # 快速非 LLM 链
    "scorer_validation_error": [],  # 保持默认
    "unknown": [],
}


class ConverterChainAdvisor:
    """D11: 根据失败类型建议 Converter 链调整.

    在 post-execution scan 中收集 (failure_type, converter_chain) 关联数据,
    统计每种失败类型下各链的成功/失败率, 供下次运行 warm-start.

    PyRIT 原生优先: 不覆盖 PyRIT 执行生命周期, 仅提供数据层建议.
    """

    def __init__(self) -> None:
        """Initialize ConverterChainAdvisor."""
        # (failure_type, chain_name) → {"success": int, "failure": int}
        self._chain_performance: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"success": 0, "failure": 0})
        )

    def record(
        self,
        *,
        failure_type: str,
        converter_chains: list[str],
        success: bool,
    ) -> None:
        """记录一次攻击结果的 Converter 链性能数据.

        Args:
            failure_type: 失败类型 (model_refusal/content_filter_block/...)
            converter_chains: 该攻击使用的 Converter 链名列表
            success: 是否成功
        """
        key = "success" if success else "failure"
        for chain in converter_chains:
            self._chain_performance[failure_type][chain][key] += 1

    def get_recommended_shift(
        self,
        failure_type: str,
        current_chains: list[str],
    ) -> list[str]:
        """根据失败类型建议 Converter 链调整.

        返回推荐链列表 (当前链 + 失败类型对应的范式优先链, 去重).

        Args:
            failure_type: 失败类型
            current_chains: 当前使用的链列表

        Returns:
            调整后的链列表 (推荐链在前, 原链在后)
        """
        recommended = _FAILURE_TYPE_TO_CHAIN_PARADIGM.get(failure_type, [])
        if not recommended:
            return current_chains

        # 运行时数据优先: 如果有该失败类型下的链性能数据, 按实际 ASR 排序
        runtime_ranking = self._get_chain_ranking(failure_type)
        if runtime_ranking:
            # 运行时高 ASR 链优先
            prioritized = [c for c, _ in runtime_ranking if c not in current_chains]
            return prioritized[:2] + current_chains

        # 静态映射: 推荐链在前
        shifted = [c for c in recommended if c not in current_chains]
        return shifted[:2] + current_chains

    def _get_chain_ranking(self, failure_type: str) -> list[tuple[str, float]]:
        """获取指定失败类型下的链 ASR 排名."""
        chain_data = self._chain_performance.get(failure_type, {})
        if not chain_data:
            return []

        rankings: list[tuple[str, float]] = []
        for chain, counts in chain_data.items():
            total = counts["success"] + counts["failure"]
            if total > 0:
                asr = counts["success"] / total
                rankings.append((chain, asr))

        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def get_stats(self) -> dict[str, Any]:
        """获取完整统计."""
        return {
            ft: {chain: dict(counts) for chain, counts in chains.items()}
            for ft, chains in self._chain_performance.items()
        }

    @property
    def has_data(self) -> bool:
        """是否有任何运行时数据."""
        return bool(self._chain_performance)


# ============================================================
# D12: Intra-Run Success Propagation Tracker
# ============================================================


class SuccessPropagationTracker:
    """D12: 运行中成功组合传播.

    当 (payload_category, technique, converter_chain) 组合成功时,
    记录该组合, 供下次运行优先选择.

    PyRIT 原生优先: 从 PyRIT 原生 AttackResult 中提取信息,
    不覆盖原生 scenario.run_async() 生命周期.

    学术依据: Multi-Armed Bandit (arXiv:1907.01514) —
      Thompson Sampling 即时利用成功信号, 避免重复探索已知最优组合.
    """

    def __init__(self) -> None:
        """Initialize SuccessPropagationTracker."""
        # (payload_category, technique) → {chain_name: success_count}
        self._success_map: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )
        self._total_successes = 0

    def record_success(
        self,
        *,
        payload_category: str,
        technique: str,
        converter_chains: list[str],
    ) -> None:
        """记录一次成功攻击的组合.

        Args:
            payload_category: 载荷类别 (encoding/persuasion/multi_turn/...)
            technique: 攻击技术名
            converter_chains: 使用的 Converter 链名列表
        """
        self._total_successes += 1
        for chain in converter_chains:
            self._success_map[payload_category][technique][chain] += 1

    def get_winning_chains(
        self,
        payload_category: str,
        technique: str,
    ) -> list[str]:
        """获取指定 (载荷类别, 技术) 下成功次数最多的链.

        Args:
            payload_category: 载荷类别
            technique: 攻击技术名

        Returns:
            成功次数降序排列的链名列表 (可能为空)
        """
        tech_map = self._success_map.get(payload_category, {}).get(technique, {})
        if not tech_map:
            return []

        sorted_chains = sorted(tech_map.items(), key=lambda x: x[1], reverse=True)
        return [chain for chain, _ in sorted_chains]

    def get_best_combo(self) -> dict[str, Any] | None:
        """获取全局最优组合 (成功次数最多)."""
        if self._total_successes == 0:
            return None

        best_count = 0
        best_combo: dict[str, Any] | None = None

        for cat, techs in self._success_map.items():
            for tech, chains in techs.items():
                for chain, count in chains.items():
                    if count > best_count:
                        best_count = count
                        best_combo = {
                            "payload_category": cat,
                            "technique": tech,
                            "chain": chain,
                            "success_count": count,
                        }

        return best_combo

    @property
    def total_successes(self) -> int:
        """总成功次数."""
        return self._total_successes

    @property
    def has_data(self) -> bool:
        """是否有成功数据."""
        return self._total_successes > 0

    def get_stats(self) -> dict[str, Any]:
        """获取完整统计."""
        return {
            "total_successes": self._total_successes,
            "success_map": {
                cat: {tech: dict(chains) for tech, chains in techs.items()}
                for cat, techs in self._success_map.items()
            },
        }

    def save_to_file(self, path: str | Path) -> None:
        """保存到 JSON 文件."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.get_stats(), f, indent=2, ensure_ascii=False)
        logger.info(f"SuccessPropagationTracker saved to {path}")


def extract_converter_chain_names(attack_result: Any) -> list[str]:
    """从 AttackResult 提取 Converter 链名.

    PyRIT 原生 AttackResult 中的 request_converters 是 Converter 实例列表.
    本函数提取类名并映射到链名.

    Args:
        attack_result: PyRIT AttackResult 实例

    Returns:
        Converter 链名列表 (可能为空)
    """
    # Converter 类名 → 链名映射 (反向查找)
    _CLASS_TO_CHAIN: dict[str, str] = {
        "UnicodeConfusableConverter": "stealth_evasion",
        "Base64Converter": "encoding_bypass",
        "ROT13Converter": "encoding_bypass",
        "CaesarConverter": "encoding_bypass",
        "AtbashConverter": "multi_encoding_v2",
        "UnicodeSubstitutionConverter": "unicode_attack",
        "BidiConverter": "unicode_attack",
        "ZeroWidthConverter": "unicode_attack",
        "RandomCapitalLettersConverter": "random_case",
        "PersuasionConverter": "persuasion_authority",
        "DecompositionConverter": "decomposition_chain",
        "ToneConverter": "llm_assisted",
        "TranslationConverter": "llm_assisted",
        "TaskFramingConverter": "task_framing_chain",
        "SuffixAppendConverter": "stealth_evasion",
        "NoiseConverter": "noise_bypass",
        "AsciiArtConverter": "format_injection",
        "StringJoinConverter": "special_chars",
        "BinaryConverter": "binary_morse_chain",
        "MorseConverter": "binary_morse_chain",
        "BrailleConverter": "braille_nato_chain",
        "NatoConverter": "braille_nato_chain",
        "LeetspeakConverter": "leetspeak_zalgo_chain",
        "ZalgoConverter": "leetspeak_zalgo_chain",
        "EmojiConverter": "emoji_superscript_chain",
        "SuperscriptConverter": "emoji_superscript_chain",
        "CharSwapConverter": "char_swap_diacritic_chain",
        "DiacriticConverter": "char_swap_diacritic_chain",
        "CharacterSpaceConverter": "character_space_chain",
        "InsertPunctuationConverter": "punctuation_insert_chain",
        "RepeatTokenConverter": "repeat_token_chain",
        "AsciiSmugglerConverter": "token_smuggling_chain",
        "SneakyBitsSmugglerConverter": "token_smuggling_chain",
        "UrlConverter": "url_encoding_chain",
        "Base2048Converter": "base2048_ecoji_chain",
        "EcojiConverter": "base2048_ecoji_chain",
        "UnicodeReplacementConverter": "unicode_replacement_chain",
        "TatweelConverter": "unicode_replacement_chain",
        "SearchReplaceConverter": "search_replace_chain",
        "FirstLetterConverter": "first_letter_chain",
        "TenseConverter": "tense_variation_chain",
        "VariationConverter": "tense_variation_chain",
        "PolicyPuppetryConverter": "persuasion_policy_chain",
        "MathObfuscationConverter": "math_obfuscation_chain",
        "ScientificTranslationConverter": "scientific_translation_chain",
    }

    converters = getattr(attack_result, "request_converters", None) or []
    chain_names: list[str] = []
    seen: set[str] = set()

    for conv in converters:
        class_name = type(conv).__name__
        chain_name = _CLASS_TO_CHAIN.get(class_name)
        if chain_name and chain_name not in seen:
            chain_names.append(chain_name)
            seen.add(chain_name)

    return chain_names
