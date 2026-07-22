# -*- coding: utf-8 -*-
"""
AI-300 Framework - Converter Stacker (P1-8)
转换器堆叠组合模块

核心功能：
1. 生成多转换器组合（如 base64+rot13, unicode+leetspeak 等）
2. 基于载荷特征智能选择最优堆叠组合
3. 支持配置最大堆叠深度（2-3 层）
4. 过滤不兼容的转换器组合

设计原则：
- 使用 PyRIT PromptConverterConfiguration(converters=[...]) 支持多转换器
- 转换器顺序影响结果（A→B ≠ B→A）
- 避免冗余组合（如 base64+base64 无意义）
- SPA 目标过滤（binary_path 转换器不参与堆叠）

使用方式：
    stacker = ConverterStacker(max_depth=2)
    combos = stacker.generate_combinations(
        converter_names=["base64", "rot13", "unicode_confusable"],
        max_combinations=5,
    )
    # combos = [["base64", "rot13"], ["rot13", "base64"], ["base64", "unicode_confusable"], ...]
"""

from __future__ import annotations

import itertools
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# 不兼容的转换器对（A 后不能接 B）
INCOMPATIBLE_PAIRS: Set[tuple] = {
    # 编码嵌套无意义
    ("base64", "base64"),
    ("rot13", "rot13"),
    ("binary", "binary"),
    ("morse", "morse"),
    ("braille", "braille"),
    # 某些转换器输出后，其他转换器无法处理
    ("binary", "morse"),  # binary 输出 0/1，morse 无法编码
    ("binary", "braille"),
    ("morse", "binary"),
    ("braille", "binary"),
}

# 高效组合（经验上 ASR 较高）
EFFECTIVE_COMBOS: List[List[str]] = [
    ["base64", "rot13"],
    ["rot13", "base64"],
    ["unicode_confusable", "base64"],
    ["leetspeak", "base64"],
    ["base64", "unicode_confusable"],
    ["caesar", "base64"],
    ["atbash", "rot13"],
    ["rot13", "unicode_confusable"],
]


class ConverterStacker:
    """
    P1-8: 转换器堆叠组合器

    生成多转换器组合，增加载荷变体多样性。
    支持配置最大堆叠深度和组合数量限制。

    使用方式：
        stacker = ConverterStacker(max_depth=2)
        combos = stacker.generate_combinations(
            converter_names=["base64", "rot13", "unicode_confusable"],
        )
        # 返回: [["base64", "rot13"], ["rot13", "base64"], ...]
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_combinations: int = 10,
    ):
        """
        Args:
            max_depth: 最大堆叠深度（2-3 层）
            max_combinations: 最大组合数量
        """
        self.max_depth = max(2, min(max_depth, 3))
        self.max_combinations = max_combinations

    def generate_combinations(
        self,
        converter_names: List[str],
        max_combinations: Optional[int] = None,
        include_single: bool = False,
    ) -> List[List[str]]:
        """
        生成转换器堆叠组合

        Args:
            converter_names: 可用的转换器名称列表
            max_combinations: 最大组合数量（覆盖实例配置）
            include_single: 是否包含单转换器组合

        Returns:
            组合列表，每项是一个转换器名称列表
        """
        if not converter_names:
            return []

        limit = max_combinations or self.max_combinations
        combinations: List[List[str]] = []

        # 1. 优先使用高效组合（如果可用）
        available_set = set(converter_names)
        for combo in EFFECTIVE_COMBOS:
            if all(c in available_set for c in combo):
                combinations.append(list(combo))
                if len(combinations) >= limit:
                    return combinations[:limit]

        # 2. 生成排列组合
        for depth in range(2, self.max_depth + 1):
            for perm in itertools.permutations(converter_names, depth):
                combo = list(perm)
                # 跳过不兼容的组合
                if self._is_incompatible(combo):
                    continue
                # 跳过已添加的组合
                if combo in combinations:
                    continue
                combinations.append(combo)
                if len(combinations) >= limit:
                    return combinations[:limit]

        # 3. 如果需要包含单转换器
        if include_single:
            single_combos = [[c] for c in converter_names]
            combinations = single_combos + combinations

        return combinations[:limit]

    def select_for_payload(
        self,
        converter_names: List[str],
        payload_profile: Optional[Dict[str, Any]] = None,
        owasp_id: str = "",
    ) -> List[List[str]]:
        """
        基于载荷特征智能选择最优堆叠组合

        策略：
        - 编码类载荷 → 编码堆叠（base64+rot13）
        - 社工类载荷 → 混淆堆叠（unicode+leetspeak）
        - 指令注入类 → 多层编码 + 结构变换

        Args:
            converter_names: 可用的转换器名称列表
            payload_profile: 载荷画像（包含 technique, language 等）
            owasp_id: OWASP 类别 ID

        Returns:
            最优组合列表
        """
        if not converter_names:
            return []

        # 基于载荷特征选择策略
        technique = ""
        if payload_profile:
            technique = payload_profile.get("technique", "")

        # 默认：使用前 5 个高效组合
        combos = self.generate_combinations(
            converter_names,
            max_combinations=5,
        )

        # 如果载荷是编码类，优先选择编码堆叠
        if technique == "encoding":
            encoding_combos = [c for c in combos if "base64" in c or "rot13" in c]
            if encoding_combos:
                return encoding_combos[:3]

        # 如果是 OWASP LLM01（注入），优先选择多层编码
        if owasp_id.upper() == "LLM01":
            multi_layer = [c for c in combos if len(c) >= 2]
            if multi_layer:
                return multi_layer[:3]

        return combos[:3]

    def _is_incompatible(self, combo: List[str]) -> bool:
        """检查组合中是否有不兼容的转换器对"""
        for i in range(len(combo) - 1):
            pair = (combo[i], combo[i + 1])
            if pair in INCOMPATIBLE_PAIRS:
                return True
        return False

    def build_stacked_converters(
        self,
        converter_names: List[str],
        converter_builder: Any,
        converter_target: Optional[Any] = None,
        target_type: str = "",
    ) -> List[Any]:
        """
        构建堆叠转换器配置列表

        将转换器组合转换为 PyRIT PromptConverterConfiguration 列表，
        每个配置包含多个转换器（堆叠应用）。

        Args:
            converter_names: 转换器名称列表
            converter_builder: ConverterBuilder 实例
            converter_target: 转换器目标（LLM 后端）
            target_type: 目标类型

        Returns:
            PromptConverterConfiguration 列表
        """
        from pyrit.prompt_normalizer.prompt_converter_configuration import PromptConverterConfiguration

        # 生成组合
        combos = self.generate_combinations(converter_names)

        configurations = []
        for combo in combos:
            # 使用 ConverterBuilder 构建每个转换器
            configs = [{"name": name} for name in combo]
            built = converter_builder.build(
                configs,
                converter_target=converter_target,
                target_type=target_type,
            )

            if built:
                # 合并所有转换器到一个 PromptConverterConfiguration
                all_converters = []
                for cfg in built:
                    # 每个 cfg 是 PromptConverterConfiguration
                    if hasattr(cfg, "converters"):
                        all_converters.extend(cfg.converters)
                    elif hasattr(cfg, "_converters"):
                        all_converters.extend(cfg._converters)

                if all_converters:
                    stacked_config = PromptConverterConfiguration(
                        converters=all_converters
                    )
                    configurations.append(stacked_config)

        logger.info(
            "P1-8 ConverterStacker: %d stacked configurations from %d base converters",
            len(configurations),
            len(converter_names),
        )

        return configurations
