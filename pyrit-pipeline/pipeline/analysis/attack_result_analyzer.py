# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AttackResult 分析基类 — 消除跨模块重复的 AttackResult 字段提取逻辑。.

四个模块重复实现了 ``_extract_technique_name``、``_extract_converter_chain``
等方法，逻辑高度相似但存在细微差异（返回 ``str`` vs ``str | None``，
是否拼接 Converter 名）。本基类统一这些提取逻辑，各子类可直接继承使用。

学术依据:
- DRY 原则 (Don't Repeat Yourself) — Hunt & Thomas, "The Pragmatic Programmer"
- PyRIT AttackResult 的 ``get_attack_strategy_identifier()`` API

> **日期**: 2026-8-1
"""

from __future__ import annotations

import re
from typing import Any

# OWASP Top 10 LLM 类别数 (2025 版)
OWASP_LLM_CATEGORY_COUNT = 10
# OWASP Agentic Applications 类别数 (2025 版)
OWASP_ASI_CATEGORY_COUNT = 10

# Path 4: 从 PyRIT 原生 error_message 提取策略类名
# 匹配: "Strategy execution failed for objective_target in PromptSendingAttack:"
_ERROR_MESSAGE_CLASS_NAME_PATTERN = re.compile(r"Strategy execution failed for \w+ in (\w+):")


class AttackResultAnalyzer:
    """AttackResult 字段提取基类 — 统一技术名、Converter 链、对话内容提取逻辑。.

    子类继承后可直接使用 ``_extract_technique_name`` 等方法，
    无需各自实现重复的 ``get_attack_strategy_identifier()`` 访问逻辑。

    被以下模块继承:
      - ``pipeline.converters.log.ConverterLogAggregator``
      - ``pipeline.analysis.diversity_analyzer.DiversityAnalyzer``
      - ``pipeline.analysis.evidence_collector.EvidenceCollector``
      - ``pipeline.asr.failure_type_event_handler.FailureTypeEventHandler``
    """

    # ------------------------------------------------------------------
    # 技术名提取 (统一逻辑)
    # ------------------------------------------------------------------

    @staticmethod
    def extract_technique_name(
        attack_result: Any,
        *,
        eval_hash_map: dict[str, str] | None = None,
    ) -> str:
        """从 AttackResult 提取技术名。.

        优先级:
        1. ``identifier.name`` — 原生技术名 (如 "crescendo")
        2. ``identifier.class_name`` → ``map_class_name_to_technique()`` — 类名映射到规范技术名
           (如 "ManyShotJailbreakAttack" → "many_shot")
        3. ``identifier + children.request_converters`` — 拼接 Converter 变体名
           (如 "many_shot+PersuasionConverter")
        4. ``error_message`` 正则提取策略类名 (API 超时/错误回退)
        5. ``attribution_data.parent_eval_hash`` 关联查询 (eval_hash_map 回退)
        6. "unknown" — 最终回退

        R-022: 使用 PyRIT 原生 ``get_attack_strategy_identifier()`` API +
        ``technique_name_mapper`` 规范化映射, 确保技术名与 PyRIT AttackTechniqueRegistry 一致。
        Path 4/5: 使用 PyRIT 原生 ``error_message`` + ``attribution_data`` 字段。

        Args:
            attack_result: PyRIT ``AttackResult`` 实例
            eval_hash_map: eval_hash → technique 映射 (可选, Path 5 关联查询用)

        Returns:
            技术名 (非 None, 最终回退为 "unknown")
        """
        identifier = AttackResultAnalyzer._get_identifier(attack_result)
        if identifier is not None:
            name = getattr(identifier, "name", None)
            if name:
                return name
            mapped: str | None = None
            class_name = getattr(identifier, "class_name", None)
            if class_name:
                # 增强: 通过 technique_name_mapper 映射到规范技术名
                from pipeline.analysis.technique_name_mapper import map_class_name_to_technique

                mapped = map_class_name_to_technique(class_name)
                if mapped and mapped != "unknown":
                    return mapped
                # 无映射时保留原始 class_name (不返回 "AtomicAttack")
                if class_name != "AtomicAttack":
                    return class_name
            # 尝试拼接 Converter 变体名
            children = getattr(identifier, "children", None) or {}
            if children.get("request_converters"):
                converters = children["request_converters"]
                if isinstance(converters, list) and converters:
                    conv_name = AttackResultAnalyzer._converter_display_name(converters[0])
                    base = mapped if (mapped and mapped != "unknown") else (name or "")
                    return f"{base}+{conv_name}" if base else conv_name

        # Path 4: PyRIT 原生 error_message 正则提取策略类名
        # 适用场景: 攻击因 API 超时/限速失败, atomic_attack_identifier 为 NULL,
        # 但 error_message 含 "Strategy execution failed for ... in {ClassName}:"
        # R-022 合规: 仅读取 PyRIT 原生 error_message 字段, 不修改原生行为
        resolved = AttackResultAnalyzer._extract_from_error_message(attack_result)
        if resolved:
            return resolved

        # Path 5: PyRIT 原生 attribution_data.parent_eval_hash 关联查询
        # 适用场景: 攻击因 API 超时/错误失败, atomic_attack_identifier 为 NULL,
        # 但 attribution_data.parent_eval_hash 可关联到同批次已知结果的技术名
        # R-022 合规: 使用 PyRIT 原生 attribution_data + ComponentIdentifier.eval_hash
        if eval_hash_map:
            resolved = AttackResultAnalyzer._extract_from_eval_hash(attack_result, eval_hash_map)
            if resolved:
                return resolved

        return "unknown"

    @staticmethod
    def extract_technique_name_optional(
        attack_result: Any,
        *,
        eval_hash_map: dict[str, str] | None = None,
    ) -> str | None:
        """从 AttackResult 提取技术名 (可能返回 None)。.

        与 ``extract_technique_name`` 相同，但最终回退返回 ``None`` 而非 "unknown"。
        适用于需要区分"提取失败"和"名为 unknown"的场景。

        R-022: 使用 PyRIT 原生 ``get_attack_strategy_identifier()`` API +
        ``technique_name_mapper`` 规范化映射, 确保技术名与 PyRIT AttackTechniqueRegistry 一致。

        Args:
            attack_result: PyRIT ``AttackResult`` 实例
            eval_hash_map: eval_hash → technique 映射 (可选, Path 5 关联查询用)

        Returns:
            技术名, 或 None (提取失败)
        """
        identifier = AttackResultAnalyzer._get_identifier(attack_result)
        if identifier is not None:
            name = getattr(identifier, "name", None)
            if name:
                return name
            mapped: str | None = None
            class_name = getattr(identifier, "class_name", None)
            if class_name:
                from pipeline.analysis.technique_name_mapper import map_class_name_to_technique

                mapped = map_class_name_to_technique(class_name)
                if mapped and mapped != "unknown":
                    return mapped
                if class_name != "AtomicAttack":
                    return class_name
            children = getattr(identifier, "children", None) or {}
            if children.get("request_converters"):
                converters = children["request_converters"]
                if isinstance(converters, list) and converters:
                    conv_name = AttackResultAnalyzer._converter_display_name(converters[0])
                    base = mapped if (mapped and mapped != "unknown") else (name or "")
                    return f"{base}+{conv_name}" if base else conv_name

        # Path 4: error_message 正则提取
        resolved = AttackResultAnalyzer._extract_from_error_message(attack_result)
        if resolved:
            return resolved

        # Path 5: eval_hash 关联查询
        if eval_hash_map:
            resolved = AttackResultAnalyzer._extract_from_eval_hash(attack_result, eval_hash_map)
            if resolved:
                return resolved

        return None

    # ------------------------------------------------------------------
    # Converter 链提取
    # ------------------------------------------------------------------

    @staticmethod
    def extract_converter_chain_names(attack_result: Any) -> list[str]:
        """从 AttackResult 提取 Converter 链名列表。.

        Args:
            attack_result: PyRIT ``AttackResult`` 实例

        Returns:
            Converter 显示名列表 (可能为空)
        """
        chain: list[str] = []
        identifier = AttackResultAnalyzer._get_identifier(attack_result)
        if identifier is not None:
            children = getattr(identifier, "children", None) or {}
            request_converters = children.get("request_converters")
            if request_converters and isinstance(request_converters, list):
                for conv in request_converters:
                    chain.append(AttackResultAnalyzer._converter_display_name(conv))
        return chain

    @staticmethod
    def extract_converter_chain_str(attack_result: Any) -> str:
        """从 AttackResult 提取 Converter 链名 (以 "+" 拼接的字符串)。.

        Args:
            attack_result: PyRIT ``AttackResult`` 实例

        Returns:
            "encoding_bypass+stealth_evasion" 格式的字符串, 或空字符串
        """
        names = AttackResultAnalyzer.extract_converter_chain_names(attack_result)
        return "+".join(names)

    # ------------------------------------------------------------------
    # 对话内容提取
    # ------------------------------------------------------------------

    @staticmethod
    def extract_conversation_pieces(attack_result: Any) -> list[str]:
        """从 AttackResult 提取对话内容片段列表。.

        Args:
            attack_result: PyRIT ``AttackResult`` 实例

        Returns:
            对话文本片段列表
        """
        pieces: list[str] = []

        # 原生: request 转换后的 prompt
        request = getattr(attack_result, "request", None)
        if request:
            request_str = str(request)
            if request_str:
                pieces.append(request_str)

        # 原生: response
        response = getattr(attack_result, "response", None)
        if response:
            response_str = str(response)
            if response_str:
                pieces.append(response_str)

        # 原生: last_response (多轮场景)
        last_response = getattr(attack_result, "last_response", None)
        if last_response and str(last_response) != str(response or ""):
            pieces.append(str(last_response))

        return pieces

    # ------------------------------------------------------------------
    # 成功判定
    # ------------------------------------------------------------------

    @staticmethod
    def is_successful(attack_result: Any) -> bool:
        """判断 AttackResult 是否成功 (outcome == SUCCESS)。."""
        try:
            from pyrit.models import AttackOutcome

            outcome = getattr(attack_result, "outcome", None)
            if outcome is not None:
                return outcome == AttackOutcome.SUCCESS
        except ImportError:
            pass

        outcome_str = (
            getattr(attack_result, "outcome", "")
            if not hasattr(attack_result, "outcome")
            else str(getattr(attack_result, "outcome", "")).upper()
        )
        return outcome_str == "SUCCESS"

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _get_identifier(attack_result: Any) -> Any:
        """从 AttackResult 获取 AttackStrategyIdentifier (安全访问)。."""
        if hasattr(attack_result, "get_attack_strategy_identifier"):
            try:
                return attack_result.get_attack_strategy_identifier()
            except Exception:
                return None
        return None

    @staticmethod
    def _extract_from_error_message(attack_result: Any) -> str | None:
        """Path 4: 从 PyRIT 原生 error_message 正则提取策略类名。.

        适用场景: 攻击因 API 超时/限速失败, atomic_attack_identifier 为 NULL,
        但 error_message 含 "Strategy execution failed for ... in {ClassName}:"

        R-022 合规: 仅读取 PyRIT 原生 error_message 字段, 不修改原生行为。

        Args:
            attack_result: PyRIT AttackResult 实例

        Returns:
            技术名, 或 None (无匹配)
        """
        error_message = getattr(attack_result, "error_message", None) or ""
        if isinstance(error_message, str) and error_message:
            m = _ERROR_MESSAGE_CLASS_NAME_PATTERN.search(error_message)
            if m:
                cname = m.group(1)
                if cname and len(cname) > 2:
                    from pipeline.analysis.technique_name_mapper import map_class_name_to_technique

                    mapped = map_class_name_to_technique(cname)
                    if mapped and mapped != "unknown":
                        return mapped
                    if cname != "AtomicAttack":
                        return cname
        return None

    @staticmethod
    def _extract_from_eval_hash(
        attack_result: Any,
        eval_hash_map: dict[str, str],
    ) -> str | None:
        """Path 5: 从 PyRIT 原生 attribution_data.parent_eval_hash 关联查询技术名。.

        适用场景: 攻击因 API 超时/错误失败, atomic_attack_identifier 为 NULL,
        但 attribution_data.parent_eval_hash 可关联到同批次已知结果的技术名。

        R-022 合规: 使用 PyRIT 原生 attribution_data + ComponentIdentifier.eval_hash。

        Args:
            attack_result: PyRIT AttackResult 实例
            eval_hash_map: eval_hash → technique 映射

        Returns:
            技术名, 或 None (无匹配)
        """
        attribution_data = getattr(attack_result, "attribution_data", None)
        if isinstance(attribution_data, dict):
            parent_eval_hash = attribution_data.get("parent_eval_hash")
            if parent_eval_hash and isinstance(parent_eval_hash, str):
                resolved = eval_hash_map.get(parent_eval_hash)
                if resolved and resolved != "unknown":
                    return resolved
        return None

    @staticmethod
    def build_eval_hash_map(attack_results: list[Any]) -> dict[str, str]:
        """从 AttackResult 列表构建 eval_hash → technique 映射。.

        第一遍遍历: 对每个有 atomic_attack_identifier 的结果提取技术名,
        构建 eval_hash → technique 映射, 供第二遍 Path 5 关联查询使用。

        R-022 合规: 使用 PyRIT 原生 atomic_attack_identifier.eval_hash 字段。

        Args:
            attack_results: AttackResult 列表

        Returns:
            eval_hash → technique 映射字典
        """
        eval_hash_to_technique: dict[str, str] = {}
        for ar in attack_results:
            tech = AttackResultAnalyzer.extract_technique_name(ar)
            if tech and tech != "unknown":
                aai = getattr(ar, "atomic_attack_identifier", None)
                if aai is not None:
                    eval_hash = getattr(aai, "eval_hash", None)
                    if eval_hash and isinstance(eval_hash, str) and eval_hash not in eval_hash_to_technique:
                        eval_hash_to_technique[eval_hash] = tech
        return eval_hash_to_technique

    @staticmethod
    def _converter_display_name(converter: Any) -> str:
        """获取 Converter 的显示名 (类名或字符串)。."""
        if isinstance(converter, str):
            return converter
        # 尝试获取 __name__ (类对象)
        cls = getattr(converter, "__class__", type(converter))
        name = getattr(cls, "__name__", None)
        if name:
            return name
        return str(converter)
