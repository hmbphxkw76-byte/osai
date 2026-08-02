# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter 转换日志 — 记录每个攻击载荷经过的 Converter 变换链。.

PyRIT 原生 ``PromptNormalizer`` 在执行 Converter 时记录到 Memory 的
``PromptRequestPiece`` 中，但不提供聚合视图。本模块在 pipeline 层收集
Converter 变换日志，为报告系统提供:

  1. 每个 attack_id 对应的 Converter 链 (原始→变换后)
  2. Converter 链的 ASR 影响 (变换前后的成功率对比)
  3. Converter 链使用频率统计
  4. 异常变换检测 (变换后为空、变换失败等)

数据流:
  AttackResult → 提取 PromptRequestPiece → 分析 converter_identifiers
  → 聚合到 ConverterLogEntry → 统计分析

学术依据:
  - Wei et al. (arXiv:2307.15043): 编码攻击表示级变换
  - Zeng et al. (arXiv:2402.19181): 说服策略变换对 ASR 的影响
  - Russinovich et al. (arXiv:2402.12109): Crescendo + encoding 协同

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# 数据结构
# ============================================================


@dataclass
class TransformationStep:
    """单步 Converter 变换记录 (后处理重转换中间步骤)。.

    L5 对齐: pyrit_ai300/src/reporting/converter_log.py 方案B
    使用 PyRIT 原生 Converter.convert_async() 对原始 prompt 重新执行转换链,
    记录每步中间输出, 展示完整的变换过程。
    """

    step: int = 0
    converter_class: str = ""
    input_text: str = ""
    output_text: str = ""
    is_llm_converter: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "converter_class": self.converter_class,
            "input_text": self.input_text[:500],
            "output_text": self.output_text[:500],
            "is_llm_converter": self.is_llm_converter,
            "error": self.error,
        }


@dataclass
class ConverterLogEntry:
    """单次 Converter 变换日志。."""

    attack_id: str
    technique_name: str
    converter_chain: list[str] = field(default_factory=list)
    original_prompt: str = ""
    transformed_prompt: str = ""
    converter_target_used: bool = False
    success: bool = False
    error: str | None = None
    # L5 对齐: 后处理重转换中间步骤 (方案B)
    transformation_steps: list[TransformationStep] = field(default_factory=list)

    @property
    def chain_name(self) -> str:
        """获取 Converter 链的简短名 (如 "Base64→ROT13")。."""
        return "→".join(self.converter_chain) if self.converter_chain else "none"


@dataclass
class ConverterChainStats:
    """Converter 链统计。."""

    chain_name: str
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    errors: int = 0

    @property
    def success_rate(self) -> float:
        total = self.successes + self.failures
        if total == 0:
            return 0.0
        return self.successes / total


@dataclass
class ConverterLogReport:
    """Converter 转换日志报告。."""

    total_attacks: int = 0
    total_with_converters: int = 0
    total_without_converters: int = 0
    total_errors: int = 0
    chain_stats: dict[str, ConverterChainStats] = field(default_factory=dict)
    entries: list[ConverterLogEntry] = field(default_factory=list)
    converter_target_usage: int = 0

    @property
    def converter_usage_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.total_with_converters / self.total_attacks

    def to_dict(self) -> dict[str, Any]:
        """转换为字典 (用于报告序列化)。."""
        return {
            "total_attacks": self.total_attacks,
            "total_with_converters": self.total_with_converters,
            "total_without_converters": self.total_without_converters,
            "total_errors": self.total_errors,
            "converter_usage_rate": round(self.converter_usage_rate, 4),
            "converter_target_usage": self.converter_target_usage,
            "chain_stats": {
                name: {
                    "total_uses": s.total_uses,
                    "successes": s.successes,
                    "failures": s.failures,
                    "errors": s.errors,
                    "success_rate": round(s.success_rate, 4),
                }
                for name, s in self.chain_stats.items()
            },
            # L5 对齐: 后处理重转换中间步骤
            "transformation_steps": {
                e.attack_id: [s.to_dict() for s in e.transformation_steps]
                for e in self.entries if e.transformation_steps
            },
        }


# ============================================================
# ConverterLogCollector
# ============================================================


class ConverterLogCollector:
    """Converter 转换日志收集器。.

    从 ScenarioResult 的 attack_results 中提取 Converter 变换信息，
    生成聚合统计报告。

    使用方式:
        collector = ConverterLogCollector()
        report = collector.collect(attack_results=result.attack_results)
        print(collector.format_report(report))
    """

    def collect(
        self,
        attack_results: dict[str, list[Any]],
    ) -> ConverterLogReport:
        """从攻击结果中收集 Converter 变换日志。.

        Args:
            attack_results: ScenarioResult.attack_results 字典

        Returns:
            ConverterLogReport: 聚合日志报告
        """
        report = ConverterLogReport()
        chain_stats_map: dict[str, ConverterChainStats] = {}

        for attack_id, results in attack_results.items():
            for ar in results:
                entry = self._extract_entry(attack_id, ar)
                report.entries.append(entry)
                report.total_attacks += 1

                if entry.converter_chain:
                    report.total_with_converters += 1
                else:
                    report.total_without_converters += 1

                if entry.error:
                    report.total_errors += 1

                if entry.converter_target_used:
                    report.converter_target_usage += 1

                # 链统计
                chain_name = entry.chain_name
                if chain_name not in chain_stats_map:
                    chain_stats_map[chain_name] = ConverterChainStats(chain_name=chain_name)
                stats = chain_stats_map[chain_name]
                stats.total_uses += 1
                if entry.success:
                    stats.successes += 1
                elif entry.error:
                    stats.errors += 1
                else:
                    stats.failures += 1

                # 子结果
                child_results = getattr(ar, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_entry = self._extract_entry(attack_id, child)
                    report.entries.append(child_entry)
                    report.total_attacks += 1

                    if child_entry.converter_chain:
                        report.total_with_converters += 1
                    else:
                        report.total_without_converters += 1

                    child_chain = child_entry.chain_name
                    if child_chain not in chain_stats_map:
                        chain_stats_map[child_chain] = ConverterChainStats(chain_name=child_chain)
                    child_stats = chain_stats_map[child_chain]
                    child_stats.total_uses += 1
                    if child_entry.success:
                        child_stats.successes += 1
                    elif child_entry.error:
                        child_stats.errors += 1
                    else:
                        child_stats.failures += 1

        report.chain_stats = chain_stats_map

        logger.info(
            f"ConverterLogCollector: {report.total_attacks} attacks, "
            f"{report.total_with_converters} with converters "
            f"({report.converter_usage_rate:.1%}), "
            f"{len(chain_stats_map)} unique chains"
        )

        return report

    def format_report(self, report: ConverterLogReport) -> str:
        """生成 Converter 日志报告文本。."""
        lines: list[str] = ["--- Converter 转换日志 ---"]

        lines.append(f"\n  总攻击数: {report.total_attacks}")
        lines.append(f"  使用 Converter: {report.total_with_converters} ({report.converter_usage_rate:.1%})")
        lines.append(f"  未使用 Converter: {report.total_without_converters}")
        lines.append(f"  变换错误: {report.total_errors}")
        lines.append(f"  LLM 辅助 Converter 使用: {report.converter_target_usage}")

        if report.chain_stats:
            lines.append("\n  Converter 链统计 (按成功率排序):")
            lines.append(f"    {'链名':<40} {'总数':>6} {'成功':>6} {'失败':>6} {'错误':>6} {'ASR':>8}")
            lines.append(f"    {'-' * 40} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 8}")

            sorted_stats = sorted(
                report.chain_stats.values(),
                key=lambda s: s.success_rate,
                reverse=True,
            )
            for stats in sorted_stats:
                bar = "█" * int(stats.success_rate * 20)
                lines.append(
                    f"    {stats.chain_name:<40} {stats.total_uses:>6} "
                    f"{stats.successes:>6} {stats.failures:>6} {stats.errors:>6} "
                    f"{stats.success_rate * 100:>7.1f}% {bar}"
                )

        # 异常检测
        error_entries = [e for e in report.entries if e.error]
        if error_entries:
            lines.append(f"\n  [!] 变换异常 ({len(error_entries)} 条):")
            for entry in error_entries[:10]:
                lines.append(f"    {entry.attack_id}: {entry.technique_name} → {entry.error[:80]}")

        return "\n".join(lines)

    def _extract_entry(self, attack_id: str, attack_result: Any) -> ConverterLogEntry:
        """从 AttackResult 提取 Converter 变换日志。."""
        entry = ConverterLogEntry(
            attack_id=attack_id,
            technique_name=self._extract_technique_name(attack_result),
        )

        # 提取成功状态
        outcome = getattr(attack_result, "outcome", None)
        if outcome is not None:
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
            entry.success = outcome_str == "SUCCESS"

        # 提取错误信息
        error_msg = getattr(attack_result, "error_message", None) or getattr(attack_result, "outcome_reason", None)
        if error_msg and entry.success is False:
            entry.error = str(error_msg)[:200]

        # 提取 Converter 链
        entry.converter_chain = self._extract_converter_chain(attack_result)

        # 检测 LLM 辅助 Converter
        entry.converter_target_used = self._check_converter_target_used(attack_result)

        # 提取原始/变换后 prompt (如果可获取)
        entry.original_prompt, entry.transformed_prompt = self._extract_prompts(attack_result)

        return entry

    def _extract_technique_name(self, attack_result: Any) -> str:
        """从 AttackResult 提取技术名 (委托给 AttackResultAnalyzer)。."""
        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

        return AttackResultAnalyzer.extract_technique_name(attack_result)

    def _extract_converter_chain(self, attack_result: Any) -> list[str]:
        """从 AttackResult 提取 Converter 链名列表。."""
        chain: list[str] = []
        identifier = None
        if hasattr(attack_result, "get_attack_strategy_identifier"):
            identifier = attack_result.get_attack_strategy_identifier()

        if identifier is not None:
            children = getattr(identifier, "children", None) or {}
            request_converters = children.get("request_converters")
            if request_converters and isinstance(request_converters, list):
                for conv in request_converters:
                    if isinstance(conv, str):
                        chain.append(conv)
                    else:
                        conv_name = type(conv).__name__
                        chain.append(conv_name)

        return chain

    def _check_converter_target_used(self, attack_result: Any) -> bool:
        """检测是否使用了 LLM 辅助 Converter。."""
        chain = self._extract_converter_chain(attack_result)
        return any(conv in self._LLM_CONVERTERS for conv in chain)

    def _extract_prompts(self, attack_result: Any) -> tuple[str, str]:
        """提取原始和变换后的 prompt (如果可获取)。."""
        original = ""
        transformed = ""

        # 尝试从 conversation 获取
        conversation = getattr(attack_result, "conversation", None)
        if conversation is not None:
            try:
                # PyRIT Conversation 对象
                if hasattr(conversation, "messages"):
                    messages = conversation.messages
                    if messages:
                        # 最后一条 user message 是变换后的
                        for msg in reversed(messages):
                            role = getattr(msg, "role", "")
                            if role == "user":
                                transformed = getattr(msg, "content", "") or ""
                                break
                        # 第一条是原始
                        for msg in messages:
                            role = getattr(msg, "role", "")
                            if role == "user":
                                original = getattr(msg, "content", "") or ""
                                break
            except (RuntimeError, OSError, ValueError):
                pass

        return original[:500], transformed[:500]

    # ============================================================
    # L5 对齐: 后处理重转换 (方案B) — 使用 PyRIT 原生 Converter.convert_async()
    # ============================================================

    #: LLM 辅助 Converter 集合 (需要 converter_target, 非确定性)
    # 修复 P0: 非 dataclass 不能使用 field(), 改为类级常量
    _LLM_CONVERTERS: set[str] = {
        "PersuasionConverter",
        "DecompositionConverter",
        "TranslationConverter",
        "ToneConverter",
        "TaskFramingConverter",
        "CodeChameleonConverter",
        "NoiseConverter",
        "MathObfuscationConverter",
        "ScientificTranslationConverter",
        "TenseConverter",
        "VariationConverter",
        "PolicyPuppetryConverter",
    }

    async def reconvert_async(
        self,
        report: ConverterLogReport,
        *,
        converter_target: Any | None = None,
    ) -> ConverterLogReport:
        """后处理重转换 — 对每个有 Converter 链的条目重新执行转换链。.

        L5 对齐: pyrit_ai300/src/reporting/converter_log.py 方案B。
        使用 PyRIT 原生 ``Converter.convert_async()`` 对原始 prompt 重新执行
        转换链, 记录每步中间输出, 展示完整的变换过程。

        设计原则:
          - 不修改 PyRIT 核心执行路径
          - 非 LLM 转换器可本地执行 (确定性, 无需 API 调用)
          - LLM 转换器需要 converter_target (可选, 缺失时标注为 "需 LLM")
          - 数据驱动: 从 AttackResult → identifier.children → converter 类名 → chain name

        Args:
            report: 已收集的 ConverterLogReport
            converter_target: LLM 辅助转换器使用的目标 (可选)

        Returns:
            更新后的 ConverterLogReport (填充 transformation_steps 字段)
        """
        for entry in report.entries:
            if not entry.converter_chain or not entry.original_prompt:
                continue

            entry.transformation_steps = await self._reconvert_entry_async(
                entry, converter_target,
            )

        return report

    async def _reconvert_entry_async(
        self,
        entry: ConverterLogEntry,
        converter_target: Any | None,
    ) -> list[TransformationStep]:
        """对单个条目执行重转换, 记录每步中间输出。."""
        steps: list[TransformationStep] = []
        current_text = entry.original_prompt

        for step_idx, conv_name in enumerate(entry.converter_chain, 1):
            step = TransformationStep(
                step=step_idx,
                converter_class=conv_name,
                input_text=current_text[:500],
            )

            is_llm = conv_name in self._LLM_CONVERTERS
            step.is_llm_converter = is_llm

            if is_llm and converter_target is None:
                step.output_text = "(需 LLM converter_target)"
                step.error = "LLM converter target not provided"
                steps.append(step)
                break

            try:
                converter = self._instantiate_converter(conv_name, converter_target)
                if converter is None:
                    step.error = f"Cannot instantiate {conv_name}"
                    step.output_text = current_text[:500]
                    steps.append(step)
                    continue

                from pyrit.models import PromptRequestPiece

                piece = PromptRequestPiece(
                    role="user",
                    original_value=current_text,
                )
                converted_pieces = await converter.convert_async(request_prompt=piece)

                if converted_pieces:
                    output = getattr(converted_pieces[0], "converted_value", "") or current_text
                    step.output_text = output[:500]
                    current_text = output
                else:
                    step.error = "Converter returned empty result"
                    step.output_text = current_text[:500]
            except (RuntimeError, OSError, ValueError) as e:
                step.error = str(e)[:200]
                step.output_text = current_text[:500]

            steps.append(step)

        return steps

    def _instantiate_converter(self, conv_name: str, converter_target: Any | None) -> Any:
        """通过类名实例化 Converter (复用 chains.py 的 _conv() 惰性导入)。.

        修复 P0:
          1. 原代码从已废弃的 ``pyrit.prompt_converter`` 导入 (1.0.0+ 迁移到 ``pyrit.converter``),
             导致 ImportError 被静默吞掉, 函数永远返回 None
          2. 复用 ``chains.py`` 的 ``_conv()`` 惰性导入机制, 消除重复导入路径
          3. Converter 覆盖从 8 个扩展到全部 35+ 个
        """
        from pipeline.converters.chains import _conv

        # 非 LLM Converter: 无参构造
        _NON_LLM_NO_ARG: set[str] = {
            "Base64Converter", "ROT13Converter", "CaesarConverter",
            "AtbashConverter", "LeetspeakConverter", "UrlConverter",
            "UnicodeConfusableConverter", "UnicodeSubstitutionConverter",
            "AsciiArtConverter", "FlipConverter", "EmojiConverter",
            "ZalgoConverter", "ZeroWidthConverter", "BinaryConverter",
            "MorseConverter", "BrailleConverter", "NatoConverter",
            "StringJoinConverter", "SuperscriptConverter",
            "BidiConverter", "RandomCapitalLettersConverter",
            "SuffixAppendConverter", "CharacterSpaceConverter",
            "InsertPunctuationConverter", "RepeatTokenConverter",
            "AsciiSmugglerConverter", "SneakyBitsSmugglerConverter",
            "Base2048Converter", "EcojiConverter",
            "UnicodeReplacementConverter", "TatweelConverter",
            "SearchReplaceConverter", "FirstLetterConverter",
            "CharSwapConverter", "DiacriticConverter",
        }

        try:
            if conv_name in _NON_LLM_NO_ARG:
                cls = _conv(conv_name)
                return cls()

            # LLM Converter: 需要 converter_target
            if conv_name in self._LLM_CONVERTERS and converter_target is not None:
                cls = _conv(conv_name)
                if conv_name == "PersuasionConverter":
                    return cls(converter_target=converter_target, persuasion_template="authority_endorsement")
                if conv_name == "TranslationConverter":
                    return cls(converter_target=converter_target, languages=["en"])
                # 其他 LLM Converter: 通用单参构造
                return cls(converter_target=converter_target)

            return None
        except (ImportError, AttributeError) as e:
            logger.warning(f"Cannot import converter {conv_name}: {e}")
            return None

    def format_transformation_log_markdown(self, report: ConverterLogReport) -> str:
        """生成后处理重转换日志 Markdown 章节 (L5 对齐报告集成)。."""
        lines: list[str] = ["### Converter Transformation Log", ""]

        entries_with_steps = [e for e in report.entries if e.transformation_steps]
        if not entries_with_steps:
            lines.append("*No transformation steps available (run reconvert_async first).*")
            return "\n".join(lines)

        for entry in entries_with_steps:
            lines.extend([
                f"#### Attack: {entry.attack_id} ({entry.technique_name})",
                "",
                f"**Chain**: `{entry.chain_name}`",
                f"**Original**: `{entry.original_prompt[:200]}...`",
                "",
                "| Step | Converter | LLM? | Input | Output | Error |",
                "|------|-----------|------|-------|--------|-------|",
            ])
            for step in entry.transformation_steps:
                inp = step.input_text[:80].replace("|", "\\|").replace("\n", " ")
                outp = step.output_text[:80].replace("|", "\\|").replace("\n", " ")
                llm = "Yes" if step.is_llm_converter else "No"
                err = step.error or ""
                lines.append(
                    f"| {step.step} | {step.converter_class} | {llm} | "
                    f"`{inp}...` | `{outp}...` | {err} |"
                )
            lines.append("")

        return "\n".join(lines)


# ============================================================
# L5 对齐: 命名一致性 + 从 AttackResult 提取 Converter 信息
# ============================================================

#: snake_case 技术名 → PascalCase 攻击类名映射
TECHNIQUE_NAME_MAP: dict[str, str] = {
    "prompt_sending": "PromptSendingAttack",
    "multi_prompt_sending": "MultiPromptSendingAttack",
    "many_shot": "ManyShotJailbreakAttack",
    "skeleton": "SkeletonKeyAttack",
    "chunked_request": "ChunkedRequestAttack",
    "red_teaming": "RedTeamingAttack",
    "crescendo": "CrescendoAttack",
    "crescendo_simulated": "CrescendoAttack",
    "tap": "TAPAttack",
    "pair": "PAIRAttack",
    "tree_of_attacks_pruned": "TreeOfAttacksWithPruningAttack",
    "sequential": "SequentialAttack",
}

#: PascalCase 攻击类名 → snake_case 技术名映射 (反向)
PASCAL_TO_SNAKE: dict[str, str] = {}
for _snake, _pascal in TECHNIQUE_NAME_MAP.items():
    if _pascal not in PASCAL_TO_SNAKE:
        PASCAL_TO_SNAKE[_pascal] = _snake


def get_attack_class_name(technique_name: str) -> str:
    """将 snake_case 技术名映射为 PascalCase 攻击类名。."""
    return TECHNIQUE_NAME_MAP.get(technique_name, technique_name)


def get_technique_name(class_name: str) -> str:
    """将 PascalCase 攻击类名映射为 snake_case 技术名。."""
    return PASCAL_TO_SNAKE.get(class_name, class_name)


def format_technique_display(technique_name: str) -> str:
    """格式化技术名显示 (同时展示 snake_case 和 PascalCase)。

    用于预执行展示和报告, 消除命名不一致。
    """
    class_name = get_attack_class_name(technique_name)
    if class_name != technique_name:
        return f"{technique_name} ({class_name})"
    return technique_name


def extract_converter_info_from_result(attack_result: Any) -> dict[str, Any]:
    """从 AttackResult 提取 Converter 信息。

    当 labels 中没有 converter_chain_name 时, 从 identifier.children
    提取 converter 类名列表, 并尝试反向映射到 chain name。

    数据流:
      AttackResult.get_attack_strategy_identifier()
        → identifier.children["request_converters"]
        → [ConverterIdentifier.class_name, ...]

    Args:
        attack_result: PyRIT AttackResult 实例

    Returns:
        包含以下字段的字典:
        - converter_class_names: list[str] — converter 类名列表
        - converter_chain_name: str | None — 匹配到的 chain name
        - has_converters: bool — 是否使用了 converter
    """
    result: dict[str, Any] = {
        "converter_class_names": [],
        "converter_chain_name": None,
        "has_converters": False,
    }

    # 优先从 labels 获取
    labels = getattr(attack_result, "labels", None) or {}
    if isinstance(labels, dict):
        chain_name = labels.get("converter_chain_name")
        if chain_name:
            result["converter_chain_name"] = chain_name
            result["has_converters"] = True
            class_names_str = labels.get("converter_class_names", "")
            if class_names_str:
                result["converter_class_names"] = [
                    n.strip() for n in class_names_str.split(",") if n.strip()
                ]
            return result

    # 从 identifier.children 提取 (PyRIT 原生 API)
    identifier = None
    if hasattr(attack_result, "get_attack_strategy_identifier"):
        try:
            identifier = attack_result.get_attack_strategy_identifier()
        except (RuntimeError, OSError, ValueError):
            pass

    if identifier is not None:
        class_names = _extract_converter_class_names_from_identifier(identifier)
        if class_names:
            result["converter_class_names"] = class_names
            result["has_converters"] = True
            result["converter_chain_name"] = "→".join(class_names)

    # SequentialAttackResult: 检查子结果
    if not result["has_converters"]:
        child_results = getattr(attack_result, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            child_info = extract_converter_info_from_result(child)
            if child_info["has_converters"]:
                result["converter_class_names"].extend(
                    child_info["converter_class_names"]
                )
                if child_info["converter_chain_name"] and not result["converter_chain_name"]:
                    result["converter_chain_name"] = child_info["converter_chain_name"]
                result["has_converters"] = True

    # 去重
    result["converter_class_names"] = list(dict.fromkeys(result["converter_class_names"]))

    return result


def _extract_converter_class_names_from_identifier(identifier: Any) -> list[str]:
    """从 ComponentIdentifier 提取 Converter 类名列表。

    PyRIT 原生 API:
      identifier.children["request_converters"] = [ConverterIdentifier, ...]
      ConverterIdentifier.class_name = "Base64Converter" 等
    """
    class_names: list[str] = []
    children = getattr(identifier, "children", None) or {}

    req_converters = children.get("request_converters")
    if req_converters:
        if isinstance(req_converters, list):
            for conv_id in req_converters:
                cn = getattr(conv_id, "class_name", "")
                if cn:
                    class_names.append(cn)
        else:
            cn = getattr(req_converters, "class_name", "")
            if cn:
                class_names.append(cn)

    resp_converters = children.get("response_converters")
    if resp_converters:
        if isinstance(resp_converters, list):
            for conv_id in resp_converters:
                cn = getattr(conv_id, "class_name", "")
                if cn:
                    class_names.append(cn)

    return class_names
