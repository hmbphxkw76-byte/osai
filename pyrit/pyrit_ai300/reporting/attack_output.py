# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Output Adapter
攻击结果输出适配器：利用 PyRIT 原生 output 模块渲染攻击结果

功能：
1. 调用 PyRIT 的 output_attack_async 渲染美观的控制台输出 (pretty 格式)
2. 调用 MarkdownAttackResultMemoryPrinter.render_async 生成 Markdown 报告内容
3. 叠加 OWASP LLM Top 10 分类信息，对齐安全评估标准
4. 支持 StdoutSink (控制台) 和 FileSink (文件) 两种输出目标
5. 支持多轮攻击的 Adversarial Conversation 和 Pruned Conversations 渲染

PyRIT 0.14.0 Output 模块架构：
- 便利函数: output_attack_async(result, format, sink, ...)
- 三层继承: PrinterBase → PrettyAttackResultPrinter → PrettyAttackResultMemoryPrinter
- 组合模式: AttackResultPrinter = ConversationPrinter + ScorePrinter
- Sink 路由: StdoutSink / FileSink / IPythonMarkdownSink

使用方式：
    adapter = AttackOutputAdapter()
    # 控制台输出 (pretty 格式)
    adapter.print_results_console(attack_results, owasp_mapping={"llm01": "Prompt Injection"})
    # 生成 Markdown 片段 (嵌入报告)
    md = adapter.render_results_markdown(attack_results, owasp_id="llm01")
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# OWASP LLM Top 10 (2025) 映射表
OWASP_LLM_MAPPINGS: Dict[str, Dict[str, str]] = {
    "LLM01": {"title": "Prompt Injection", "category": "prompt_injection"},
    "LLM02": {"title": "Sensitive Information Disclosure", "category": "info_leakage"},
    "LLM03": {"title": "Supply Chain Vulnerabilities", "category": "supply_chain"},
    "LLM04": {"title": "Data and Model Poisoning", "category": "model_poisoning"},
    "LLM05": {"title": "Improper Output Handling", "category": "output_handling"},
    "LLM06": {"title": "Excessive Agency", "category": "excessive_agency"},
    "LLM07": {"title": "System Prompt Leakage", "category": "system_prompt_leak"},
    "LLM08": {"title": "Vector and Embedding Weaknesses", "category": "vector_db"},
    "LLM09": {"title": "Misinformation", "category": "misinformation"},
    "LLM10": {"title": "Unbounded Consumption", "category": "resource_exhaustion"},
}


class AttackOutputAdapter:
    """
    攻击结果输出适配器

    封装 PyRIT 原生 output 模块，叠加 OWASP LLM Top 10 元数据。

    核心方法：
        print_results_console: 控制台 pretty 输出 (ANSI 彩色)
        render_results_markdown: 生成 Markdown 片段 (嵌入报告)
        render_summary_markdown: 生成精简摘要 Markdown
        write_results_to_file: 写入文件 (无 ANSI 颜色)
    """

    def __init__(
        self,
        width: int = 100,
        indent_size: int = 2,
        enable_colors: bool = True,
    ):
        """
        Args:
            width: 输出宽度 (字符)
            indent_size: 缩进空格数
            enable_colors: 是否启用 ANSI 颜色 (控制台 True, 文件 False)
        """
        self._width = width
        self._indent_size = indent_size
        self._enable_colors = enable_colors

    # ── 公开接口 ──────────────────────────────────────────────────────

    def print_results_console(
        self,
        attack_results: List[Any],
        owasp_mapping: Optional[Dict[str, str]] = None,
        *,
        include_adversarial: bool = True,
        include_auxiliary_scores: bool = False,
        include_pruned: bool = False,
    ) -> None:
        """
        控制台 pretty 输出：使用 PyRIT 原生 output_attack_async

        Args:
            attack_results: PyRIT AttackResult 对象列表
            owasp_mapping: OWASP ID → 描述映射 (如 {"llm01": "Prompt Injection"})
            include_adversarial: 是否包含对抗对话 (多轮攻击)
            include_auxiliary_scores: 是否包含辅助评分
            include_pruned: 是否包含剪枝对话 (TAP 攻击)
        """
        from pyrit.output import output_attack_async
        from pyrit_ai300.utils.async_helper import run_async

        if not attack_results:
            self._print_owasp_banner(owasp_mapping or {})
            print("  (无攻击结果)")
            return

        # 打印 OWASP 横幅
        self._print_owasp_banner(owasp_mapping or {})

        for result in attack_results:
            if result is None:
                continue
            try:
                run_async(
                    output_attack_async(
                        result,
                        format="pretty",
                        include_adversarial_conversation=include_adversarial,
                        include_auxiliary_scores=include_auxiliary_scores,
                        include_pruned_conversations=include_pruned,
                    )
                )
            except Exception as e:
                logger.warning("PyRIT output failed for result %s: %s",
                               getattr(result, "conversation_id", "?"), e)
                # Fallback: 打印基本信息
                self._print_fallback(result, owasp_mapping or {})

    def render_results_markdown(
        self,
        attack_results: List[Any],
        owasp_id: str = "",
        owasp_title: str = "",
    ) -> str:
        """
        生成 Markdown 片段：嵌入评估报告的 Detailed Findings 部分

        使用 PyRIT 的 MarkdownAttackResultMemoryPrinter.render_async

        Args:
            attack_results: PyRIT AttackResult 对象列表
            owasp_id: OWASP LLM Top 10 ID (如 "LLM01")
            owasp_title: OWASP 标题描述

        Returns:
            Markdown 文本
        """
        from pyrit.output.attack_result.markdown import (
            MarkdownAttackResultMemoryPrinter,
        )
        from pyrit_ai300.utils.async_helper import run_async

        if not attack_results:
            return self._render_empty_markdown(owasp_id, owasp_title)

        sections: List[str] = []

        # OWASP 头部
        owasp_header = self._render_owasp_header_md(owasp_id, owasp_title, attack_results)
        sections.append(owasp_header)

        # 每个 AttackResult 的 Markdown 渲染
        for idx, result in enumerate(attack_results, 1):
            if result is None:
                continue
            try:
                printer = MarkdownAttackResultMemoryPrinter()
                md = run_async(
                    printer.render_async(
                        result,
                        include_adversarial_conversation=True,
                        include_auxiliary_scores=False,
                        include_pruned_conversations=False,
                    )
                )
                sections.append(f"\n### Attack Result #{idx}\n")
                sections.append(md)
            except Exception as e:
                logger.warning("Markdown render failed for result #%d: %s", idx, e)
                sections.append(self._render_fallback_md(result, idx, owasp_id))

        return "\n".join(sections)

    def render_summary_markdown(
        self,
        attack_results: List[Any],
        owasp_id: str = "",
    ) -> str:
        """
        生成精简摘要 Markdown：仅包含攻击摘要 (不含完整对话)

        Args:
            attack_results: PyRIT AttackResult 对象列表
            owasp_id: OWASP LLM Top 10 ID

        Returns:
            精简摘要 Markdown 文本
        """
        from pyrit.output.attack_result.markdown import (
            MarkdownAttackResultMemoryPrinter,
        )
        from pyrit_ai300.utils.async_helper import run_async

        if not attack_results:
            return f"\n*No attack results for {owasp_id or 'N/A'}*\n"

        lines: List[str] = []
        success_count = sum(
            1 for r in attack_results
            if r and getattr(r, "outcome", None) and r.outcome.name == "SUCCESS"
        )
        total = len(attack_results)

        lines.append(f"\n#### Summary for {owasp_id or 'N/A'}\n")
        lines.append(f"- **Total Attacks:** {total}")
        lines.append(f"- **Successful:** {success_count}")
        lines.append(f"- **Failed:** {total - success_count}")
        lines.append(f"- **Success Rate:** {(success_count / total * 100):.0f}%" if total else "  N/A")
        lines.append("")

        # 每个 AttackResult 的摘要
        for idx, result in enumerate(attack_results, 1):
            if result is None:
                continue
            try:
                printer = MarkdownAttackResultMemoryPrinter()
                md_lines = run_async(printer._get_summary_markdown_async(result))
                lines.append(f"\n**Result #{idx}:**\n")
                lines.extend(md_lines)
            except Exception as e:
                logger.debug("Summary render failed for result #%d: %s", idx, e)

        return "\n".join(lines)

    def write_results_to_file(
        self,
        attack_results: List[Any],
        output_path: str,
        owasp_mapping: Optional[Dict[str, str]] = None,
        *,
        format: str = "markdown",
        include_adversarial: bool = True,
    ) -> str:
        """
        写入文件：使用 PyRIT FileSink

        Args:
            attack_results: PyRIT AttackResult 对象列表
            output_path: 输出文件路径
            owasp_mapping: OWASP ID → 描述映射
            format: "markdown" 或 "pretty"
            include_adversarial: 是否包含对抗对话

        Returns:
            实际写入的文件路径
        """
        from pyrit.output import FileSink, output_attack_async
        from pyrit_ai300.utils.async_helper import run_async

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        sink = FileSink(path=path, mode="w")

        for result in attack_results:
            if result is None:
                continue
            try:
                run_async(
                    output_attack_async(
                        result,
                        format=format,
                        sink=sink,
                        include_adversarial_conversation=include_adversarial,
                    )
                )
            except Exception as e:
                logger.warning("File output failed for result %s: %s",
                               getattr(result, "conversation_id", "?"), e)

        logger.info("Attack results written to: %s", path)
        return str(path)

    # ── 从 result dicts 中重建 AttackResult (备用方案) ──────────────

    @staticmethod
    def reconstruct_from_dicts(
        result_dicts: List[Dict[str, Any]],
    ) -> List[Any]:
        """
        从结果字典列表中重建 AttackResult 对象 (使用 CentralMemory)

        当 AttackResult 对象不可用时，可从 conversation_id 重建。
        需要 CentralMemory 中存在对应的对话记录。

        Args:
            result_dicts: 包含 conversation_id 的结果字典列表

        Returns:
            AttackResult 对象列表 (可能包含 None)
        """
        from pyrit.memory import CentralMemory

        # 防御性检查：CentralMemory 可能未初始化
        try:
            memory = CentralMemory.get_memory_instance()
        except (ValueError, RuntimeError):
            logger.debug("CentralMemory not initialized, cannot reconstruct")
            return [None] * len(result_dicts)

        results: List[Any] = []

        for rd in result_dicts:
            conv_id = rd.get("conversation_id")
            if not conv_id:
                results.append(None)
                continue

            try:
                # 尝试从内存中获取对话并重建 AttackResult
                conversation = list(memory.get_conversation(conversation_id=conv_id))
                if not conversation:
                    results.append(None)
                    continue

                # 创建一个简化版的 AttackResult (仅含基本信息)
                from pyrit.executor.attack import AttackResult, AttackOutcome

                outcome_str = rd.get("outcome", "UNDETERMINED")
                outcome = AttackOutcome[outcome_str] if outcome_str in AttackOutcome.__members__ else AttackOutcome.UNDETERMINED

                result = AttackResult(
                    objective=rd.get("payload", rd.get("objective", "")),
                    outcome=outcome,
                    conversation_id=conv_id,
                    outcome_reason=rd.get("response", ""),
                )
                results.append(result)
            except Exception as e:
                logger.debug("Reconstruct failed for conv_id=%s: %s", conv_id, e)
                results.append(None)

        return results

    # ── 内部辅助方法 ──────────────────────────────────────────────────

    def _print_owasp_banner(self, owasp_mapping: Dict[str, str]) -> None:
        """打印 OWASP 分类横幅"""
        width = self._width
        print()
        print("═" * width)
        title = "OWASP LLM Top 10 Attack Results"
        print(title.center(width))
        if owasp_mapping:
            for owasp_id, desc in owasp_mapping.items():
                print(f"  {owasp_id.upper():8s} | {desc}")
        print("═" * width)

    def _print_fallback(
        self,
        result: Any,
        owasp_mapping: Dict[str, str],
    ) -> None:
        """Fallback 输出 (PyRIT output 不可用时)"""
        conv_id = getattr(result, "conversation_id", "N/A")
        outcome = getattr(result, "outcome", "UNKNOWN")
        objective = getattr(result, "objective", "N/A")
        print(f"  Attack Result: {outcome} | Conv: {conv_id}")
        print(f"  Objective: {objective[:80]}")

    def _render_owasp_header_md(
        self,
        owasp_id: str,
        owasp_title: str,
        attack_results: List[Any],
    ) -> str:
        """渲染 OWASP 头部 Markdown"""
        owasp_upper = owasp_id.upper() if owasp_id else "N/A"
        owasp_meta = OWASP_LLM_MAPPINGS.get(owasp_upper, {})
        if not owasp_title:
            owasp_title = owasp_meta.get("title", "")

        success_count = sum(
            1 for r in attack_results
            if r and getattr(r, "outcome", None) and r.outcome.name == "SUCCESS"
        )
        total = len(attack_results)

        lines = [
            f"## {owasp_upper}: {owasp_title}\n",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| OWASP ID | `{owasp_upper}` |",
            f"| Total Attacks | {total} |",
            f"| Successful | {success_count} |",
            f"| Failed | {total - success_count} |",
            f"| Success Rate | {(success_count / total * 100):.0f}% |" if total else f"| Success Rate | N/A |",
            "",
        ]
        return "\n".join(lines)

    def _render_empty_markdown(self, owasp_id: str, owasp_title: str) -> str:
        """渲染空结果 Markdown"""
        owasp_upper = owasp_id.upper() if owasp_id else "N/A"
        if not owasp_title:
            owasp_title = OWASP_LLM_MAPPINGS.get(owasp_upper, {}).get("title", "")
        return f"\n## {owasp_upper}: {owasp_title}\n\n*No attack results available.*\n"

    def _render_fallback_md(
        self,
        result: Any,
        idx: int,
        owasp_id: str,
    ) -> str:
        """渲染 Fallback Markdown"""
        conv_id = getattr(result, "conversation_id", "N/A")
        outcome = getattr(result, "outcome", "UNKNOWN")
        objective = getattr(result, "objective", "N/A")
        return (
            f"\n### Attack Result #{idx} (Fallback)\n"
            f"- **Status:** {outcome}\n"
            f"- **Conversation ID:** `{conv_id}`\n"
            f"- **Objective:** {objective[:200]}\n"
        )
