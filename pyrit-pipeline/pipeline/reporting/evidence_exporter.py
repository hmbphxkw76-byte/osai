# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""证据导出器 — PyRIT 原生 render_async + 三级证据链集成。

L5 对齐 PyRIT 1.0.0 output 模块:
  - 使用 MarkdownAttackResultMemoryPrinter.render_async() 生成每个攻击 Markdown
  - 使用 MarkdownConversationMemoryPrinter.render_async() 渲染对话历史
  - 使用 MarkdownScorePrinter.render_async() 渲染评分
  - 支持 include_reasoning_trace (o1/o3 推理模型)
  - 支持 blur_images (图片模糊, 保护审查者)
  - 生成 evidence.json + attack_summary.csv + owasp_coverage_matrix.csv
  - 打包为 ZIP 证据包

学术依据:
  - HarmBench (arXiv:2402.04249): 标准化红队证据收集
  - JailbreakBench (arXiv:2402.01135): 漏洞披露最佳实践
"""

from __future__ import annotations

import csv
import io
import json
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.memory import CentralMemory

from pipeline.reporting.report_generator import _get_attack_type, _get_outcome_str, _safe_get

logger = logging.getLogger(__name__)


class EvidenceExporter:
    """证据导出器 — 利用 PyRIT MemoryInterface + 原生 Markdown 打印器。

    L5 对齐 PyRIT 1.0.0 output 模块:
      - 使用 render_async() 直接获取渲染字符串, 消除 write_async()+read-back 冗余 I/O
      - 每个攻击生成独立 Markdown 文件
      - 每个对话生成独立 Markdown 文件
      - 汇总对话历史使用原生 MarkdownConversationMemoryPrinter
    """

    def __init__(
        self,
        evidence_dir: Path,
        *,
        include_reasoning_trace: bool = True,
        blur_images: bool = False,
        blur_radius: int = 20,
    ):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.include_reasoning_trace = include_reasoning_trace
        self.blur_images = blur_images
        self.blur_radius = blur_radius

        # 子目录
        (self.evidence_dir / "attacks").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "conversations").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "scores").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "blurred").mkdir(parents=True, exist_ok=True)

    async def export_all_evidence(
        self,
        attack_results: list[Any],
        owasp_coverage: dict[str, dict[str, Any]] | None = None,
    ) -> Path:
        """导出完整证据包。

        Returns:
            证据包 zip 文件路径
        """
        memory = CentralMemory.get_memory_instance()

        # 提取对话 ID
        conversation_ids = list(set(
            str(_safe_get(ar, "conversation_id"))
            for ar in attack_results
            if _safe_get(ar, "conversation_id")
        ))

        # 获取消息片段和评分
        message_pieces = []
        scores_for_pieces = []
        if conversation_ids:
            for conv_id in conversation_ids:
                pieces = memory.get_message_pieces(conversation_id=conv_id)
                message_pieces.extend(pieces)
                piece_ids = [str(p.id) for p in pieces]
                if piece_ids:
                    piece_scores = memory.get_prompt_scores(prompt_ids=piece_ids)
                    scores_for_pieces.extend(piece_scores)

        # 1. 生成 evidence.json
        evidence_data = self._build_evidence_json(
            attack_results, message_pieces, scores_for_pieces, conversation_ids,
        )

        # 2. 生成每个攻击的 Markdown
        attack_md_files = await self._export_attack_markdowns(attack_results)

        # 3. 生成每个对话的 Markdown
        conversation_md_files = await self._export_conversation_markdowns(
            memory, conversation_ids, attack_results,
        )

        # 4. 生成汇总对话历史
        conversation_summary = await self._render_conversation_log(
            memory, attack_results, conversation_ids, scores_for_pieces,
        )

        # 5. 生成评分 Markdown
        score_md_files = await self._export_score_markdowns(scores_for_pieces)

        # 6. 生成 CSV
        attack_csv = self._render_attack_summary_csv(attack_results)
        coverage_csv = self._render_coverage_matrix_csv(owasp_coverage or {})
        timeline_csv = self._render_attack_timeline_csv(attack_results)

        # 打包为 zip
        archive_path = self.evidence_dir.parent / f"{self.evidence_dir.name}_evidence.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr("evidence.json", json.dumps(evidence_data, indent=2, ensure_ascii=False, default=str))
            zipf.writestr("conversation_history.md", conversation_summary)
            zipf.writestr("attack_summary.csv", attack_csv)
            zipf.writestr("owasp_coverage_matrix.csv", coverage_csv)
            zipf.writestr("attack_timeline.csv", timeline_csv)

            for filename, content in attack_md_files:
                zipf.writestr(f"attacks/{filename}", content)
            for filename, content in conversation_md_files:
                zipf.writestr(f"conversations/{filename}", content)
            for filename, content in score_md_files:
                zipf.writestr(f"scores/{filename}", content)

        logger.info(f"Evidence archive: {archive_path}")
        return archive_path

    def _build_evidence_json(
        self,
        attack_results: list[Any],
        message_pieces: list[Any],
        scores: list[Any],
        conversation_ids: list[str],
    ) -> dict[str, Any]:
        """构建结构化 evidence.json (使用 model_dump)。"""

        def _safe_dump(obj):
            if hasattr(obj, "model_dump"):
                try:
                    return obj.model_dump(mode="json")
                except Exception:
                    return str(obj)
            return str(obj)

        return {
            "export_time": datetime.now().isoformat(),
            "attack_results": [_safe_dump(ar) for ar in attack_results],
            "attack_results_count": len(attack_results),
            "message_pieces": [_safe_dump(p) for p in message_pieces],
            "scores": [_safe_dump(s) for s in scores],
            "conversation_ids": conversation_ids,
        }

    async def _export_attack_markdowns(self, attack_results: list[Any]) -> list[tuple[str, str]]:
        """使用 MarkdownAttackResultMemoryPrinter.render_async() 生成每个攻击的 Markdown。"""
        files: list[tuple[str, str]] = []

        try:
            from pyrit.output.attack_result.markdown import MarkdownAttackResultMemoryPrinter
            printer = MarkdownAttackResultMemoryPrinter(
                blur_images=self.blur_images,
                blur_radius=self.blur_radius,
            )
        except ImportError:
            logger.warning("MarkdownAttackResultMemoryPrinter not available, using fallback")
            for i, ar in enumerate(attack_results, 1):
                is_success = _get_outcome_str(ar).upper() == "SUCCESS"
                suffix = "_success" if is_success else ""
                filename = f"attack_{i:04d}{suffix}.md"
                content = f"# Attack {i}\n\n- Objective: {_safe_get(ar, 'objective', 'N/A')}\n- Outcome: {_get_outcome_str(ar)}\n"
                files.append((filename, content))
            return files

        for i, ar in enumerate(attack_results, 1):
            is_success = _get_outcome_str(ar).upper() == "SUCCESS"
            suffix = "_success" if is_success else ""
            filename = f"attack_{i:04d}{suffix}.md"
            file_path = self.evidence_dir / "attacks" / filename

            try:
                content = await printer.render_async(
                    ar,
                    include_auxiliary_scores=True,
                    include_pruned_conversations=True,
                    include_adversarial_conversation=True,
                )
                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                logger.warning(f"Failed to export attack #{i}: {e}")
                fallback = f"# Attack {i}\n\n*Export failed: {e}*\n\n- Objective: {_safe_get(ar, 'objective', 'N/A')}\n- Outcome: {_get_outcome_str(ar)}\n"
                files.append((filename, fallback))

        return files

    async def _export_conversation_markdowns(
        self,
        memory: Any,
        conversation_ids: list[str],
        attack_results: list[Any],
    ) -> list[tuple[str, str]]:
        """使用 MarkdownConversationMemoryPrinter.render_async() 生成每个对话的 Markdown。"""
        files: list[tuple[str, str]] = []

        try:
            from pyrit.output.conversation.markdown import MarkdownConversationMemoryPrinter
            from pyrit.output.score.markdown import MarkdownScorePrinter

            score_printer = MarkdownScorePrinter()
            printer = MarkdownConversationMemoryPrinter(
                score_printer=score_printer,
                blur_images=self.blur_images,
                blur_radius=self.blur_radius,
            )
        except ImportError:
            logger.warning("MarkdownConversationMemoryPrinter not available")
            return files

        # 构建成功对话 ID 集合
        success_conv_ids = set()
        for ar in attack_results:
            if _get_outcome_str(ar).upper() == "SUCCESS":
                conv_id = str(_safe_get(ar, "conversation_id", ""))
                if conv_id:
                    success_conv_ids.add(conv_id)

        for conv_id in conversation_ids:
            suffix = "_success" if conv_id in success_conv_ids else ""
            filename = f"conv_{conv_id[:8]}{suffix}.md"
            file_path = self.evidence_dir / "conversations" / filename

            try:
                messages = list(memory.get_conversation_messages(conversation_id=conv_id))
                if not messages:
                    continue

                content = await printer.render_async(
                    messages,
                    include_scores=True,
                    include_reasoning_trace=self.include_reasoning_trace,
                )
                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                logger.warning(f"Failed to export conversation {conv_id}: {e}")

        return files

    async def _render_conversation_log(
        self,
        memory: Any,
        attack_results: list[Any],
        conversation_ids: list[str],
        scores: list[Any],
    ) -> str:
        """渲染汇总对话历史 Markdown。"""
        lines = [
            f"# AI Conversation History",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Attack Results: {len(attack_results)}",
            f"Total Conversations: {len(conversation_ids)}",
            "",
            "---",
            "",
        ]

        try:
            from pyrit.output.conversation.markdown import MarkdownConversationMemoryPrinter
            from pyrit.output.score.markdown import MarkdownScorePrinter

            score_printer = MarkdownScorePrinter()
            conv_printer = MarkdownConversationMemoryPrinter(
                score_printer=score_printer,
                blur_images=self.blur_images,
                blur_radius=self.blur_radius,
            )
        except ImportError:
            conv_printer = None

        ar_by_conv = {}
        for ar in attack_results:
            conv_id = str(_safe_get(ar, "conversation_id", ""))
            if conv_id:
                ar_by_conv[conv_id] = ar

        for conv_id in conversation_ids:
            lines.extend([f"## Conversation: {conv_id}", ""])

            related_ar = ar_by_conv.get(conv_id)
            if related_ar:
                lines.extend([
                    f"**Objective**: {_safe_get(related_ar, 'objective', 'N/A')}",
                    f"**Outcome**: {_get_outcome_str(related_ar)}",
                    f"**Turns**: {_safe_get(related_ar, 'executed_turns', 'N/A')}",
                    "",
                ])

            if conv_printer:
                try:
                    messages = list(memory.get_conversation_messages(conversation_id=conv_id))
                    if messages:
                        conv_md = await conv_printer.render_async(
                            messages,
                            include_scores=True,
                            include_reasoning_trace=self.include_reasoning_trace,
                        )
                        lines.append(conv_md)
                    else:
                        lines.append(f"*No messages found for conversation: {conv_id}*\n")
                except Exception as e:
                    lines.append(f"*Render failed: {e}*\n")
            else:
                lines.append(f"*Native printer not available*\n")

            lines.extend(["---", ""])

        # 评分摘要
        if scores:
            lines.extend([
                "## Scoring Summary",
                "",
                "| Score Type | Value | Category | Rationale |",
                "|-----------|-------|----------|-----------|",
            ])
            for s in scores:
                lines.append(
                    f"| {_safe_get(s, 'score_type', 'N/A')} | "
                    f"{_safe_get(s, 'score_value', 'N/A')} | "
                    f"{_safe_get(s, 'score_category', 'N/A')} | "
                    f"{str(_safe_get(s, 'score_rationale', ''))[:120]} |"
                )
            lines.append("")

        return "\n".join(lines)

    async def _export_score_markdowns(self, scores: list[Any]) -> list[tuple[str, str]]:
        """使用 MarkdownScorePrinter.render_async() 生成每个评分的 Markdown。"""
        files: list[tuple[str, str]] = []
        if not scores:
            return files

        try:
            from pyrit.output.score.markdown import MarkdownScorePrinter
            score_printer = MarkdownScorePrinter()
        except ImportError:
            return files

        for i, score in enumerate(scores, 1):
            is_success = _is_success_score(score)
            suffix = "_success" if is_success else ""
            filename = f"score_{i:04d}{suffix}.md"
            file_path = self.evidence_dir / "scores" / filename

            try:
                content = await score_printer.render_async([score])
                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                logger.warning(f"Failed to export score #{i}: {e}")

        return files

    def _render_attack_summary_csv(self, attack_results: list[Any]) -> str:
        """渲染完整列的攻击摘要 CSV。"""
        output = io.StringIO()
        fieldnames = [
            "attack_id", "conversation_id", "attack_type", "objective",
            "outcome", "outcome_reason", "executed_turns", "execution_time_ms",
            "last_score_value", "last_score_category", "last_score_type",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for ar in attack_results:
            last_score = _safe_get(ar, "last_score")
            row = {
                "attack_id": str(_safe_get(ar, "attack_result_id", "")),
                "conversation_id": str(_safe_get(ar, "conversation_id", "")),
                "attack_type": _get_attack_type(ar),
                "objective": str(_safe_get(ar, "objective", "")).replace("\n", " ").replace("\r", " "),
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")).replace("\n", " ").replace("\r", " "),
                "executed_turns": _safe_get(ar, "executed_turns", ""),
                "execution_time_ms": _safe_get(ar, "execution_time_ms", ""),
                "last_score_value": _safe_get(last_score, "score_value", ""),
                "last_score_category": _safe_get(last_score, "score_category", ""),
                "last_score_type": _safe_get(last_score, "score_type", ""),
            }
            writer.writerow(row)

        return output.getvalue()

    def _render_coverage_matrix_csv(self, coverage: dict[str, dict[str, Any]]) -> str:
        """渲染 OWASP 覆盖矩阵 CSV。"""
        output = io.StringIO()
        fieldnames = ["owasp_id", "name", "framework", "severity", "attack_count", "success_count", "success_rate", "covered"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for owasp_id, info in sorted(coverage.items()):
            writer.writerow({
                "owasp_id": owasp_id,
                "name": info.get("name", ""),
                "framework": info.get("framework", ""),
                "severity": info.get("severity", ""),
                "attack_count": info.get("attack_count", 0),
                "success_count": info.get("success_count", 0),
                "success_rate": f"{info.get('success_rate', 0):.1f}%",
                "covered": "Yes" if info.get("covered") else "No",
            })

        return output.getvalue()

    def _render_attack_timeline_csv(self, attack_results: list[Any]) -> str:
        """渲染攻击时间线 CSV。"""
        output = io.StringIO()
        fieldnames = ["timestamp", "attack_id", "attack_type", "objective", "outcome", "outcome_reason", "turns", "execution_time"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        sorted_results = sorted(attack_results, key=lambda ar: str(_safe_get(ar, "timestamp", "")))
        for ar in sorted_results:
            writer.writerow({
                "timestamp": str(_safe_get(ar, "timestamp", "")),
                "attack_id": str(_safe_get(ar, "attack_result_id", "")),
                "attack_type": _get_attack_type(ar),
                "objective": str(_safe_get(ar, "objective", "")).replace("\n", " ")[:100],
                "outcome": _get_outcome_str(ar),
                "outcome_reason": str(_safe_get(ar, "outcome_reason", "")).replace("\n", " ")[:100],
                "turns": _safe_get(ar, "executed_turns", ""),
                "execution_time": _format_time(_safe_get(ar, "execution_time_ms")),
            })

        return output.getvalue()


def _is_success_score(score: Any) -> bool:
    """判断评分是否指示攻击成功。"""
    score_type = _safe_get(score, "score_type", "")
    score_value = _safe_get(score, "score_value")
    if score_type == "true_false":
        return bool(score_value)
    if score_type == "float_scale":
        try:
            return float(score_value) > 0.5
        except (ValueError, TypeError):
            return False
    return False


def _format_time(ms: Any) -> str:
    """格式化毫秒时间为可读字符串。"""
    if ms is None:
        return "N/A"
    try:
        ms_int = int(ms)
    except (ValueError, TypeError):
        return "N/A"
    if ms_int < 1000:
        return f"{ms_int}ms"
    return f"{ms_int / 1000:.2f}s"
