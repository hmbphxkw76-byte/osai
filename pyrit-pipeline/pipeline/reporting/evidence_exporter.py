# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""证据导出器 — PyRIT 原生 render_async + 三级证据链集成。.

L5 对齐 PyRIT 1.0.1 output 模块:
  - 使用 MarkdownAttackResultMemoryPrinter.render_async() 生成每个攻击 Markdown
  - 使用 MarkdownConversationMemoryPrinter.render_async() 渲染对话历史
  - 使用 MarkdownScorePrinter.render_async() 渲染评分
  - 支持 include_reasoning_trace (o1/o3 推理模型)
  - 支持 blur_images (图片模糊, 保护审查者)
  - 支持 blurred_dir (模糊图片副本重定向到专用目录, 纳入 ZIP)
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
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.memory import CentralMemory
from pyrit.output.attack_result.markdown import MarkdownAttackResultMemoryPrinter
from pyrit.output.conversation.markdown import MarkdownConversationMemoryPrinter
from pyrit.output.score.markdown import MarkdownScorePrinter

from pipeline.converters.log import extract_converter_info_from_result
from pipeline.reporting.report_generator import _get_attack_type, _get_outcome_str, _safe_get

logger = logging.getLogger(__name__)


class EvidenceExporter:
    """证据导出器 — 利用 PyRIT MemoryInterface + 原生 Markdown 打印器。.

    L5 对齐 PyRIT 1.0.1 output 模块:
      - 使用 render_async() 直接获取渲染字符串, 消除 write_async()+read-back 冗余 I/O
      - 每个攻击生成独立 Markdown 文件
      - 每个对话生成独立 Markdown 文件
      - 汇总对话历史使用原生 MarkdownConversationMemoryPrinter
      - blurred_dir 全链路透传给所有打印机
      - _collect_blurred_images() 收集模糊图片副本纳入 ZIP
    """

    def __init__(
        self,
        evidence_dir: Path,
        *,
        include_reasoning_trace: bool = True,
        blur_images: bool = False,
        blur_radius: int = 20,
        blurred_dir: os.PathLike[str] | str | None = None,
    ) -> None:
        """Initialize EvidenceExporter."""
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.include_reasoning_trace = include_reasoning_trace
        self.blur_images = blur_images
        self.blur_radius = blur_radius

        # 子目录
        (self.evidence_dir / "attacks").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "conversations").mkdir(parents=True, exist_ok=True)
        (self.evidence_dir / "scores").mkdir(parents=True, exist_ok=True)

        # L5 对齐: 模糊图片副本专用目录
        if blurred_dir is not None:
            self.blurred_dir = os.fspath(blurred_dir)
        else:
            self._blurred_dir_path = self.evidence_dir / "blurred"
            self._blurred_dir_path.mkdir(parents=True, exist_ok=True)
            self.blurred_dir = str(self._blurred_dir_path)

    async def export_all_evidence(
        self,
        attack_results: list[Any],
        owasp_coverage: dict[str, dict[str, Any]] | None = None,
    ) -> Path:
        """导出完整证据包。.

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
        logger.info(f"Evidence export: {len(attack_results)} attack_results, {len(conversation_ids)} conversations")

        # 获取消息片段和评分
        message_pieces: list[Any] = []
        scores_for_pieces: list[Any] = []
        if conversation_ids:
            for conv_id in conversation_ids:
                try:
                    pieces = memory.get_message_pieces(conversation_id=conv_id)
                    message_pieces.extend(pieces)
                    piece_ids = [str(p.id) for p in pieces if hasattr(p, "id") and p.id]
                    if piece_ids:
                        piece_scores = memory.get_prompt_scores(prompt_ids=piece_ids)
                        scores_for_pieces.extend(piece_scores)
                except Exception as e:
                    logger.warning(f"Failed to get message pieces for conv {conv_id}: {e}")

        logger.info(
            f"Evidence export: {len(message_pieces)} message_pieces,"
            f" {len(scores_for_pieces)} scores_for_pieces"
        )

        # A2 修复: 如果 scores_for_pieces 为空, 从 memory.get_scores() 获取全量评分作为 fallback
        if not scores_for_pieces:
            try:
                all_scores_fallback = list(memory.get_scores())
                if all_scores_fallback:
                    logger.info(f"Evidence export: using get_scores() fallback, got {len(all_scores_fallback)} scores")
                    scores_for_pieces = all_scores_fallback
            except Exception as e:
                logger.warning(f"get_scores() fallback failed: {e}")

        # L5 对齐 D1: 获取场景结果和对话统计 (对齐 pyrit_ai300 evidence.json 结构)
        scenario_results = []
        try:
            scenario_results = list(memory.get_scenario_results())
        except Exception as e:
            logger.debug(f"get_scenario_results failed: {e}")

        all_scores = []
        try:
            all_scores = list(memory.get_scores())
        except Exception as e:
            logger.debug(f"get_scores failed: {e}")

        conversation_stats = {}
        if conversation_ids:
            try:
                conversation_stats = memory.get_conversation_stats(conversation_ids=conversation_ids)
            except Exception as e:
                logger.debug(f"get_conversation_stats failed: {e}")

        # 1. 生成 evidence.json (L5 对齐 D1: 扩展字段)
        evidence_data = self._build_evidence_json(
            attack_results, message_pieces, scores_for_pieces,
            scenario_results, all_scores, conversation_stats, conversation_ids,
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

        # 5. 生成评分 Markdown (A2 修复: 传入全量评分作为 fallback)
        all_scores_for_export = scores_for_pieces
        if not all_scores_for_export and all_scores:
            all_scores_for_export = all_scores
            logger.info(f"Evidence export: using all_scores for score markdowns, {len(all_scores_for_export)} scores")
        score_md_files = await self._export_score_markdowns(all_scores_for_export)

        # 6. 生成 CSV
        attack_csv = self._render_attack_summary_csv(attack_results)
        coverage_csv = self._render_coverage_matrix_csv(owasp_coverage or {})
        timeline_csv = self._render_attack_timeline_csv(attack_results)

        # 7. 收集模糊图片副本 (L5 对齐: 纳入 ZIP)
        blurred_image_files = self._collect_blurred_images()

        # 打包为 zip
        archive_path = self.evidence_dir.parent / f"{self.evidence_dir.name}_evidence.zip"
        logger.info(f"Creating evidence ZIP: {archive_path}")
        logger.info(
            f"  ZIP contents: {len(attack_md_files)} attacks,"
            f" {len(conversation_md_files)} conversations, {len(score_md_files)} scores"
        )
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

            # 模糊图片副本
            for arcname, file_path in blurred_image_files:
                zipf.write(file_path, arcname)

        logger.info(f"Evidence archive: {archive_path}")
        return archive_path

    def _build_evidence_json(
        self,
        attack_results: list[Any],
        message_pieces: list[Any],
        scores_for_pieces: list[Any],
        scenario_results: list[Any],
        all_scores: list[Any],
        conversation_stats: Any,
        conversation_ids: list[str],
    ) -> dict[str, Any]:
        """构建结构化 evidence.json (使用 model_dump)。.

        L5 对齐 D1: 扩展字段, 对齐 pyrit_ai300 evidence.json 结构。
        新增 scenario_results, message_piece_count, conversation_stats 等字段。
        """

        def _safe_dump(obj: Any) -> Any:
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
            "message_piece_count": len(message_pieces),
            "message_piece_scores": [_safe_dump(s) for s in scores_for_pieces],
            "scenario_results": [_safe_dump(sr) for sr in scenario_results],
            "scores": [_safe_dump(s) for s in all_scores],
            "conversation_stats": str(conversation_stats)
            if not isinstance(conversation_stats, dict)
            else conversation_stats,
            "conversation_ids": conversation_ids,
        }

    async def _export_attack_markdowns(self, attack_results: list[Any]) -> list[tuple[str, str]]:
        """使用 MarkdownAttackResultMemoryPrinter.render_async() 生成每个攻击的 Markdown。.

        L5 对齐: 模块级导入打印机, blurred_dir 全链路传递, except Exception 宽口径捕获。
        """
        files: list[tuple[str, str]] = []

        printer = MarkdownAttackResultMemoryPrinter(
            blur_images=self.blur_images,
            blur_radius=self.blur_radius,
            blurred_dir=self.blurred_dir,
        )

        for i, ar in enumerate(attack_results, 1):
            # 成功攻击加 _success 后缀, 失败攻击不加, 便于区分
            outcome_str = _get_outcome_str(ar).upper()
            suffix = "_success" if outcome_str == "SUCCESS" else ""
            filename = f"attack_{i:04d}{suffix}.md"
            file_path = self.evidence_dir / "attacks" / filename

            try:
                content = await printer.render_async(
                    ar,
                    include_auxiliary_scores=True,
                    include_pruned_conversations=True,
                    include_adversarial_conversation=True,
                )

                # L5 对齐 D2: 追加 Converter Transformation Log (对齐 pyrit_ai300 方案B)
                conv_info = extract_converter_info_from_result(ar)
                if conv_info["has_converters"]:
                    chain_name = conv_info.get("converter_chain_name", "unknown")
                    class_names = conv_info.get("converter_class_names", [])
                    content += "\n\n---\n\n"
                    content += f"## Converter Transformation Log: `{chain_name}`\n\n"
                    content += f"- **Converter Classes**: {', '.join(class_names)}\n\n"
                    content += "| Step | Converter Class |\n|------|----------------|\n"
                    for step_idx, cn in enumerate(class_names, 1):
                        content += f"| {step_idx} | {cn} |\n"
                    content += "\n*Full transformation log with intermediate text outputs"
                    content += " is generated via post-processing re-conversion.*\n"

                # P2-Gap8: 载荷变形链路追溯 (R-010: PyRIT 原生字段优先)
                content += "\n\n---\n\n"
                content += "## Payload Transformation Trace\n\n"
                # 1. 原始载荷 (objective / metadata / conversation)
                objective = _safe_get(ar, "objective", "")
                if objective:
                    obj_text = str(objective)[:200]
                    content += f"### Original Payload\n\n```\n{obj_text}\n```\n\n"
                # 2. Converter 链
                if conv_info["has_converters"]:
                    content += "### Converter Chain\n\n"
                    for step_idx, cn in enumerate(class_names, 1):
                        content += f"{step_idx}. `{cn}`\n"
                    content += "\n"
                # 3. 发送到目标的载荷 (conversation 中的 user 消息)
                try:
                    if hasattr(ar, "conversation") and ar.conversation:
                        messages = ar.conversation.messages if hasattr(ar.conversation, "messages") else []
                        user_msgs = [m for m in messages if (getattr(m, "role", "") or "") == "user"]
                        if user_msgs:
                            sent_payload = str(
                            getattr(user_msgs[-1], "content", "")
                            or getattr(user_msgs[-1], "original_value", "")
                        )[:300]
                            content += f"### Sent Payload (after conversion)\n\n```\n{sent_payload}\n```\n\n"
                        # 4. 目标响应
                        assistant_msgs = [m for m in messages if (getattr(m, "role", "") or "") == "assistant"]
                        if assistant_msgs:
                            response = str(
                                getattr(assistant_msgs[-1], "content", "")
                                or getattr(assistant_msgs[-1], "original_value", "")
                            )[:300]
                            content += f"### Target Response\n\n```\n{response}\n```\n\n"
                except Exception:
                    pass
                # 5. 结果
                outcome = _get_outcome_str(ar)
                content += f"### Outcome: **{outcome}**\n\n"

                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                logger.warning(f"Failed to export attack #{i}: {e}")
                fallback = (
                    f"# Attack {i}\n\n*Export failed: {e}*\n\n"
                    f"- Objective: {_safe_get(ar, 'objective', 'N/A')}\n"
                    f"- Outcome: {_get_outcome_str(ar)}\n"
                )
                files.append((filename, fallback))

        return files

    async def _export_conversation_markdowns(
        self,
        memory: Any,
        conversation_ids: list[str],
        attack_results: list[Any],
    ) -> list[tuple[str, str]]:
        """使用 MarkdownConversationMemoryPrinter.render_async() 生成每个对话的 Markdown。.

        A1 修复: 使用 memory.get_message_pieces() 替代不存在的 get_conversation_messages(),
        对齐 PyRIT 1.0.1 MemoryInterface API。
        """
        files: list[tuple[str, str]] = []

        score_printer = MarkdownScorePrinter()
        printer = MarkdownConversationMemoryPrinter(
            score_printer=score_printer,
            blur_images=self.blur_images,
            blur_radius=self.blur_radius,
            blurred_dir=self.blurred_dir,
        )

        # 构建成功对话 ID 集合
        success_conv_ids = set()
        for ar in attack_results:
            if _get_outcome_str(ar).upper() == "SUCCESS":
                conv_id = str(_safe_get(ar, "conversation_id", ""))
                if conv_id:
                    success_conv_ids.add(conv_id)

        # L5: 收集渲染失败, 输出汇总而非逐条 warning (信号/噪音分离)
        render_failures: list[tuple[str, str]] = []

        for conv_id in conversation_ids:
            suffix = "_success" if conv_id in success_conv_ids else ""
            filename = f"conv_{conv_id[:8]}{suffix}.md"
            file_path = self.evidence_dir / "conversations" / filename

            try:
                # A1 修复: 使用 get_message_pieces() 替代 get_conversation_messages()
                # P1 修复: MessagePiece.to_message() 转换为 Message (PyRIT 1.0.1 兼容)
                pieces = list(memory.get_message_pieces(conversation_id=conv_id))
                if not pieces:
                    logger.debug(f"No message pieces for conversation {conv_id}")
                    continue

                # P1: 将 MessagePiece 转换为 Message (MarkdownConversationMemoryPrinter 期望 list[Message])
                messages = [p.to_message() for p in pieces]
                content = await printer.render_async(
                    messages,
                    include_scores=True,
                    include_reasoning_trace=self.include_reasoning_trace,
                )
                file_path.write_text(content, encoding="utf-8")
                files.append((filename, content))
            except Exception as e:
                render_failures.append((conv_id, str(e)[:80]))

        # L5: 汇总输出渲染失败 (替代逐条 warning, 减少 700+ 行噪音)
        if render_failures:
            logger.info(
                f"Conversation export: {len(render_failures)}/{len(conversation_ids)}"
                f" failed (errors logged in summary)"
            )
            for conv_id, err in render_failures[:3]:
                logger.info(f"  conv {conv_id[:8]}: {err}")
            if len(render_failures) > 3:
                logger.info(f"  ... and {len(render_failures) - 3} more")
        else:
            logger.info(f"Exported {len(files)} conversation markdowns")
        return files

    async def _render_conversation_log(
        self,
        memory: Any,
        attack_results: list[Any],
        conversation_ids: list[str],
        scores: list[Any],
    ) -> str:
        """渲染汇总对话历史 Markdown。."""
        lines = [
            "# AI Conversation History",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Attack Results: {len(attack_results)}",
            f"Total Conversations: {len(conversation_ids)}",
            "",
            "---",
            "",
        ]

        score_printer = MarkdownScorePrinter()
        conv_printer = MarkdownConversationMemoryPrinter(
            score_printer=score_printer,
            blur_images=self.blur_images,
            blur_radius=self.blur_radius,
            blurred_dir=self.blurred_dir,
        )

        ar_by_conv = {}
        for ar in attack_results:
            conv_id = str(_safe_get(ar, "conversation_id", ""))
            if conv_id:
                ar_by_conv[conv_id] = ar

        # L5: 收集渲染失败, 输出汇总而非逐条 warning
        render_failures_log: list[str] = []

        for conv_id in conversation_ids:
            lines.extend([f"## Conversation: {conv_id}", ""])

            related_ar = ar_by_conv.get(conv_id)
            if related_ar:
                lines.extend([
                    f"**Objective**: {_safe_get(related_ar, 'objective', 'N/A')}",
                    f"**Outcome**: {_get_outcome_str(related_ar)}",
                    f"**Turns**: {_safe_get(related_ar, 'executed_turns', 'N/A')}",
                    f"**Execution Time**: {_format_time(_safe_get(related_ar, 'execution_time_ms'))}",
                    "",
                ])

            try:
                # A1 修复: 使用 get_message_pieces() 替代不存在的 get_conversation_messages()
                # P1 修复: MessagePiece.to_message() 转换为 Message (PyRIT 1.0.1 兼容)
                pieces = list(memory.get_message_pieces(conversation_id=conv_id))
                if pieces:
                    # P1: 将 MessagePiece 转换为 Message
                    messages = [p.to_message() for p in pieces]
                    conv_md = await conv_printer.render_async(
                        messages,
                        include_scores=True,
                        include_reasoning_trace=self.include_reasoning_trace,
                    )
                    lines.append(conv_md)
                else:
                    lines.append(f"*No messages found for conversation: {conv_id}*\n")
            except Exception:
                render_failures_log.append(conv_id)
                lines.append("*Render failed (see summary)*\n")

            lines.extend(["---", ""])

        # L5: 渲染失败汇总 (替代逐条 warning, 减少噪音)
        if render_failures_log:
            lines.extend([
                "## Render Failure Summary",
                "",
                f"{len(render_failures_log)}/{len(conversation_ids)} conversations failed to render.",
                f"Failed IDs: {', '.join(cid[:8] for cid in render_failures_log[:10])}",
                "",
            ])

        # 评分摘要
        if scores:
            lines.extend([
                "## Scoring Summary",
                "",
                "| Score ID | Score Type | Value | Category | Rationale |",
                "|----------|-----------|-------|----------|-----------|",
            ])
            for s in scores:
                score_id = str(_safe_get(s, "id", "N/A"))
                lines.append(
                    f"| {score_id} | "
                    f"{_safe_get(s, 'score_type', 'N/A')} | "
                    f"{_safe_get(s, 'score_value', 'N/A')} | "
                    f"{_safe_get(s, 'score_category', 'N/A')} | "
                    f"{str(_safe_get(s, 'score_rationale', ''))[:120]} |"
                )
            lines.append("")

        return "\n".join(lines)

    async def _export_score_markdowns(self, scores: list[Any]) -> list[tuple[str, str]]:
        """使用 MarkdownScorePrinter.render_async() 生成每个评分的 Markdown。.

        L5 对齐: 模块级导入打印机, except Exception 宽口径捕获, 失败时生成 fallback。
        """
        files: list[tuple[str, str]] = []
        if not scores:
            return files

        score_printer = MarkdownScorePrinter()

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
                fallback = f"# Score {i}\n\n*Export failed: {e}*\n"
                files.append((filename, fallback))

        return files

    def _collect_blurred_images(self) -> list[tuple[str, str]]:
        """收集模糊图片副本文件列表, 用于纳入证据 zip 包。.

        L5 对齐 PyRIT 1.0.1 output 模块:
        - Markdown 格式下 blur_images=True 时, 打印机将模糊副本写入 blurred_dir
        - 模糊副本文件名格式为 <stem>_blurred.png
        - 此方法扫描 blurred_dir 收集所有模糊副本, 返回 (arcname, file_path) 列表

        Returns:
            [(zip内路径, 磁盘路径), ...] 列表
        """
        if not self.blur_images:
            return []

        blurred_path = Path(self.blurred_dir)
        if not blurred_path.exists():
            return []

        files = []
        for img_file in sorted(blurred_path.glob("*_blurred.png")):
            arcname = f"blurred/{img_file.name}"
            files.append((arcname, str(img_file)))

        return files

    def _render_attack_summary_csv(self, attack_results: list[Any]) -> str:
        """渲染完整列的攻击摘要 CSV。."""
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
        """渲染 OWASP 覆盖矩阵 CSV。."""
        output = io.StringIO()
        fieldnames = [
            "owasp_id", "name", "framework", "severity",
            "attack_count", "success_count", "success_rate", "covered",
        ]
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
        """渲染攻击时间线 CSV。."""
        output = io.StringIO()
        fieldnames = [
            "timestamp", "attack_id", "attack_type", "objective",
            "outcome", "outcome_reason", "turns", "execution_time",
        ]
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
    """判断评分是否指示攻击成功。."""
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
    """格式化毫秒时间为可读字符串。."""
    if ms is None:
        return "N/A"
    try:
        ms_int = int(ms)
    except (ValueError, TypeError):
        return "N/A"
    if ms_int < 1000:
        return f"{ms_int}ms"
    return f"{ms_int / 1000:.2f}s"
