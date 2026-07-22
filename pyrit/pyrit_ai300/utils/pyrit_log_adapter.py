# -*- coding: utf-8 -*-
"""
AI-300 Framework - PyRIT Native Log Adapter (L5)
PyRIT 原生日志格式适配器

设计目标：
    将 AI-300 框架的攻击阶段日志输出对齐到 PyRIT 0.14.0 原生格式。
    PyRIT 原生日志使用清晰的英文 f-string 风格消息，
    通过 self._logger.info/debug/warning 记录攻击执行全过程。

PyRIT 原生日志模式（来自 pyrit.executor.attack.core.attack_strategy）：
    - self._logger.info(f"Starting attack: {objective}")
    - self._logger.debug(f"Attack execution completed in {execution_time_ms}ms")
    - self._logger.info(f"Starting {class_name} with objective: {objective}")
    - self._logger.info(f"Max attempts: {n}")
    - self._logger.debug(f"Attempt {n}/{total}")
    - self._logger.warning(f"No response received on attempt {n} (likely filtered)")
    - self._logger.info("TAP attack achieved objective - attack successful!")
    - self._logger.warning("All branches have been pruned - stopping attack.")

    PyRIT 原生输出渲染（来自 pyrit.output）：
    - output_attack_async(result, format="pretty", ...)  → 控制台彩色输出
    - MarkdownAttackResultMemoryPrinter.render_async()   → Markdown 报告

适配器职责：
    1. 提供与 PyRIT 原生日志模式一致的方法（log_attack_start, log_attack_result, ...）
    2. 使用 PyRIT 原生 output_attack_async 渲染攻击结果
    3. 结构化元数据通过 extra 参数传递（支持 JSON 日志聚合）
    4. 消除自定义 ######## 标记和 emoji 前缀（✓ PASS / ✗ BLOCK）

使用方式：
    from pyrit_ai300.utils.pyrit_log_adapter import PyRITLogAdapter

    adapter = PyRITLogAdapter(logger)
    adapter.log_attack_start("PromptSendingAttack", "What is your model name?")
    adapter.log_attack_result("PromptSendingAttack", "SUCCESS", 1234)
    adapter.log_attack_summary("LLM01", 10, 7, 3)
    adapter.render_attack_result(attack_result)  # PyRIT 原生 pretty 输出
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PyRITLogAdapter:
    """
    PyRIT 原生日志格式适配器

    将 AI-300 框架的攻击执行日志对齐到 PyRIT 0.14.0 原生日志格式。
    所有方法使用 PyRIT 原生的 f-string 英文消息风格，
    通过标准 logging 模块输出，支持 JSON/TEXT 双模式（StructuredLogger）。

    设计原则（L5）：
    - 消息格式与 PyRIT 原生完全一致，便于日志聚合和搜索
    - 结构化元数据通过 extra 参数传递，不侵入消息文本
    - 攻击结果渲染委托给 PyRIT 原生 output_attack_async
    - 零外部依赖，与标准 logging 完全兼容
    """

    def __init__(self, log: Optional[logging.Logger] = None):
        """
        Args:
            log: Logger 实例（None 时使用模块级 logger）
        """
        self._logger = log or logger

    # ── 攻击执行生命周期日志 ──────────────────────────────────────────

    def log_attack_start(
        self,
        attack_class: str,
        objective: str,
        **metadata: Any,
    ) -> None:
        """
        记录攻击开始（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.info(f"Starting {class_name} with objective: {objective}")

        Args:
            attack_class: 攻击类名（如 "PromptSendingAttack"）
            objective: 攻击目标/prompt
            **metadata: 结构化元数据（owasp_id, mode, target_model 等）
        """
        class_name = attack_class.split(".")[-1] if "." in attack_class else attack_class
        self._logger.info(
            f"Starting {class_name} with objective: {objective[:200]}",
            extra={"attack_class": class_name, "objective": objective[:500], **metadata}
            if metadata
            else None,
        )

    def log_attack_config(
        self,
        attack_name: str,
        mode: str,
        payload_count: int,
        concurrency: int = 1,
        target_model: str = "",
        **metadata: Any,
    ) -> None:
        """
        记录攻击配置信息（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.info(f"Max attempts: {n}")

        Args:
            attack_name: 攻击名称
            mode: 执行模式（chain / presets / smart_match）
            payload_count: 载荷数量
            concurrency: 并发数
            target_model: 目标模型名
            **metadata: 结构化元数据
        """
        self._logger.info(
            f"Attack config: {attack_name} (mode={mode}, payloads={payload_count}, "
            f"concurrency={concurrency}, target={target_model or 'unknown'})",
            extra={
                "attack_name": attack_name,
                "mode": mode,
                "payload_count": payload_count,
                "concurrency": concurrency,
                "target_model": target_model,
                **metadata,
            },
        )

    def log_attempt(
        self,
        attempt: int,
        total: int,
        **metadata: Any,
    ) -> None:
        """
        记录攻击尝试（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.debug(f"Attempt {attempt + 1}/{self._max_attempts_on_failure + 1}")

        Args:
            attempt: 当前尝试序号（1-based）
            total: 总尝试次数
            **metadata: 结构化元数据
        """
        self._logger.debug(
            f"Attempt {attempt}/{total}",
            extra={"attempt": attempt, "total_attempts": total, **metadata},
        )

    def log_attack_result(
        self,
        attack_class: str,
        outcome: str,
        execution_time_ms: int = 0,
        conversation_id: str = "",
        executed_turns: int = 1,
        **metadata: Any,
    ) -> None:
        """
        记录攻击结果（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.debug(f"Attack execution completed in {execution_time_ms}ms")
            self._logger.info("TAP attack achieved objective - attack successful!")

        Args:
            attack_class: 攻击类名
            outcome: 结果状态（SUCCESS / FAILED / ERROR / UNDETERMINED）
            execution_time_ms: 执行耗时（毫秒）
            conversation_id: 对话 ID
            executed_turns: 执行轮次
            **metadata: 结构化元数据
        """
        class_name = attack_class.split(".")[-1] if "." in attack_class else attack_class

        if outcome == "SUCCESS":
            self._logger.info(
                f"{class_name} achieved objective - attack successful!",
                extra={
                    "attack_class": class_name,
                    "outcome": outcome,
                    "execution_time_ms": execution_time_ms,
                    "conversation_id": conversation_id,
                    "executed_turns": executed_turns,
                    **metadata,
                },
            )
        elif outcome == "ERROR":
            self._logger.error(
                f"{class_name} failed with error",
                extra={
                    "attack_class": class_name,
                    "outcome": outcome,
                    "execution_time_ms": execution_time_ms,
                    "conversation_id": conversation_id,
                    **metadata,
                },
            )
        else:
            self._logger.info(
                f"{class_name} completed with outcome: {outcome} in {execution_time_ms}ms",
                extra={
                    "attack_class": class_name,
                    "outcome": outcome,
                    "execution_time_ms": execution_time_ms,
                    "conversation_id": conversation_id,
                    "executed_turns": executed_turns,
                    **metadata,
                },
            )

    def log_no_response(self, attempt: int, **metadata: Any) -> None:
        """
        记录无响应警告（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.warning(f"No response received on attempt {attempt + 1} (likely filtered)")

        Args:
            attempt: 尝试序号
            **metadata: 结构化元数据
        """
        self._logger.warning(
            f"No response received on attempt {attempt} (likely filtered)",
            extra={"attempt": attempt, **metadata},
        )

    def log_fallback(
        self,
        primary_class: str,
        fallback_class: str,
        fallback_idx: int,
        total_fallbacks: int,
        **metadata: Any,
    ) -> None:
        """
        记录 fallback 链执行（对齐 PyRIT 原生格式）

        Args:
            primary_class: 主攻击类名
            fallback_class: fallback 攻击类名
            fallback_idx: fallback 序号（1-based）
            total_fallbacks: 总 fallback 数量
            **metadata: 结构化元数据
        """
        primary_short = primary_class.split(".")[-1]
        fallback_short = fallback_class.split(".")[-1]
        self._logger.info(
            f"Primary attack {primary_short} failed, trying fallback {fallback_idx}/{total_fallbacks}: {fallback_short}",
            extra={
                "primary_class": primary_short,
                "fallback_class": fallback_short,
                "fallback_idx": fallback_idx,
                "total_fallbacks": total_fallbacks,
                **metadata,
            },
        )

    def log_pruning(self, reason: str, **metadata: Any) -> None:
        """
        记录分支剪枝（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.info("Pruning the branch since we can't proceed without red teaming prompt.")
            self._logger.warning("All branches have been pruned - stopping attack.")

        Args:
            reason: 剪枝原因
            **metadata: 结构化元数据
        """
        self._logger.info(
            f"Pruning branch: {reason}",
            extra={"reason": reason, **metadata},
        )

    def log_early_stop(
        self,
        consecutive_failures: int,
        threshold: int,
        skipped_count: int,
        reason: str = "",
        **metadata: Any,
    ) -> None:
        """
        记录早停触发（对齐 PyRIT 原生格式）

        PyRIT 原生模式：
            self._logger.warning("All branches have been pruned - stopping attack.")

        Args:
            consecutive_failures: 连续失败次数
            threshold: 触发阈值
            skipped_count: 被跳过的载荷数量
            reason: 早停原因
            **metadata: 结构化元数据
        """
        self._logger.warning(
            f"Stopping attack: {consecutive_failures} consecutive failures (threshold={threshold}), "
            f"skipping {skipped_count} remaining payloads",
            extra={
                "consecutive_failures": consecutive_failures,
                "threshold": threshold,
                "skipped_count": skipped_count,
                "reason": reason,
                **metadata,
            },
        )

    # ── 攻击摘要日志 ──────────────────────────────────────────────────

    def log_attack_summary(
        self,
        attack_name: str,
        total: int,
        success: int,
        failed: int,
        execution_time_ms: float = 0,
        **metadata: Any,
    ) -> None:
        """
        记录攻击摘要（对齐 PyRIT 原生格式）

        Args:
            attack_name: 攻击名称
            total: 总载荷数
            success: 成功数
            failed: 失败数
            execution_time_ms: 总耗时
            **metadata: 结构化元数据
        """
        rate = (success / total * 100) if total > 0 else 0
        self._logger.info(
            f"Attack summary: {attack_name} — {success}/{total} succeeded ({rate:.0f}%), "
            f"{failed} failed in {execution_time_ms:.0f}ms",
            extra={
                "attack_name": attack_name,
                "total": total,
                "success": success,
                "failed": failed,
                "success_rate": round(rate, 2),
                "execution_time_ms": round(execution_time_ms, 2),
                **metadata,
            },
        )

    def log_scope_start(
        self,
        scope: str,
        payload_count: int,
        target_endpoint: str = "",
        target_model: str = "",
        **metadata: Any,
    ) -> None:
        """
        记录 scope 攻击开始（对齐 PyRIT 原生格式）

        Args:
            scope: OWASP scope（如 "llm01", "all"）
            payload_count: 载荷总数
            target_endpoint: 目标端点
            target_model: 目标模型
            **metadata: 结构化元数据
        """
        self._logger.info(
            f"Starting OWASP scope: {scope} with {payload_count} payloads "
            f"(target={target_endpoint or 'N/A'}, model={target_model or 'unknown'})",
            extra={
                "scope": scope,
                "payload_count": payload_count,
                "target_endpoint": target_endpoint,
                "target_model": target_model,
                **metadata,
            },
        )

    def log_scope_complete(
        self,
        scope: str,
        total: int,
        success: int,
        failed: int,
        execution_time_ms: float = 0,
        **metadata: Any,
    ) -> None:
        """
        记录 scope 攻击完成（对齐 PyRIT 原生格式）

        Args:
            scope: OWASP scope
            total: 总载荷数
            success: 成功数
            failed: 失败数
            execution_time_ms: 总耗时
            **metadata: 结构化元数据
        """
        rate = (success / total * 100) if total > 0 else 0
        self._logger.info(
            f"OWASP scope {scope} completed: {success}/{total} succeeded ({rate:.0f}%) "
            f"in {execution_time_ms:.0f}ms",
            extra={
                "scope": scope,
                "total": total,
                "success": success,
                "failed": failed,
                "success_rate": round(rate, 2),
                "execution_time_ms": round(execution_time_ms, 2),
                **metadata,
            },
        )

    # ── 数据驱动过滤/排序日志 ─────────────────────────────────────────

    def log_payload_filter(
        self,
        attack_name: str,
        before: int,
        after: int,
        filter_type: str = "context/capability",
        **metadata: Any,
    ) -> None:
        """
        记录载荷过滤（数据驱动）

        Args:
            attack_name: 攻击名称
            before: 过滤前数量
            after: 过滤后数量
            filter_type: 过滤类型
            **metadata: 结构化元数据
        """
        removed = before - after
        if removed > 0:
            self._logger.info(
                f"Payload filter: {attack_name} — {after}/{before} retained "
                f"({removed} removed by {filter_type})",
                extra={
                    "attack_name": attack_name,
                    "before": before,
                    "after": after,
                    "removed": removed,
                    "filter_type": filter_type,
                    **metadata,
                },
            )

    def log_surface_filter(
        self,
        attack_name: str,
        owasp_id: str,
        required_surfaces: set,
        actual_surfaces: list,
        **metadata: Any,
    ) -> None:
        """
        记录攻击面过滤（数据驱动）

        Args:
            attack_name: 攻击名称
            owasp_id: OWASP ID
            required_surfaces: 需要的攻击面
            actual_surfaces: 实际攻击面
            **metadata: 结构化元数据
        """
        self._logger.info(
            f"Surface filter: skipping {attack_name} ({owasp_id}) — "
            f"requires {required_surfaces}, target has {actual_surfaces}",
            extra={
                "attack_name": attack_name,
                "owasp_id": owasp_id,
                "required_surfaces": list(required_surfaces),
                "actual_surfaces": actual_surfaces,
                **metadata,
            },
        )

    def log_asr_rank(
        self,
        payload_count: int,
        target_model: str,
        **metadata: Any,
    ) -> None:
        """
        记录 ASR 排序（数据驱动）

        Args:
            payload_count: 载荷数量
            target_model: 目标模型
            **metadata: 结构化元数据
        """
        self._logger.info(
            f"ASR ranking: {payload_count} payloads sorted by ASR for '{target_model}'",
            extra={
                "payload_count": payload_count,
                "target_model": target_model,
                **metadata,
            },
        )

    def log_model_specific_select(
        self,
        selected: int,
        total: int,
        target_model: str,
        **metadata: Any,
    ) -> None:
        """
        记录模型特定选择（数据驱动）

        Args:
            selected: 选中数量
            total: 总数量
            target_model: 目标模型
            **metadata: 结构化元数据
        """
        if selected < total:
            self._logger.info(
                f"Model-specific selection: {selected}/{total} payloads selected for '{target_model}'",
                extra={
                    "selected": selected,
                    "total": total,
                    "target_model": target_model,
                    **metadata,
                },
            )

    def log_model_probe(
        self,
        model_name: str,
        source: str = "probe",
        **metadata: Any,
    ) -> None:
        """
        记录模型探测结果（数据驱动）

        Args:
            model_name: 探测到的模型名
            source: 探测来源
            **metadata: 结构化元数据
        """
        if model_name:
            self._logger.info(
                f"Model probe result: '{model_name}' (via {source})",
                extra={
                    "model_name": model_name,
                    "source": source,
                    **metadata,
                },
            )
        else:
            self._logger.info(
                "Model probe: could not detect model, using defaults",
                extra={"source": source, **metadata},
            )

    # ── PyRIT 原生输出渲染 ────────────────────────────────────────────

    def render_attack_result(
        self,
        attack_result: Any,
        *,
        include_adversarial: bool = True,
        include_auxiliary_scores: bool = False,
        include_pruned: bool = False,
    ) -> None:
        """
        使用 PyRIT 原生 output_attack_async 渲染单个攻击结果

        对齐 PyRIT 原生输出模式：
            from pyrit.output import output_attack_async
            await output_attack_async(result, format="pretty", ...)

        Args:
            attack_result: PyRIT AttackResult 对象
            include_adversarial: 是否包含对抗对话
            include_auxiliary_scores: 是否包含辅助评分
            include_pruned: 是否包含剪枝对话
        """
        if attack_result is None:
            return

        try:
            from pyrit.output import output_attack_async
            from .async_helper import run_async

            run_async(
                output_attack_async(
                    attack_result,
                    format="pretty",
                    include_adversarial_conversation=include_adversarial,
                    include_auxiliary_scores=include_auxiliary_scores,
                    include_pruned_conversations=include_pruned,
                )
            )
        except ImportError:
            self._logger.debug("PyRIT output module not available, skipping native render")
        except Exception as e:
            self._logger.warning(
                f"PyRIT native output failed: {e}",
                extra={"error": str(e)},
            )

    def render_attack_results(
        self,
        attack_results: List[Any],
        *,
        include_adversarial: bool = True,
        include_auxiliary_scores: bool = False,
        include_pruned: bool = False,
    ) -> None:
        """
        使用 PyRIT 原生 output_attack_async 渲染多个攻击结果

        Args:
            attack_results: PyRIT AttackResult 对象列表
            include_adversarial: 是否包含对抗对话
            include_auxiliary_scores: 是否包含辅助评分
            include_pruned: 是否包含剪枝对话
        """
        for result in attack_results:
            self.render_attack_result(
                result,
                include_adversarial=include_adversarial,
                include_auxiliary_scores=include_auxiliary_scores,
                include_pruned=include_pruned,
            )


# ── 模块级单例 ──────────────────────────────────────────────────────

_default_adapter: Optional[PyRITLogAdapter] = None


def get_pyrit_log_adapter(logger: Optional[logging.Logger] = None) -> PyRITLogAdapter:
    """
    获取 PyRIT 日志适配器实例（模块级单例）

    Args:
        logger: Logger 实例（仅首次调用生效）

    Returns:
        PyRITLogAdapter 实例
    """
    global _default_adapter
    if _default_adapter is None:
        _default_adapter = PyRITLogAdapter(logger)
    elif logger is not None:
        _default_adapter._logger = logger
    return _default_adapter
