# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""统一输出管理器 — 目录结构管理 + 双通道输出 (终端 + 文件).

合并自 utils/output_manager.py (目录结构) 和原 reporting/output_manager.py (双通道).

核心能力:
1. OutputManager: 管理 output/ 目录结构和路径生成 (db/ evidence/ logs/ reports/ empirical_asr/)
2. DualOutputManager: 双通道输出 — StdoutSink (终端实时显示) + FileSink (Markdown 持久化)
3. ProgressDashboard: 批量攻击实时进度仪表盘
4. ProgressPoller: 非侵入式背景轮询器 — 基于 CentralMemory 实时更新 Dashboard
5. SummaryTable: 批量攻击完成后的汇总表格

遵循开发规则 1.4.1 (原生优先): 使用 PyRIT 原生 output_attack_async / FileSink.
进度轮询使用 PyRIT 原生 MemoryInterface.get_attack_results(scenario_result_id=...).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 路径 4: 从 PyRIT 原生 error_message 提取策略类名
# 匹配: "Strategy execution failed for objective_target in PromptSendingAttack:"
_ERROR_MESSAGE_CLASS_NAME_PATTERN = re.compile(r"Strategy execution failed for \w+ in (\w+):")


# ============================================================
# 终端进度仪表盘
# ============================================================


class ProgressDashboard:
    """批量攻击实时进度仪表盘.

    L5 增强: 支持 ASR 迷你仪表盘渲染 (P0-2),
    基于 PyRIT 原生 AttackResult.outcome 统计实时攻击成功率。
    """

    def __init__(self, total: int) -> None:
        """初始化进度仪表盘."""
        self.total = total
        self.completed = 0
        self.succeeded = 0
        self.failed = 0
        self.errored = 0
        self._start_time = time.time()
        # L5 P0-2: 实时 ASR 迷你仪表盘数据
        self._asr_tech_success: dict[str, int] = {}
        self._asr_tech_total: dict[str, int] = {}

    def update(self, *, succeeded: int = 0, failed: int = 0, errored: int = 0) -> None:
        """累加更新计数."""
        self.succeeded += succeeded
        self.failed += failed
        self.errored += errored

    def increment_completed(self) -> None:
        """递增已完成计数."""
        self.completed += 1

    def render(self) -> str:
        """渲染进度仪表盘."""
        elapsed = time.time() - self._start_time
        # 安全上限: completed 不超过 total (防御性, 正常情况下不会触发)
        effective_total = max(self.total, self.completed)
        pct = self.completed / effective_total * 100 if effective_total > 0 else 0
        rate = self.completed / elapsed * 60 if elapsed > 0 else 0
        remaining = (elapsed / self.completed * (effective_total - self.completed)) if self.completed > 0 else 0

        bar_width = 30
        filled = min(int(bar_width * pct / 100), bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        lines = [
            "",
            f"  ┌{'─' * 60}┐",
            f"  │ {'PyRIT AI Red Team - Batch Attack Progress':^56s} │",
            f"  │ {bar} {self.completed}/{self.total} ({pct:.1f}%){'':>16s}│",
            (f"  │ {'✅ OK:':>8s} {self.succeeded:<5d}  {'❌ FAIL:':>8s} {self.failed:<5d}"
            f"  {'⚠ ERR:':>7s} {self.errored:<5d}{'':>6s}│"),
            (f"  │ {'Elapsed:':>8s} {elapsed:.0f}s    {'ETA:':>5s} ~{remaining:.0f}s"
            f"    {'Rate:':>5s} {rate:.1f}/min{'':>8s}│"),
        ]

        # L5 P0-2: 实时 ASR 迷你仪表盘 (当有结果时显示)
        if self.completed > 0:
            asr = self.succeeded / self.completed * 100 if self.completed > 0 else 0
            lines.append(
                f"  │ {'ASR:':>8s} {asr:.1f}%  "
                f"({'✅':>1s} {self.succeeded} / {'❌':>1s} {self.failed}"
                f" / {'⚠':>1s} {self.errored}){'':>16s}│"
            )
            # Top 3 技术 ASR
            top_techs = sorted(
                self._asr_tech_total.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:3]
            for tech, total in top_techs:
                succ = self._asr_tech_success.get(tech, 0)
                tech_asr = succ / total * 100 if total > 0 else 0
                tech_short = tech[:25] + "..." if len(tech) > 25 else tech
                lines.append(
                    f"  │   {tech_short:<28s} {tech_asr:>5.1f}% "
                    f"({succ}/{total}){'':>14s}│"
                )

        lines.append(f"  └{'─' * 60}┘")
        return "\n".join(lines)

    def print_progress(self) -> None:
        """打印进度到终端."""
        print(self.render())

    def update_from_attack_results(self, attack_results: list[Any]) -> None:
        """从 AttackResult 列表更新计数 (用于实时轮询).

        重置计数后重新统计, 确保与 CentralMemory 中的实际数据一致。

        关键设计: completed/succeeded/failed/errored 按 **唯一 objective** 统计,
        与 ``atomic_attack_count`` (total) 保持同一单位。
        一个 AtomicAttack 可能产生多个 AttackResult (因 max_attempts_per_objective
        或多轮攻击技术), 但在进度条上应算作 1 个完成。

        L5 P0-2 增强: 按技术分组 ASR 仍按 AttackResult 级别统计 (更细粒度)。
        L5 Round 20 增强: 两遍遍历 — 第一遍构建 eval_hash→技术名映射,
        第二遍用 Path 5 (attribution_data.parent_eval_hash 关联查询) 解析 unknown 结果。

        Args:
            attack_results: 从 CentralMemory 查询到的 AttackResult 列表
        """
        self.succeeded = 0
        self.failed = 0
        self.errored = 0
        self._asr_tech_success.clear()
        self._asr_tech_total.clear()

        # 按唯一 objective 聚合: 每个 AtomicAttack 共享同一个 objective
        # 多个 AttackResult 可能属于同一个 AtomicAttack (多次尝试)
        objective_best_outcome: dict[str, str] = {}

        # Path 5: eval_hash → technique 映射 (第一遍构建, 第二遍使用)
        eval_hash_to_technique: dict[str, str] = {}
        # 需要第二遍解析的 unknown 结果: (ar, outcome_str)
        unknown_results: list[tuple[Any, str]] = []

        for ar in attack_results:
            outcome = getattr(ar, "outcome", None)
            if outcome is None:
                continue
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

            # 按唯一 objective 聚合: 使用 vars() 避免 MagicMock auto-attr 副作用
            # (与 _extract_technique 同模式, 性能优化)
            ar_dict = vars(ar) if hasattr(ar, "__dict__") else {}
            objective = str(ar_dict.get("objective", "") or "")
            if objective:
                if outcome_str == "SUCCESS":
                    objective_best_outcome[objective] = "SUCCESS"
                elif objective not in objective_best_outcome:
                    objective_best_outcome[objective] = outcome_str

            # L5 P0-2: 按技术分组统计 ASR (AttackResult 级别, 更细粒度)
            tech = self._extract_technique(ar)
            if tech and tech != "unknown":
                self._asr_tech_total[tech] = self._asr_tech_total.get(tech, 0) + 1
                if outcome_str == "SUCCESS":
                    self._asr_tech_success[tech] = self._asr_tech_success.get(tech, 0) + 1
                # Path 5: 构建 eval_hash → technique 映射
                aai = ar_dict.get("atomic_attack_identifier")
                if aai is not None:
                    eval_hash = getattr(aai, "eval_hash", None)
                    if eval_hash and isinstance(eval_hash, str) and eval_hash not in eval_hash_to_technique:
                        eval_hash_to_technique[eval_hash] = tech
            else:
                # 延迟到第二遍: 尝试通过 Path 5 (eval_hash 关联查询) 解析
                unknown_results.append((ar, outcome_str))

        # Path 5: 第二遍 — 用 eval_hash 关联查询解析 unknown 结果
        if unknown_results and eval_hash_to_technique:
            for ar, outcome_str in unknown_results:
                tech = self._extract_technique(ar, eval_hash_map=eval_hash_to_technique)
                if tech and tech != "unknown":
                    self._asr_tech_total[tech] = self._asr_tech_total.get(tech, 0) + 1
                    if outcome_str == "SUCCESS":
                        self._asr_tech_success[tech] = self._asr_tech_success.get(tech, 0) + 1

        # completed/succeeded/failed/errored = 唯一 objective 级别 (与 total 同单位)
        for outcome_str in objective_best_outcome.values():
            if outcome_str == "SUCCESS":
                self.succeeded += 1
            elif outcome_str == "FAILURE":
                self.failed += 1
            else:
                self.errored += 1
        self.completed = self.succeeded + self.failed + self.errored

    @staticmethod
    def _extract_technique(ar: Any, *, eval_hash_map: dict[str, str] | None = None) -> str:
        """从 AttackResult 提取技术名 (用于 ASR 分组 + 终端显示).

        R-022 PyRIT 原生优先 (修正路径 — 使用 get_attack_strategy_identifier):
          1. ar.get_attack_strategy_identifier() — PyRIT 原生 API
             → 返回内层 AttackIdentifier (class_name="ManyShotJailbreakAttack" 等)
             a. .class_name → map_class_name_to_technique() (如 "ManyShotJailbreakAttack" → "many_shot")
             b. .params.get("attack_strategy") (策略参数回退)
          2. ar.atomic_attack_identifier — 外层标识符回退 (向下钻取 attack_technique → attack)
          3. ar.metadata.get("technique") — 元数据回退
          4. error_message 正则提取策略类名 (API 超时/错误回退)
          5. attribution_data.parent_eval_hash 关联查询 (eval_hash_map 回退)
          6. "unknown" — 最终回退

        注意: ar.atomic_attack_identifier.unique_name 返回 "AtomicAttack::hash",
        这是复合标识符的哈希, 非技术名。正确路径是通过 get_attack_strategy_identifier()
        获取内层 AttackIdentifier 的 class_name, 再通过 technique_name_mapper 映射。

        Args:
            ar: AttackResult 实例
            eval_hash_map: eval_hash → technique 映射 (可选, Path 5 关联查询用)
        """
        # 路径 1: PyRIT 原生 get_attack_strategy_identifier() → 内层 AttackIdentifier
        # Performance: 检查 type 级方法, 避免 MagicMock auto-attr 导致的方法调用开销
        # (MagicMock.get_attack_strategy_identifier() 每次创建新 MagicMock, 1000 次调用 ~2s)
        _type_method = getattr(type(ar), "get_attack_strategy_identifier", None)
        if _type_method is not None and type(_type_method).__name__ == "function":
            try:
                attack_id = ar.get_attack_strategy_identifier()
                if attack_id is not None:
                    # 1a: class_name → 规范技术名映射
                    cname = getattr(attack_id, "class_name", None)
                    if cname and isinstance(cname, str) and len(cname) > 2:
                        from pipeline.analysis.technique_name_mapper import map_class_name_to_technique

                        mapped = map_class_name_to_technique(cname)
                        if mapped and mapped != "unknown":
                            return mapped
                        # 无映射时保留原始 class_name (不返回 "AtomicAttack")
                        if cname != "AtomicAttack":
                            return cname
                    # 1b: params 中的 attack_strategy
                    params = getattr(attack_id, "params", None) or {}
                    if isinstance(params, dict):
                        for key in ("attack_strategy", "technique", "attack_mode"):
                            val = params.get(key)
                            if val and isinstance(val, str):
                                return val
            except Exception:
                pass

        # 路径 2: ar.atomic_attack_identifier 向下钻取 (回退)
        ar_dict = vars(ar) if hasattr(ar, "__dict__") else {}
        aai = ar_dict.get("atomic_attack_identifier")
        if aai is not None:
            try:
                # 尝试向下钻取: attack_technique → attack
                technique_child = None
                children = getattr(aai, "children", None) or {}
                if isinstance(children, dict):
                    technique_child = children.get("attack_technique")
                if technique_child is not None:
                    tech_children = getattr(technique_child, "children", None) or {}
                    if isinstance(tech_children, dict):
                        attack_child = tech_children.get("attack")
                        if attack_child is not None:
                            cname = getattr(attack_child, "class_name", None)
                            if cname and isinstance(cname, str) and len(cname) > 2:
                                from pipeline.analysis.technique_name_mapper import map_class_name_to_technique

                                mapped = map_class_name_to_technique(cname)
                                if mapped and mapped != "unknown":
                                    return mapped
                                if cname != "AtomicAttack":
                                    return cname
            except Exception:
                pass

        # 路径 3: PyRIT 原生 metadata
        metadata = ar_dict.get("metadata") or {}
        if isinstance(metadata, dict):
            for key in ("technique", "attack_mode", "attack_type", "strategy_name"):
                val = metadata.get(key)
                if val and isinstance(val, str):
                    return val

        # 路径 4: PyRIT 原生 error_message 正则提取策略类名
        # 适用场景: 攻击因 API 超时/限速失败, atomic_attack_identifier 为 NULL,
        # 但 error_message 含 "Strategy execution failed for ... in {ClassName}:"
        # R-022 合规: 仅读取 PyRIT 原生 error_message 字段, 不修改原生行为
        error_message = ar_dict.get("error_message") or ""
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

        # 路径 5: PyRIT 原生 attribution_data.parent_eval_hash 关联查询
        # 适用场景: 攻击因 API 超时/错误失败, atomic_attack_identifier 为 None,
        # 但 attribution_data.parent_eval_hash 可关联到同批次已知结果的技术名
        # R-022 合规: 使用 PyRIT 原生 attribution_data + ComponentIdentifier.eval_hash
        if eval_hash_map:
            attribution_data = ar_dict.get("attribution_data")
            if isinstance(attribution_data, dict):
                parent_eval_hash = attribution_data.get("parent_eval_hash")
                if parent_eval_hash and isinstance(parent_eval_hash, str):
                    resolved = eval_hash_map.get(parent_eval_hash)
                    if resolved and resolved != "unknown":
                        return resolved

        return "unknown"


# ============================================================
# 进度轮询器 — 非侵入式背景轮询 CentralMemory
# ============================================================


class ProgressPoller:
    """非侵入式背景进度轮询器.

    在 ``scenario.run_async()`` 执行期间, 通过 asyncio 后台任务定期
    查询 PyRIT 原生 ``CentralMemory.get_attack_results(scenario_result_id=...)``
    获取已完成的 AttackResult, 实时增强 PyRIT 原生 tqdm 进度条.

    R-022 设计原则 (原生优先, 自研即增强):
    - 非侵入式: 不覆盖任何 PyRIT 原生方法, 不修改 scenario 内部状态
    - 原生优先: 使用 PyRIT 原生 ``MemoryInterface.get_attack_results()`` API
    - 原生增强: 通过 tqdm 公开 API ``_instances`` + ``set_postfix()``
      将 ASR/OK/FAIL 数据注入原生 tqdm 进度条, 不替换原生进度条
    - 可选增强: 如果 Memory/tqdm 不可用或查询失败, 静默降级 (不影响执行)
    - 轻量级: 默认 5 秒轮询间隔, 自适应退避到 _MAX_INTERVAL

    用法::

        poller = ProgressPoller(dashboard=dashboard, scenario_result_id=srid, interval=5)
        poller.start()
        result = await scenario.run_async()
        await poller.stop()
    """

    # ── 自适应退避参数 ──
    _MAX_INTERVAL: float = 30.0   # 退避上限

    def __init__(
        self,
        *,
        dashboard: ProgressDashboard,
        scenario_result_id: str,
        interval: float = 5.0,
        asr_tracker: Any | None = None,
        technique_converter_map: dict[str, list] | None = None,
    ) -> None:
        """初始化轮询器.

        Args:
            dashboard: ProgressDashboard 实例 (作为数据收集器, 不再用于渲染).
            scenario_result_id: 场景结果 ID。
            interval: 初始轮询间隔 (秒), 会自适应退避到 _MAX_INTERVAL。
            asr_tracker: 可选的 RealTimeASRTracker 实例, 用于实时 ASR 反馈。
            technique_converter_map: 技术→Converter 实例列表映射, 用于回调行 Converter 链回退。
        """
        self._dashboard = dashboard
        self._scenario_result_id = scenario_result_id
        # P2 修复: 存储 technique_converter_map 供回调行 Converter 链回退
        self._technique_converter_map = technique_converter_map or {}
        self._interval = interval
        self._base_interval = interval  # 退避重置基准
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._last_completed: int = -1  # 上次看到的完成数 (-1 表示从未注入)
        self._asr_tracker = asr_tracker  # P3-O1: 实时 ASR 追踪器
        self._breakthrough_count: int = 0  # O-ASR-9: 突破计数
        self._last_dashboard_count: int = 0  # O-ASR-3: 上次看板打印时的完成数
        self._verbose: bool = os.getenv("PIPELINE_VERBOSE", "0") == "1"  # P2-O7: verbose 模式

    def start(self) -> None:
        """启动背景轮询任务。."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """停止轮询并等待任务结束。."""
        self._stopped = True
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _poll_loop(self) -> None:
        """轮询循环 — 定期查询 CentralMemory 并增强原生 tqdm.

        R-022 策略 (原生优先, 自研即增强):
          ① 查询 PyRIT 原生 CentralMemory 获取 AttackResult 列表
          ② 更新 Dashboard 数据 (全量重统计, 作为数据收集器)
          ③ 通过 ``_inject_postfix()`` 将 ASR/OK/FAIL 注入原生 tqdm
          ④ 检测新增 AttackResult, 打印红队可读回调行
          ⑤ 自适应退避: 无变化时轮询间隔 5s→10s→15s→30s
        """
        seen_ids: dict[str, float] = {}  # ar_id → first_seen_timestamp (monotonic cleanup)

        while not self._stopped:
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break

            if self._stopped:
                break

            try:
                from pyrit.memory import CentralMemory

                memory = CentralMemory.get_memory_instance()
                if memory is None:
                    self._backoff()
                    continue

                results = memory.get_attack_results(scenario_result_id=self._scenario_result_id)
                if not results:
                    self._backoff()
                    continue

                # 定期清理 seen_ids: 超过 300 秒的记录移除, 防止集合无限增长
                now = time.monotonic()
                if len(seen_ids) > 200:
                    expired = [k for k, t in seen_ids.items() if now - t > 300]
                    for k in expired:
                        del seen_ids[k]

                # P0-1: 检测新增 AttackResult, 打印红队可读回调行
                new_results: list[Any] = []
                for ar in results:
                    ar_id = str(getattr(ar, "id", "") or getattr(ar, "attack_result_id", ""))
                    if ar_id and ar_id not in seen_ids:
                        seen_ids[ar_id] = now
                        new_results.append(ar)

                if new_results:
                    for ar in new_results:
                        outcome = getattr(ar, "outcome", None)
                        outcome_str = (
                            str(outcome.value).upper()
                            if hasattr(outcome, "value")
                            else str(outcome).upper()
                        ) if outcome else "UNKNOWN"
                        # D2 增强: 红队回调行 — [B]/[E] + 技术+Converter链 + 数据集 + 载荷 + 响应
                        tech = ProgressDashboard._extract_technique(ar)
                        # P1 修复: 跳过 SequentialAttack 信封结果 (tech="sequential"),
                        # 仅显示子攻击结果 (含真实技术名+响应), 避免冗余行.
                        if tech == "sequential":
                            continue
                        obj = str(getattr(ar, "objective", ""))[:50]
                        resp = _extract_response_brief(ar)
                        # 新增: Converter 链提取 (从原生标识符)
                        conv_names = _extract_converter_chain_brief(ar)
                        # P2 修复: 原生标识符可能不含 pipeline 配置的 Converter,
                        # 回退到 technique_converter_map 按技术名查找
                        if not conv_names and self._technique_converter_map:
                            converters = self._technique_converter_map.get(tech, [])
                            conv_names = [type(c).__name__ for c in converters]
                        # 新增: 数据集来源
                        dataset = _extract_dataset_from_result(ar)
                        # 新增: Baseline/增强标记
                        is_baseline = tech == "prompt_sending" or not conv_names
                        strategy_marker = "[B]" if is_baseline else "[E]"
                        # 组装显示行
                        tech_conv = f"{tech}+{'→'.join(conv_names)}" if conv_names else tech
                        dataset_str = f" | {dataset}" if dataset else ""
                        # O-ASR-9: 突破告警 — 成功攻击使用高亮格式
                        if outcome_str == "SUCCESS":
                            self._breakthrough_count += 1
                            bt_num = self._breakthrough_count
                            # 提取 OWASP 分类
                            import re as _re
                            owasp_match = _re.search(r"(llm\d{2}|asi\d{2})", dataset or "", _re.IGNORECASE)
                            owasp_tag = f" | {owasp_match.group(1).upper()}" if owasp_match else ""
                            conv_tag = f" + {'→'.join(conv_names)}" if conv_names else " (baseline 直发)"
                            print(f"  🚨 BREAKTHROUGH #{bt_num} | {tech}{conv_tag}{owasp_tag}")
                            # P2-O7: 增强突破告警 — 显示载荷+响应+Converter链+ASR
                            print(f"     载荷: {obj}")
                            if resp:
                                print(f"     响应: {resp}")
                            # P2-O7: 显示当前 ASR
                            try:
                                _total = self._dashboard.completed
                                _succ = self._breakthrough_count
                                if _total > 0:
                                    _live_asr = (_succ / _total) * 100
                                    print(f"     实时 ASR: {_live_asr:.1f}% ({_succ}/{_total})")
                            except Exception:
                                pass
                        else:
                            # P2-O7: 噪音过滤 — 拒绝结果不显示响应 (减少终端噪音)
                            marker = "❌" if outcome_str == "FAILURE" else "⚠"
                            # P2-O7: 仅在 verbose 模式下显示失败响应
                            if resp and getattr(self, "_verbose", False):
                                print(f"  {marker} {strategy_marker} {tech_conv[:45]}{dataset_str} | {obj} → {resp}")
                            else:
                                print(f"  {marker} {strategy_marker} {tech_conv[:45]}{dataset_str} | {obj}")

                    # P3-O1: 实时 ASR 反馈 — 将新结果反馈到 ASR 追踪器
                    if self._asr_tracker is not None:
                        try:
                            self._asr_tracker.on_new_results(new_results)
                        except Exception as e:
                            logger.debug(f"RealTime ASR tracker update failed (non-fatal): {e}")

                    # O-ASR-3: 实时 ASR 看板 — 每 15 个新结果打印一次
                    current_completed = self._dashboard.completed
                    if current_completed - self._last_dashboard_count >= 15:
                        self._last_dashboard_count = current_completed
                        self._print_realtime_asr_dashboard(current_completed)

                # 更新 Dashboard 数据 (全量重统计, 作为数据收集器)
                self._dashboard.update_from_attack_results(results)

                # O1: 将 ASR/OK/FAIL 注入 PyRIT 原生 tqdm 进度条
                self._inject_postfix()

                # 自适应退避 / 重置
                if self._dashboard.completed != self._last_completed:
                    self._last_completed = self._dashboard.completed
                    self._reset_interval()
                else:
                    self._backoff()
            except Exception as e:
                logger.debug(f"Progress poll failed (non-fatal): {e}")
                self._backoff()

    def _inject_postfix(self) -> None:
        """R-022 数据层增强: 将 ASR/OK/FAIL 数据注入 PyRIT 原生 tqdm 进度条.

        E1 增强: 从最近的 AttackResult 提取真正攻击技术名 (委托 AttackResultAnalyzer),
        注入技术级实时 ASR 到 tqdm postfix.

        注入效果::

            Executing TextAdaptive: 4%|███| 3/82 [13:31<5:23, ASR=75%, OK=3, FAIL=1, ERR=0, Tech=many_shot(100%)]

        失败时静默降级 (tqdm 实例不可用则跳过, 不影响执行).
        """
        try:
            from tqdm.auto import tqdm as tqdm_cls

            # 查找 PyRIT 原生创建的活跃 tqdm 实例
            for instance in tqdm_cls._instances:
                desc = getattr(instance, "desc", "")
                if desc.startswith("Executing "):
                    # 计算实时全局 ASR
                    completed = self._dashboard.completed
                    succeeded = self._dashboard.succeeded
                    failed = self._dashboard.failed
                    errored = self._dashboard.errored
                    asr = (succeeded / completed * 100) if completed > 0 else 0

                    # E1: 从最近的 AttackResult 提取真正攻击技术名
                    # 使用与 dashboard 相同的 _extract_technique() 确保 key 一致
                    tech_name = self._get_latest_technique_name()
                    tech_asr_str = ""
                    if tech_name and hasattr(self._dashboard, "_asr_tech_success"):
                        tech_total = self._dashboard._asr_tech_total.get(tech_name, 0)
                        tech_succ = self._dashboard._asr_tech_success.get(tech_name, 0)
                        if tech_total > 0:
                            tech_asr = tech_succ / tech_total * 100
                            tech_asr_str = f"{tech_name[:20]}({tech_asr:.0f}%)"

                    # 注入到原生 tqdm 的 postfix (单次调用避免 race condition)
                    postfix_dict: dict[str, Any] = {
                        "ASR": f"{asr:.0f}%",
                        "OK": succeeded,
                        "FAIL": failed,
                        "ERR": errored,
                    }
                    # P3-O2: tech_name 为 "unknown" 时不注入 Tech 字段,
                    # 避免进度条显示无意义的 Tech=unknown(0%)
                    if tech_asr_str and tech_name != "unknown":
                        postfix_dict["Tech"] = tech_asr_str
                    instance.set_postfix(**postfix_dict, refresh=True)
                    break  # 只增强第一个匹配的实例
        except Exception as e:
            logger.debug(f"tqdm postfix injection failed (non-fatal): {e}")

    def _get_latest_technique_name(self) -> str:
        """E1: 从最近的 AttackResult 提取攻击技术名.

        查询 CentralMemory 获取最近完成的 AttackResult,
        使用与 ProgressDashboard._extract_technique() 相同的提取逻辑,
        确保 tech_name 与 _asr_tech_total 字典 key 一致.

        R-022: 使用 PyRIT 原生 CentralMemory API + AttackResult identifier 字段.

        Returns:
            技术名 (如 "many_shot"), 或空字符串 (查询失败时静默降级).
        """
        try:
            from pyrit.memory import CentralMemory

            memory = CentralMemory.get_memory_instance()
            results = memory.get_attack_results(
                scenario_result_id=self._scenario_result_id,
            )
            if not results:
                return ""
            # 取最近一条结果, 使用与 dashboard 相同的提取逻辑确保 key 一致
            # P3 修复: 跳过 SequentialAttack 信封结果 (tech="sequential"),
            # 反向遍历找到第一个子攻击结果 (含真实技术名)
            # P3-O2 修复: 同时跳过 "unknown" (失败攻击的技术名提取 fallback),
            # 继续向前查找有真实技术名的 AttackResult, 避免进度条显示 Tech=unknown(0%)
            for ar in reversed(results):
                tech = ProgressDashboard._extract_technique(ar)
                if tech and tech not in ("sequential", "unknown"):
                    return tech
            return ""
        except Exception:
            return ""

    def _print_realtime_asr_dashboard(self, completed: int) -> None:
        """O-ASR-3: 实时 ASR 看板 — 每 15 个结果打印一次.

        展示当前总体 ASR + 按技术分组的实时 ASR + 趋势预警.
        帮助攻击者在执行过程中实时感知攻击效果, 及时调整策略.

        学术依据:
          - arXiv:2310.04451 — PAIR 自适应策略选择 (实时反馈)
          - arXiv:2406.16241 — TAP 基于搜索的攻击优化 (动态调整)
        """
        try:
            total = self._dashboard.total
            succeeded = self._dashboard.succeeded
            asr = (succeeded / completed * 100) if completed > 0 else 0

            # 从 ASR 追踪器获取技术级 ASR
            tech_asr_lines: list[str] = []
            if self._asr_tracker is not None:
                all_asr = self._asr_tracker.get_all_asr()
                # 按 ASR 降序排列, 展示 Top 3
                sorted_tech = sorted(all_asr.items(), key=lambda x: x[1], reverse=True)
                for tech, tech_asr in sorted_tech[:3]:
                    bar = "█" * int(tech_asr * 20)
                    tech_asr_lines.append(f"  {tech[:25]:<25} {tech_asr * 100:>5.1f}% {bar}")

                # 零 ASR 技术预警
                zero_techs = [
                    t for t, a in all_asr.items()
                    if a == 0.0 and self._asr_tracker.get_technique_asr(t) == 0
                ]
                # 获取技术尝试次数
                for tech_name in list(zero_techs)[:3]:
                    tech_data = self._asr_tracker._techniques.get(tech_name)
                    if tech_data and tech_data.total >= 5:
                        tech_asr_lines.append(f"  ⚠ {tech_name[:23]} 0% ({tech_data.total}次) → 建议熔断跳过")

            # 预测 ASR 区间
            expected_low = 25
            expected_high = 35
            trend = ""
            if asr < expected_low:
                trend = "↓ 低于预期"
            elif asr > expected_high:
                trend = "↑ 高于预期"
            else:
                trend = "→ 符合预期"

            print()
            print(f"  ┌─ 实时 ASR 看板 ({completed}/{total} 完成) ──────────────────────┐")
            print(f"  │ 总体: {asr:.1f}% ({succeeded}/{completed}) | 预测 "
                  f"{expected_low}-{expected_high}% | 趋势: {trend}")
            if tech_asr_lines:
                print("  │")
                for line in tech_asr_lines:
                    print(f"  │{line}")
            print("  └──────────────────────────────────────────────────────────┘")
        except Exception as e:
            logger.debug(f"O-ASR-3 realtime dashboard failed (non-fatal): {e}")

    def _backoff(self) -> None:
        """自适应退避: 当前间隔翻倍, 上限 _MAX_INTERVAL."""
        self._interval = min(self._interval * 2, self._MAX_INTERVAL)

    def _reset_interval(self) -> None:
        """有变化时重置轮询间隔到基准值."""
        self._interval = self._base_interval


def _extract_response_brief(ar: Any) -> str:
    """D2: 从 AttackResult 提取目标响应摘要 (前 50 字符).

    R-022 多路径回退:
      1. ar.last_response — PyRIT 1.0.1 原生 last_response 字段 (MessagePiece)
      2. ar.outcome_reason — PyRIT 1.0.1 原生结果原因

    Args:
        ar: AttackResult 实例

    Returns:
        响应摘要字符串 (最多 50 字符), 空字符串表示无可用响应
    """
    # 路径 1: PyRIT 1.0.1 原生 last_response
    try:
        last_resp = getattr(ar, "last_response", None)
        if last_resp is not None:
            content = getattr(last_resp, "content", "") or getattr(last_resp, "original_value", "")
            if content:
                brief = str(content)[:50]
                return brief + "..." if len(str(content)) > 50 else brief
    except Exception:
        pass

    # 路径 2: PyRIT 1.0.1 原生 outcome_reason
    try:
        reason = getattr(ar, "outcome_reason", None)
        if reason and isinstance(reason, str) and len(reason) > 5:
            brief = reason[:50]
            return brief + "..." if len(reason) > 50 else brief
    except Exception:
        pass

    return ""


def _extract_converter_chain_brief(ar: Any) -> list[str]:
    """D2 增强: 从 AttackResult 提取 Converter 链名列表 (用于实时回调行).

    R-022 PyRIT 原生优先:
      1. AttackResultAnalyzer.extract_converter_chain_names(ar) — 原生标识符路径
         → ar.get_attack_strategy_identifier().children["request_converters"]
         → ConverterIdentifier.class_name (如 "PersuasionConverter", "UnicodeConverter")
      2. ar.metadata — 元数据回退

    Args:
        ar: AttackResult 实例

    Returns:
        Converter 类名列表 (可能为空)
    """
    # 路径 1: 原生标识符路径 — AttackResultAnalyzer
    try:
        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

        chain = AttackResultAnalyzer.extract_converter_chain_names(ar)
        if chain:
            return chain
    except Exception:
        pass

    # 路径 2: metadata 回退
    try:
        metadata = getattr(ar, "metadata", None) or {}
        if isinstance(metadata, dict):
            conv_list = metadata.get("converters") or metadata.get("converter_chain")
            if conv_list and isinstance(conv_list, list):
                return [str(c) for c in conv_list]
    except Exception:
        pass

    return []


def _extract_dataset_from_result(ar: Any) -> str:
    """D2 增强: 从 AttackResult 提取数据集来源名 (用于实时回调行).

    R-022 PyRIT 原生优先:
      1. ar.atomic_attack_identifier.params.get("display_group") — 原生标识符参数
      2. ar.metadata.get("dataset_name") — 元数据回退
      3. ar.metadata.get("display_group") — 元数据回退

    Args:
        ar: AttackResult 实例

    Returns:
        数据集名 (如 "owasp_llm01"), 或空字符串
    """
    # 路径 1: 原生标识符 params
    try:
        aai = getattr(ar, "atomic_attack_identifier", None)
        if aai is not None:
            params = getattr(aai, "params", None) or {}
            if isinstance(params, dict):
                dg = params.get("display_group")
                if dg and isinstance(dg, str):
                    return dg
    except Exception:
        pass

    # 路径 2: metadata 回退
    try:
        metadata = getattr(ar, "metadata", None) or {}
        if isinstance(metadata, dict):
            for key in ("dataset_name", "display_group"):
                val = metadata.get(key)
                if val and isinstance(val, str):
                    return val
    except Exception:
        pass

    return ""


# ============================================================
# 终端汇总表格
# ============================================================


class SummaryTable:
    """批量攻击完成后的汇总表格."""

    @staticmethod
    def render_mode_table(mode_stats: dict) -> str:
        """渲染攻击模式汇总表."""
        lines = [
            "",
            f"  ┌{'─' * 70}┐",
            f"  │ {'Attack Mode Summary':^66s} │",
            f"  ├{'─' * 70}┤",
            f"  │ {'Mode':<22s} │ {'Total':>6s} │ {'Success':>8s} │ {'Fail':>6s} │ {'Rate':>6s} │",
            f"  ├{'─' * 22}┼{'─' * 8}┼{'─' * 10}┼{'─' * 8}┼{'─' * 8}┤",
        ]
        total_all = sum(s["total"] for s in mode_stats.values()) if mode_stats else 0
        succ_all = sum(s["success"] for s in mode_stats.values()) if mode_stats else 0
        fail_all = sum(s["fail"] for s in mode_stats.values()) if mode_stats else 0

        for mode, stats in sorted(mode_stats.items()):
            rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
            lines.append(
                f"  │ {mode:<22s} │ {stats['total']:>6d} │ "
                f"{stats['success']:>8d} │ {stats['fail']:>6d} │ {rate:>5.0f}% │"
            )

        rate_all = succ_all / total_all * 100 if total_all > 0 else 0
        lines.append(f"  ├{'─' * 22}┼{'─' * 8}┼{'─' * 10}┼{'─' * 8}┼{'─' * 8}┤")
        lines.append(
            f"  │ {'TOTAL':<22s} │ {total_all:>6d} │ {succ_all:>8d} │ {fail_all:>6d} │ {rate_all:>5.0f}% │"
        )
        lines.append(f"  └{'─' * 70}┘")
        return "\n".join(lines)


# ============================================================
# 双通道输出管理器
# ============================================================


class DualOutputManager:
    """双通道输出管理器 — 终端 + 文件.

    使用 PyRIT 原生 output_attack_async + FileSink.
    """

    def __init__(self, output_dir: Path, *, verbose: bool = False) -> None:
        """初始化双通道输出管理器."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self._attack_count = 0

        # 文件通道
        self.log_path = self.output_dir / "attacks.md"
        if self.log_path.exists():
            self.log_path.unlink()

        try:
            from pyrit.output import FileSink
            self.file_sink = FileSink(path=self.log_path, mode="a")
        except ImportError:
            self.file_sink = None

        # 终端通道
        try:
            from pyrit.output import StdoutSink, get_default_sink
            self.stdout_sink = get_default_sink(StdoutSink)
        except ImportError:
            self.stdout_sink = None

    async def output_attack_result(
        self,
        result: Any,
        *,
        to_terminal: bool = True,
        to_file: bool = True,
    ) -> None:
        """输出单个攻击结果到双通道。."""
        self._attack_count += 1

        if to_terminal and self.stdout_sink:
            try:
                from pyrit.output import output_attack_async
                await output_attack_async(
                    result,
                    format="pretty",
                    sink=self.stdout_sink,
                    include_auxiliary_scores=True,
                    include_adversarial_conversation=self.verbose,
                )
            except Exception as e:
                logger.warning(f"Terminal output failed: {e}")

        if to_file and self.file_sink:
            try:
                from pyrit.output import output_attack_async
                await output_attack_async(
                    result,
                    format="markdown",
                    sink=self.file_sink,
                    include_auxiliary_scores=True,
                    include_adversarial_conversation=True,
                )
            except Exception as e:
                logger.warning(f"File output failed: {e}")

    async def close(self) -> None:
        """关闭文件通道。."""
        try:
            if self.file_sink:
                await self.file_sink.write_async(
                    f"\n\n---\n*Total attacks logged: {self._attack_count}*\n"
                    f"*Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}*\n"
                )
        except Exception:
            pass


# ============================================================
# Output 目录结构管理器 (合并自 utils/output_manager.py)
# ============================================================


class OutputManager:
    """管理 output/ 目录结构和路径生成。.

    在流水线启动时创建，贯穿所有阶段，
    通过 ``ctx.output_manager`` 传递给各 stage 使用。

    Attributes:
        base_dir: output 根目录 (默认: output)
        timestamp: 本次运行的时间戳 (YYYYMMDD_HHMMSS)
    """

    def __init__(self, base_dir: str = "outputs", timestamp: str | None = None) -> None:
        """初始化输出目录管理器.

        L5-F2: prefix 可通过 OUTPUT_PREFIX 环境变量配置 (默认: redteam_)。
        """
        self.base_dir = Path(base_dir)
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.prefix = os.getenv("OUTPUT_PREFIX", "redteam_")
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """创建所有子目录 (幂等)。."""
        for subdir in ("db", "evidence", "logs", "reports", "empirical_asr"):
            (self.base_dir / subdir).mkdir(parents=True, exist_ok=True)

    # ── 数据库 ──

    @property
    def db_dir(self) -> Path:
        """SQLite 数据库目录。."""
        return self.base_dir / "db"

    @property
    def db_path(self) -> Path:
        """本次运行的 SQLite 数据库路径。."""
        return self.db_dir / f"{self.prefix}{self.timestamp}.db"

    # ── 证据 ──

    @property
    def evidence_dir(self) -> Path:
        """证据根目录。."""
        return self.base_dir / "evidence"

    @property
    def evidence_run_dir(self) -> Path:
        """本次运行的证据目录 (含子目录 attacks/ conversations/ scores/ blurred/)。.

        首次访问时自动创建子目录。
        """
        d = self.evidence_dir / f"{self.prefix}{self.timestamp}"
        for subdir in ("attacks", "conversations", "scores", "blurred"):
            (d / subdir).mkdir(parents=True, exist_ok=True)
        return d

    @property
    def evidence_zip_path(self) -> Path:
        """证据打包 zip 路径。."""
        return self.evidence_dir / f"{self.prefix}{self.timestamp}_evidence.zip"

    # ── 日志 ──

    @property
    def logs_dir(self) -> Path:
        """日志目录。."""
        return self.base_dir / "logs"

    @property
    def log_path(self) -> Path:
        """信号日志路径 (ASR, 攻击, 证据核心信息)。."""
        return self.logs_dir / f"pipeline-{self.timestamp}.log"

    @property
    def noise_log_path(self) -> Path:
        """噪音日志路径 (scorer skipping, config loading 等)。."""
        return self.logs_dir / f"pipeline-{self.timestamp}.noise.log"

    # ── 报告 ──

    @property
    def reports_dir(self) -> Path:
        """报告目录。."""
        return self.base_dir / "reports"

    def report_path(self, ext: str = "md") -> Path:
        """本次运行的报告路径。.

        Args:
            ext: 文件扩展名 (md / html / pdf)
        """
        return self.reports_dir / f"{self.prefix}{self.timestamp}_report.{ext}"

    # ── 经验 ASR ──

    @property
    def empirical_asr_dir(self) -> Path:
        """经验 ASR 数据目录 (per-model JSON)。."""
        return self.base_dir / "empirical_asr"

    def empirical_asr_path(self, model_name: str) -> Path:
        """指定模型的经验 ASR JSON 路径。."""
        safe_name = model_name.replace("/", "_").replace("\\", "_")
        return self.empirical_asr_dir / f"{safe_name}.json"

    # ── 便捷方法 ──

    def print_summary(self) -> None:
        """打印 Output 目录结构摘要。."""
        print("  Output 目录结构:")
        print(f"    根目录: {self.base_dir}")
        print(f"    数据库: {self.db_path.name}")
        print(f"    证据:   {self.evidence_run_dir.relative_to(self.base_dir)}/")
        print(f"    日志:   {self.log_path.name} + {self.noise_log_path.name}")
        print(f"    报告:   {self.reports_dir.relative_to(self.base_dir)}/")
        print(f"    时间戳: {self.timestamp}")
