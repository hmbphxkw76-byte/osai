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
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


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
            f"  │ {'✅ OK:':>8s} {self.succeeded:<5d}  {'❌ FAIL:':>8s} {self.failed:<5d}"
            f"  {'⚠ ERR:':>7s} {self.errored:<5d}{'':>6s}│",
            f"  │ {'Elapsed:':>8s} {elapsed:.0f}s    {'ETA:':>5s} ~{remaining:.0f}s"
            f"    {'Rate:':>5s} {rate:.1f}/min{'':>8s}│",
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
            if tech:
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
    def _extract_technique(ar: Any) -> str:
        """从 AttackResult 提取技术名 (用于 ASR 分组).

        PyRIT 原生优先: 使用 AttackResult 的 attack_mode/attack_type 字段。
        性能优化: 使用 vars() 避免 MagicMock __getattr__ 副作用。
        """
        # 使用 vars(ar) 替代 getattr, 避免 MagicMock 自动创建 Mock 属性
        ar_dict = vars(ar) if hasattr(ar, "__dict__") else {}
        for field_name in ("attack_mode", "attack_type", "strategy_name"):
            val = ar_dict.get(field_name)
            if val is not None:
                return str(val)
        return "unknown"


# ============================================================
# 进度轮询器 — 非侵入式背景轮询 CentralMemory
# ============================================================


class ProgressPoller:
    """非侵入式背景进度轮询器.

    在 ``scenario.run_async()`` 执行期间, 通过 asyncio 后台任务定期
    查询 PyRIT 原生 ``CentralMemory.get_attack_results(scenario_result_id=...)``
    获取已完成的 AttackResult, 实时更新 ProgressDashboard.

    设计原则:
    - 非侵入式: 不覆盖任何 PyRIT 原生方法, 不修改 scenario 内部状态
    - 原生优先: 使用 PyRIT 原生 ``MemoryInterface.get_attack_results()`` API
    - 可选增强: 如果 Memory 不可用或查询失败, 静默降级 (不影响执行)
    - 轻量级: 默认 5 秒轮询间隔, 对性能影响可忽略

    用法::

        poller = ProgressPoller(dashboard=dashboard, scenario_result_id=srid, interval=5)
        poller.start()
        result = await scenario.run_async()
        await poller.stop()
    """

    # ── 防刷屏参数 (业界标准: 仅变化才刷新 + 心跳保活 + 自适应退避) ──
    _MAX_INTERVAL: float = 30.0   # 退避上限
    _HEARTBEAT_INTERVAL: float = 30.0  # 心跳行打印间隔

    def __init__(
        self,
        *,
        dashboard: ProgressDashboard,
        scenario_result_id: str,
        interval: float = 5.0,
    ) -> None:
        """初始化轮询器.

        Args:
            dashboard: ProgressDashboard 实例。
            scenario_result_id: 场景结果 ID。
            interval: 初始轮询间隔 (秒), 会自适应退避到 _MAX_INTERVAL。
        """
        self._dashboard = dashboard
        self._scenario_result_id = scenario_result_id
        self._interval = interval
        self._base_interval = interval  # 退避重置基准
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._last_completed: int = -1  # 上次看到的完成数 (-1 表示从未渲染)
        self._last_heartbeat: float = time.time()  # 上次心跳时间

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
        """轮询循环 — 定期查询 CentralMemory 并更新 Dashboard.

        防刷屏三合一策略 (业界标准, 对标 tqdm/rich.progress):
          ① 状态变化才重绘: 只有 completed 计数变化时才打印完整仪表盘
          ② 心跳线保活: 无变化时每隔 _HEARTBEAT_INTERVAL 秒打印单行心跳
          ③ 自适应退避: 无变化时轮询间隔 5s→10s→15s→30s 渐进退避;
             有变化时重置回 base interval

        L5 P0-1 增强: 检测新增 AttackResult, 打印实时攻击回调 (✅/❌)。
        L5 P0-2 增强: 更新 ASR 迷你仪表盘。
        """
        seen_ids: set[str] = set()

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
                    # Memory 不可用也走心跳逻辑, 避免无声卡死
                    self._maybe_heartbeat()
                    self._backoff()
                    continue

                results = memory.get_attack_results(scenario_result_id=self._scenario_result_id)
                if not results:
                    self._maybe_heartbeat()
                    self._backoff()
                    continue

                # P0-1: 检测新增 AttackResult, 打印实时回调
                new_results: list[Any] = []
                for ar in results:
                    ar_id = str(getattr(ar, "id", "") or getattr(ar, "attack_result_id", ""))
                    if ar_id and ar_id not in seen_ids:
                        seen_ids.add(ar_id)
                        new_results.append(ar)

                if new_results:
                    for ar in new_results:
                        outcome = getattr(ar, "outcome", None)
                        outcome_str = (
                            str(outcome.value).upper()
                            if hasattr(outcome, "value")
                            else str(outcome).upper()
                        ) if outcome else "UNKNOWN"
                        marker = "✅" if outcome_str == "SUCCESS" else ("❌" if outcome_str == "FAILURE" else "⚠")
                        obj = str(getattr(ar, "objective", ""))[:50]
                        tech = ProgressDashboard._extract_technique(ar)
                        print(f"  {marker} [{tech[:20]}] {obj}")

                # 更新 Dashboard (全量重统计, 确保一致性)
                self._dashboard.update_from_attack_results(results)

                # ① 仅状态变化才重绘完整仪表盘
                if self._dashboard.completed != self._last_completed:
                    self._last_completed = self._dashboard.completed
                    self._dashboard.print_progress()
                    self._reset_interval()
                else:
                    # ② 无变化时打印心跳行 (每 _HEARTBEAT_INTERVAL 秒一次)
                    self._maybe_heartbeat()
                    # ③ 自适应退避
                    self._backoff()
            except Exception as e:
                logger.debug(f"Progress poll failed (non-fatal): {e}")
                self._backoff()

    def _backoff(self) -> None:
        """自适应退避: 当前间隔翻倍, 上限 _MAX_INTERVAL."""
        self._interval = min(self._interval * 2, self._MAX_INTERVAL)

    def _reset_interval(self) -> None:
        """有变化时重置轮询间隔到基准值."""
        self._interval = self._base_interval
        self._last_heartbeat = time.time()  # 重置心跳计时

    def _maybe_heartbeat(self) -> None:
        """心跳线保活: 每隔 _HEARTBEAT_INTERVAL 秒打印单行心跳.

        格式: ⏳ {elapsed}s | {completed}/{total} ({pct}%) ✅{succ} ❌{fail}
        用途: 让用户知道流水线在运行, 但不刷屏。
        """
        now = time.time()
        if now - self._last_heartbeat >= self._HEARTBEAT_INTERVAL:
            self._last_heartbeat = now
            elapsed = now - self._dashboard._start_time
            effective_total = max(self._dashboard.total, self._dashboard.completed)
            pct = (
                self._dashboard.completed / effective_total * 100
                if effective_total > 0
                else 0
            )
            print(
                f"  ⏳ {elapsed:.0f}s | {self._dashboard.completed}/{self._dashboard.total} "
                f"({pct:.1f}%) ✅{self._dashboard.succeeded} "
                f"❌{self._dashboard.failed} ⚠{self._dashboard.errored}"
            )


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
