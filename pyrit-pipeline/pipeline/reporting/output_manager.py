# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""统一输出管理器 — 目录结构管理 + 双通道输出 (终端 + 文件)。

合并自 utils/output_manager.py (目录结构) 和原 reporting/output_manager.py (双通道)。

核心能力:
1. OutputManager: 管理 output/ 目录结构和路径生成 (db/ evidence/ logs/ reports/ empirical_asr/)
2. DualOutputManager: 双通道输出 — StdoutSink (终端实时显示) + FileSink (Markdown 持久化)
3. ProgressDashboard: 批量攻击实时进度仪表盘
4. SummaryTable: 批量攻击完成后的汇总表格

遵循开发规则 1.4.1 (原生优先): 使用 PyRIT 原生 output_attack_async / FileSink。
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# 终端进度仪表盘
# ============================================================


class ProgressDashboard:
    """批量攻击实时进度仪表盘。"""

    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.succeeded = 0
        self.failed = 0
        self.errored = 0
        self._start_time = time.time()

    def update(self, *, succeeded: int = 0, failed: int = 0, errored: int = 0):
        self.succeeded += succeeded
        self.failed += failed
        self.errored += errored

    def increment_completed(self):
        self.completed += 1

    def render(self) -> str:
        elapsed = time.time() - self._start_time
        pct = self.completed / self.total * 100 if self.total > 0 else 0
        rate = self.completed / elapsed * 60 if elapsed > 0 else 0
        remaining = (elapsed / self.completed * (self.total - self.completed)) if self.completed > 0 else 0

        bar_width = 30
        filled = int(bar_width * pct / 100)
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
            f"  └{'─' * 60}┘",
        ]
        return "\n".join(lines)

    def print_progress(self):
        print(self.render())


# ============================================================
# 终端汇总表格
# ============================================================


class SummaryTable:
    """批量攻击完成后的汇总表格。"""

    @staticmethod
    def render_mode_table(mode_stats: dict) -> str:
        """渲染攻击模式汇总表。"""
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
    """双通道输出管理器 — 终端 + 文件。

    使用 PyRIT 原生 output_attack_async + FileSink。
    """

    def __init__(self, output_dir: Path, *, verbose: bool = False):
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
        except Exception:
            self.file_sink = None

        # 终端通道
        try:
            from pyrit.output import StdoutSink, get_default_sink
            self.stdout_sink = get_default_sink(StdoutSink)
        except Exception:
            self.stdout_sink = None

    async def output_attack_result(
        self,
        result: Any,
        *,
        to_terminal: bool = True,
        to_file: bool = True,
    ) -> None:
        """输出单个攻击结果到双通道。"""
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
        """关闭文件通道。"""
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
        self.base_dir = Path(base_dir)
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
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
        return self.db_dir / f"redteam_{self.timestamp}.db"

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
        d = self.evidence_dir / f"redteam_{self.timestamp}"
        for subdir in ("attacks", "conversations", "scores", "blurred"):
            (d / subdir).mkdir(parents=True, exist_ok=True)
        return d

    @property
    def evidence_zip_path(self) -> Path:
        """证据打包 zip 路径。."""
        return self.evidence_dir / f"redteam_{self.timestamp}_evidence.zip"

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
        return self.reports_dir / f"redteam_{self.timestamp}_report.{ext}"

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
