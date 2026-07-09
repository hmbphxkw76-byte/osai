"""
===============================================================================
PyRIT Config Center — 攻击战役管理器 (Campaign Manager)
===============================================================================
线程安全的攻击战役生命周期管理器，负责：
  - 在独立线程中启动/管理后台 asyncio 事件循环
  - 通过队列向 Web 前端 SSE 推送实时攻击进度
  - 支持启动/停止/状态查询/结果导出
  - 单 Campaign 锁防止并发冲突
===============================================================================
"""
from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


class CampaignStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class CampaignState:
    """攻击战役的完整状态快照，线程安全更新。"""
    status: CampaignStatus = CampaignStatus.IDLE
    phase: str = ""
    target_url: str = ""
    total_tasks: int = 0
    completed: int = 0
    success: int = 0
    failure: int = 0
    error: int = 0
    started_at: str = ""
    finished_at: str = ""
    elapsed_seconds: float = 0.0
    latest_log: str = ""
    guidance: dict | None = None
    results: list[dict] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    db_path: str = ""
    log_file: str = ""
    report_file: str = ""
    cancel_requested: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self.status.value,
                "phase": self.phase,
                "target_url": self.target_url,
                "total_tasks": self.total_tasks,
                "completed": self.completed,
                "success": self.success,
                "failure": self.failure,
                "error": self.error,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "elapsed_seconds": round(self.elapsed_seconds, 1),
                "latest_log": self.latest_log,
                "guidance": self.guidance,
                "db_path": self.db_path,
                "log_file": self.log_file,
                "report_file": self.report_file,
                "cancel_requested": self.cancel_requested,
                "percent": round(self.completed / max(self.total_tasks, 1) * 100, 1) if self.total_tasks else 0,
            }


class CampaignManager:
    """攻击战役全局管理器（Singleton）。

    职责:
      1. 在独立 daemon 线程中启动 asyncio 事件循环
      2. 运行 PyRITNativeOrchestrator.run_campaign()
      3. 通过 queue.Queue 向 SSE 端点推送实时事件
      4. 管理战役状态（启动/取消/查询/历史）
    """

    _instance: CampaignManager | None = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self.state = CampaignState()
        self._event_queue: queue.Queue = queue.Queue()
        self._loop_thread: threading.Thread | None = None
        self._orchestrator = None
        self._attack_target = None
        self._cases: list = []
        self._combo_filter: set | None = None
        self._case_filter: set | None = None
        self._max_concurrent: int = 5
        self._use_adaptive: bool = False
        self._enable_early_stop: bool = False
        self._target_vendor: str = ""
        # 保存最近的运行参数用于恢复显示
        self._last_run_args: dict = {}

    @classmethod
    def get_instance(cls) -> CampaignManager:
        """获取全局单例。"""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ═══════════════════════════════════════════════════════════════
    # 公共 API
    # ═══════════════════════════════════════════════════════════════

    def start_campaign(
        self,
        target_url: str,
        api_key: str = "",
        cookie: str = "",
        jwt_token: str = "",
        phase: str = "all",
        scenario_preset: str = "standard",
        max_concurrent: int = 5,
        case_ids: str = "",
        combo_filter: str = "",
        use_adaptive: bool = False,
        enable_early_stop: bool = False,
        target_vendor: str = "",
        lang: str = "cn",
    ) -> dict:
        """启动新的攻击战役。

        Returns:
            {"ok": True, "message": "..."} 或 {"ok": False, "error": "..."}
        """
        if self.state.status == CampaignStatus.RUNNING:
            return {"ok": False, "error": "已有攻击战役正在运行中，请等待完成或先取消当前战役"}

        # 重置状态
        self.state = CampaignState()
        self.state.status = CampaignStatus.RUNNING
        self.state.phase = phase
        self.state.target_url = target_url
        self.state.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._event_queue = queue.Queue()

        self._last_run_args = {
            "target_url": target_url,
            "phase": phase,
            "scenario_preset": scenario_preset,
            "max_concurrent": max_concurrent,
            "use_adaptive": use_adaptive,
            "enable_early_stop": enable_early_stop,
            "target_vendor": target_vendor,
            "lang": lang,
            "api_key": api_key,
            "cookie": cookie,
            "jwt_token": jwt_token,
        }

        # 启动后台线程
        self._loop_thread = threading.Thread(
            target=self._run_campaign_loop,
            args=(target_url, api_key, cookie, jwt_token, phase, scenario_preset,
                  max_concurrent, case_ids, combo_filter, use_adaptive,
                  enable_early_stop, target_vendor, lang),
            daemon=True,
            name="campaign-loop",
        )
        self._loop_thread.start()

        self._push_event({
            "type": "started",
            "message": f"攻击战役已启动: {phase}",
            "target_url": target_url,
            "phase": phase,
        })

        return {
            "ok": True,
            "message": f"攻击战役已启动 ({phase})",
            "status": "running",
        }

    def cancel_campaign(self) -> dict:
        """请求取消正在运行的攻击战役。"""
        if self.state.status != CampaignStatus.RUNNING:
            return {"ok": False, "error": "没有正在运行的攻击战役"}
        self.state.cancel_requested = True
        self._push_event({
            "type": "cancelling",
            "message": "正在取消攻击战役...",
        })
        return {"ok": True, "message": "取消请求已发送"}

    def get_status(self) -> dict:
        """获取当前战役状态快照。"""
        return self.state.snapshot()

    def get_history(self) -> list[dict]:
        """获取历史战役记录。"""
        return self.state.history

    def get_events(self, timeout: float = 30.0) -> dict | None:
        """阻塞获取下一个 SSE 事件（供 SSE 端点使用）。

        Returns:
            dict event 或 None（超时/停止信号）
        """
        try:
            event = self._event_queue.get(timeout=timeout)
            self._event_queue.task_done()
            return event
        except queue.Empty:
            return None

    # ═══════════════════════════════════════════════════════════════
    # 后台执行
    # ═══════════════════════════════════════════════════════════════

    def _run_campaign_loop(
        self,
        target_url: str,
        api_key: str,
        cookie: str,
        jwt_token: str,
        phase: str,
        scenario_preset: str,
        max_concurrent: int,
        case_ids: str,
        combo_filter: str,
        use_adaptive: bool,
        enable_early_stop: bool,
        target_vendor: str,
        lang: str,
    ):
        """后台线程入口：创建独立的 asyncio 事件循环并执行攻击。"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                self._execute_campaign(
                    target_url, api_key, cookie, jwt_token, phase, scenario_preset,
                    max_concurrent, case_ids, combo_filter, use_adaptive,
                    enable_early_stop, target_vendor, lang,
                )
            )
        except Exception as e:
            logger.exception("Campaign execution failed")
            self.state.status = CampaignStatus.ERROR
            self.state.latest_log = f"执行异常: {e}"
            self._push_event({
                "type": "error",
                "message": f"战役执行异常: {str(e)[:500]}",
            })
        finally:
            loop.close()

    async def _execute_campaign(
        self,
        target_url: str,
        api_key: str,
        cookie: str,
        jwt_token: str,
        phase: str,
        scenario_preset: str,
        max_concurrent: int,
        case_ids: str,
        combo_filter: str,
        use_adaptive: bool,
        enable_early_stop: bool,
        target_vendor: str,
        lang: str,
    ):
        """实际的攻击执行协程。"""
        import os

        from orchestrators.pyrit_orchestrator import (
            PyRITNativeOrchestrator,
            AttackPhase,
            AttackConfig,
        )
        from datasets.loader import load_test_cases
        from pyrit.prompt_target import OpenAIChatTarget
        from pyrit.memory import SQLiteMemory, CentralMemory
        from utils import ensure_results_dir, results_path, RESULTS_DIR
        from entrypoint.bootstrap import normalize_auth_value

        try:
            # ── 1. 加载测试用例 ──
            json_file = os.path.join("datasets", f"test_cases_{lang}.json")
            cases, _ = load_test_cases(json_file)
            if not cases:
                raise ValueError(f"无法加载测试用例: {json_file}")

            # ── 2. 解析 phase ──
            phase_map = {
                "probe": AttackPhase.PROBE, "single": AttackPhase.SINGLE,
                "crescendo": AttackPhase.CRESCENDO,
                "pair": AttackPhase.PAIR, "tap": AttackPhase.TAP,
                "flip": AttackPhase.FLIP, "chunked": AttackPhase.CHUNKED,
                "manyshot": AttackPhase.MANYSHOT,
                "skeleton_key": AttackPhase.SKELETON_KEY,
                "all": AttackPhase.ALL,
            }
            attack_phase = phase_map.get(phase, AttackPhase.ALL)

            # ── 3. 构建认证 ──
            normalized_auth = normalize_auth_value(api_key or "")

            # ── 4. 构建攻击目标 ──
            from targets.target_builder import build_attack_target_from_args
            from types import SimpleNamespace

            target_type = "model"
            ssl_skip = not target_url.startswith("https://")

            mock_args = SimpleNamespace(
                target_url=target_url,
                target_type=target_type,
                ssl_skip=ssl_skip,
                auth=api_key,
                env_file=None,
            )

            # 尝试从 shared.env 加载
            from targets.config import load_env_config as _load_env_config_static
            attacker_config, scorer_config = _load_env_config_static(None)

            attack_target = await build_attack_target_from_args(
                mock_args, attacker_config, enable_probe=False,
                normalized_auth=normalized_auth,
            )

            if attack_target is None:
                # 回退：用默认 OpenAI Target
                attack_target = OpenAIChatTarget(
                    endpoint=target_url,
                    api_key=api_key or "placeholder",
                )

            # ── 5. 构建评委 ──
            scorer_target = OpenAIChatTarget(temperature=0)
            if scorer_config and scorer_config.get("endpoint"):
                try:
                    scorer_target = OpenAIChatTarget(
                        endpoint=scorer_config.get("endpoint", ""),
                        api_key=scorer_config.get("api_key", ""),
                    )
                except Exception:
                    pass

            # ── 6. 初始化 Memory ──
            ensure_results_dir()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            db_path = results_path(f"pyrit_campaign_memory_{ts}.db")
            memory = SQLiteMemory(db_path=db_path)
            CentralMemory.set_memory_instance(memory)

            self.state.db_path = db_path

            # ── 7. 创建 Orchestrator ──
            attack_config = AttackConfig.from_preset(scenario_preset)
            orch = PyRITNativeOrchestrator(
                scorer_target=scorer_target,
                max_concurrent=max_concurrent,
                db_path=db_path,
                attack_config=attack_config,
            )

            self._push_event({
                "type": "info",
                "message": f"引擎已就绪 — 阶段: {phase}, 并发: {max_concurrent}, 预设: {scenario_preset}",
                "db_path": db_path,
            })

            # ── 8. 过滤用例 ──
            if case_ids:
                _ids = set(case_ids.replace(" ", "").split(","))
                cases = [c for c in cases if c.get("id", "") in _ids]

            # ── 9. 过滤阶段 ──
            if attack_phase != AttackPhase.ALL:
                from executor import classify_case
                cases = [c for c in cases if classify_case(c) == attack_phase.value]

            if not cases:
                raise ValueError("没有匹配的测试用例")

            # 计算总任务数
            from converters import GLOBAL_ATTACK_COMBINATIONS, resolve_converters
            _cf = set()
            if combo_filter:
                _cf = set(tuple(p.split(":")) for p in combo_filter.strip().split(",") if ":" in p)
            if not _cf:
                _cf = None

            total_tasks = 0
            for case in cases:
                combos = case.get("attack_combos", GLOBAL_ATTACK_COMBINATIONS)
                total_tasks += len(combos)

            self.state.total_tasks = total_tasks
            self._push_event({
                "type": "info",
                "message": f"共 {len(cases)} 个用例, ~{total_tasks} 个攻击任务",
                "case_count": len(cases),
                "total_tasks": total_tasks,
            })

            # ── 10. 执行攻击 — 使用 progress callback ──
            all_results = await orch.run_campaign(
                cases=cases,
                attack_target=attack_target,
                phase=attack_phase,
                case_filter=set(case_ids.split(",")) if case_ids else None,
                combo_filter=_cf,
                use_adaptive_engine=use_adaptive,
                use_dedup_cache=True,
                target_vendor=target_vendor,
                enable_early_stop=enable_early_stop,
                progress_callback=self._on_attack_progress,
            )

            # ── 11. 保存结果 ──
            campaign_name = f"PyRIT_RedTeam_{phase.replace('-','_')}"
            log_file = orch.export_results(all_results, campaign_name)

            self.state.log_file = log_file
            self.state.results = all_results

            # ── 12. 生成报告 ──
            try:
                from reporting import analyze_and_visualize, print_detailed_report, generate_penetrating_report
                from reporting.professional_report import generate_professional_report
                from utils import RESULTS_DIR

                # 标准报告
                heatmap_file = results_path(f"pyrit_campaign_heatmap_{ts}.png")
                analyze_and_visualize(all_results, f"PyRIT Red Team {phase} Success Matrix", heatmap_file)

                # 专业渗透报告
                prof_report_path = generate_professional_report(
                    results=all_results,
                    campaign_name=f"PyRIT_RedTeam_{phase}",
                    target_url=target_url,
                    output_dir=RESULTS_DIR,
                    phase=phase,
                    scenario_preset=scenario_preset,
                    target_vendor=target_vendor,
                )
                if prof_report_path:
                    self.state.report_file = str(prof_report_path)
                    self._push_event({
                        "type": "report_ready",
                        "message": "专业渗透测试报告已生成",
                        "report_file": str(prof_report_path),
                    })

                # 兼容旧格式
                generate_penetrating_report(
                    all_results, campaign_name,
                    output_dir=RESULTS_DIR,
                    target_info={"target_url": target_url, "phase": phase},
                )
            except Exception as e:
                logger.warning(f"报告生成失败（非致命）: {e}")
                self._push_event({
                    "type": "warning",
                    "message": f"报告生成部分失败: {str(e)[:500]}",
                })

            # ── 13. 归档历史 ──
            self.state.history.append(self.state.snapshot())
            if len(self.state.history) > 20:
                self.state.history = self.state.history[-20:]

            # ── 14. 完成 ──
            self.state.status = CampaignStatus.COMPLETED
            self.state.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._push_event({
                "type": "completed",
                "message": "攻击战役已完成",
                "results_count": len(all_results),
                "log_file": log_file,
                "report_file": self.state.report_file,
                "db_path": db_path,
            })

        except Exception as e:
            logger.exception("Campaign execution failed")
            self.state.status = CampaignStatus.ERROR
            self.state.latest_log = f"执行异常: {str(e)[:500]}"
            self._push_event({
                "type": "error",
                "message": f"战役执行异常: {str(e)[:500]}",
            })
        finally:
            if attack_target and hasattr(attack_target, 'close') and callable(attack_target.close):
                try:
                    await attack_target.close()
                except Exception:
                    pass

    def _on_attack_progress(self, event: dict):
        """攻击进度回调 — 由 orchestrator 在每个攻击完成时调用。"""
        # 检查取消请求
        if self.state.cancel_requested:
            self.state.status = CampaignStatus.CANCELLED
            self.state.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            raise asyncio.CancelledError("用户取消了攻击战役")

        # 更新状态
        self.state.completed = event.get("completed", 0)
        self.state.success = event.get("success", 0)
        self.state.failure = event.get("failure", 0)
        self.state.error = event.get("error_count", 0)
        self.state.latest_log = event.get("log_msg", "")
        self.state.guidance = event.get("guidance")
        self.state.total_tasks = event.get("total", self.state.total_tasks)
        self.state.elapsed_seconds = event.get("elapsed_seconds", 0)

        # 推送 SSE 事件
        self._push_event({
            "type": "progress",
            "completed": self.state.completed,
            "total": self.state.total_tasks,
            "success": self.state.success,
            "failure": self.state.failure,
            "error_count": self.state.error,
            "percent": event.get("percent", 0),
            "case_id": event.get("case_id", ""),
            "combo_name": event.get("combo_name", ""),
            "status": event.get("status", ""),
            "mode": event.get("mode", ""),
            "log_msg": event.get("log_msg", ""),
            "response_preview": (event.get("response_text", "") or "")[:300],
            "prompt_preview": (event.get("converted_prompt", "") or "")[:200],
            "score_reason": (event.get("score_reason", "") or "")[:200],
            "guidance": event.get("guidance"),
            "elapsed_seconds": self.state.elapsed_seconds,
        })

    def _push_event(self, event: dict):
        """向事件队列添加 SSE 事件（非阻塞）。"""
        try:
            event["timestamp"] = datetime.now().strftime("%H:%M:%S")
            self._event_queue.put_nowait(event)
        except queue.Full:
            pass  # 丢弃旧事件，防止队列堵塞

    # ═══════════════════════════════════════════════════════════════
    # 结果查询
    # ═══════════════════════════════════════════════════════════════

    def get_results_summary(self) -> dict:
        """获取结果摘要。"""
        if not self.state.results:
            return {"ok": False, "error": "无攻击结果数据", "results_count": 0}
        return {
            "ok": True,
            "results_count": len(self.state.results),
            "success": self.state.success,
            "failure": self.state.failure,
            "error": self.state.error,
            "db_path": self.state.db_path,
            "log_file": self.state.log_file,
            "report_file": self.state.report_file,
        }
