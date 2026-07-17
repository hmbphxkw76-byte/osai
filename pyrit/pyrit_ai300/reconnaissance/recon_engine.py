# -*- coding: utf-8 -*-
"""
AI-300 Framework - Reconnaissance Engine
统一调度器：编排所有侦察适配器的执行

设计原则：
- 并发执行：ThreadPoolExecutor 并行调度
- 超时控制：每个适配器独立超时
- 错误隔离：单个工具失败不影响其他工具
- 结果合并：ProfileMerger 统一合并
- 流水线追踪：可选 PipelineTracker 集成
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from .adapters import (
    AdapterResult,
    BaseAdapter,
    DeepTeamAdapter,
    GarakAdapter,
)
from .profile_merger import ProfileMerger
from .target_profile import TargetProfile

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


class ReconEngine:
    """
    侦察引擎统一调度器

    编排 2 个开源工具的执行顺序、并发和错误处理。
    输出 TargetProfile（侦察与攻击的唯一接口契约）。
    可选集成 PipelineTracker 进行全链路追踪。
    """

    # 适配器注册表
    ADAPTER_MAP: Dict[str, type] = {
        "garak": GarakAdapter,
        "deepteam": DeepTeamAdapter,
    }

    def __init__(self, config_path: str = "config/recon/recon.yaml"):
        """
        Args:
            config_path: 侦察配置文件路径
        """
        self.config = self._load_config(config_path)
        self.merger = ProfileMerger(weights=self.config.get("merger", {}).get("confidence_weights"))
        self._adapters: Dict[str, BaseAdapter] = {}

    def run(
        self,
        target: str,
        depth: str = "standard",
        tools: Optional[List[str]] = None,
        tracker: Optional[Any] = None,
    ) -> TargetProfile:
        """
        执行完整侦察流程

        Args:
            target: 目标 URL/endpoint
            depth: 侦察深度（quick/standard/deep）
            tools: 指定工具列表（None=全部启用）
            tracker: PipelineTracker 实例（可选，用于全链路追踪）

        Returns:
            TargetProfile 合并后的目标画像
        """
        start_time = time.time()

        # 确定要使用的工具
        tools_to_run = tools or self._get_enabled_tools()
        logger.info("Starting recon on %s with tools: %s", target, tools_to_run)

        # ── 侦察开始（tracker） ──
        if tracker:
            tracker.log_recon_start(target, tools_to_run)

        # 初始化适配器
        self._init_adapters(tools_to_run)

        # 并发执行所有适配器
        results = self._run_concurrent(target, tools_to_run, tracker)

        # ── 合并结果 ──
        merge_start = time.time()
        profile = self.merger.merge(target=target, results=results, depth=depth)
        merge_duration = (time.time() - merge_start) * 1000

        # 记录合并（tracker）
        if tracker:
            successful_tools = [r.tool for r in results if r.success]
            tracker.log_recon_merge(
                tools_used=successful_tools,
                vuln_count=profile.vulnerability_count,
                risk_level=profile.risk_level,
                duration_ms=merge_duration,
            )

        total_duration = (time.time() - start_time) * 1000
        logger.info(
            "Recon complete: %d tools, %d vulnerabilities, risk=%s, %.1fs",
            len(results),
            profile.vulnerability_count,
            profile.risk_level,
            total_duration / 1000,
        )

        # 记录侦察完成（tracker）
        if tracker:
            tracker.log_recon_complete(
                profile_path="",  # 由调用者填充
                success=True,
                duration_ms=total_duration,
            )

        return profile

    def run_single(self, target: str, tool: str, config: dict = None) -> AdapterResult:
        """
        执行单个工具

        Args:
            target: 目标 URL/endpoint
            tool: 工具名称
            config: 工具配置（可选）

        Returns:
            AdapterResult
        """
        adapter = self._get_adapter(tool)
        tool_config = config or self._get_tool_config(tool)
        return adapter.run(target, tool_config)

    def check_tools(self) -> Dict[str, bool]:
        """
        检查所有工具可用性

        Returns:
            工具名 -> 是否可用
        """
        status = {}
        for name, adapter_cls in self.ADAPTER_MAP.items():
            try:
                adapter = adapter_cls()
                status[name] = adapter.check_available()
            except Exception:
                status[name] = False
        return status

    # ── 私有方法 ──

    def _load_config(self, config_path: str) -> dict:
        """加载侦察配置"""
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            return config.get("recon", config)
        except FileNotFoundError:
            logger.warning("Config not found: %s, using defaults", config_path)
            return {}
        except Exception as e:
            logger.error("Failed to load config: %s", str(e))
            return {}

    def _get_enabled_tools(self) -> List[str]:
        """获取启用的工具列表"""
        tools_config = self.config.get("tools", {})
        enabled = []
        for name, tool_config in tools_config.items():
            if isinstance(tool_config, dict) and tool_config.get("enabled", True):
                enabled.append(name)
        return enabled or list(self.ADAPTER_MAP.keys())

    def _init_adapters(self, tools: List[str]) -> None:
        """初始化指定适配器"""
        self._adapters = {}
        for tool in tools:
            if tool in self.ADAPTER_MAP:
                self._adapters[tool] = self.ADAPTER_MAP[tool]()

    def _get_adapter(self, tool: str) -> BaseAdapter:
        """获取适配器实例"""
        if tool not in self._adapters:
            if tool not in self.ADAPTER_MAP:
                raise ValueError(f"Unknown tool: {tool}")
            self._adapters[tool] = self.ADAPTER_MAP[tool]()
        return self._adapters[tool]

    def _get_tool_config(self, tool: str) -> dict:
        """获取工具配置"""
        return self.config.get("tools", {}).get(tool, {})

    def _run_concurrent(
        self,
        target: str,
        tools: List[str],
        tracker: Optional[Any] = None,
    ) -> List[AdapterResult]:
        """并发执行所有适配器（线程池）"""
        results = []

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for tool in tools:
                adapter = self._get_adapter(tool)
                tool_config = self._get_tool_config(tool)
                future = executor.submit(adapter.run, target, tool_config)
                futures[future] = tool

            for future in concurrent.futures.as_completed(futures):
                tool = futures[future]
                tool_start = time.time()
                try:
                    result = future.result()
                    results.append(result)
                    # 记录工具结果（tracker）
                    if tracker:
                        duration_ms = (time.time() - tool_start) * 1000
                        tracker.log_recon_tool(
                            tool=tool,
                            success=result.success,
                            findings_count=len(result.findings),
                            duration_ms=duration_ms,
                        )
                except Exception as e:
                    logger.error("Tool %s failed: %s", str(e))
                    results.append(AdapterResult(tool=tool, success=False, errors=[str(e)]))
                    # 记录工具失败（tracker）
                    if tracker:
                        duration_ms = (time.time() - tool_start) * 1000
                        tracker.log_recon_tool(
                            tool=tool,
                            success=False,
                            findings_count=0,
                            duration_ms=duration_ms,
                            error=str(e),
                        )

        return results
