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

import hashlib
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .adapters import (
    AdapterResult,
    BaseAdapter,
    DeepTeamAdapter,
    GiskardRagAdapter,
    InfraScanAdapter,
    NativeProbeAdapter,
    ProtocolFingerprintAdapter,
    SPAChatReconAdapter,
)
from .profile_merger import ProfileMerger
from .target_profile import TargetProfile

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# ── OPT-E2: Profile 级缓存目录 ──
RECON_PROFILE_CACHE_DIR = "results/recon/cache/profile"

# ── OPT-E3: 深度自适应超时（秒） ──
DEPTH_TIMEOUTS: Dict[str, Dict[str, int]] = {
    "quick": {"aimap": 15, "native_probe": 60, "deepteam": 60},
    "standard": {"aimap": 30, "native_probe": 120, "deepteam": 120},
    "deep": {"aimap": 60, "native_probe": 300, "deepteam": 300},
}


class ReconEngine:
    """
    侦察引擎统一调度器

    编排 2 个开源工具的执行顺序、并发和错误处理。
    输出 TargetProfile（侦察与攻击的唯一接口契约）。
    可选集成 PipelineTracker 进行全链路追踪。
    """

    # 适配器注册表
    ADAPTER_MAP: Dict[str, type] = {
        "deepteam": DeepTeamAdapter,
        "protocol_fingerprint": ProtocolFingerprintAdapter,
        "spa_chat_recon": SPAChatReconAdapter,
        "native_probe": NativeProbeAdapter,
        "giskard_rag": GiskardRagAdapter,
        "infra_scan": InfraScanAdapter,
    }

    def __init__(self, config_path: str = "config/recon/recon.yaml"):
        """
        Args:
            config_path: 侦察配置文件路径
        """
        self.config = self._load_config(config_path)
        self.merger = ProfileMerger(weights=self.config.get("merger", {}).get("confidence_weights"))
        self._adapters: Dict[str, BaseAdapter] = {}
        # L5: 线程安全锁，保护 _adapters dict 并发访问
        self._adapters_lock = threading.Lock()

    def run(
        self,
        target: str,
        depth: str = "standard",
        tools: Optional[List[str]] = None,
        tracker: Optional[Any] = None,
        use_cache: Optional[bool] = None,
    ) -> TargetProfile:
        """
        执行完整侦察流程（v2 优化版）

        OPT-E1: AIMAP 与 DeepTeam 并行执行（DeepTeam 不依赖 AIMAP）
        OPT-E2: Profile 级增量缓存（target + depth 哈希）
        OPT-E3: 深度自适应超时

        流程（v2）：
        1. OPT-E2: 检查 profile 缓存，命中则直接返回
        2. 启动 AIMAP（主线程）+ DeepTeam（后台线程）并行
        3. AIMAP 完成后配置 NativeProbe 并执行
        4. 等待 DeepTeam 完成
        5. 合并所有结果
        6. OPT-E2: 保存 profile 到缓存

        Args:
            target: 目标 URL/endpoint
            depth: 侦察深度（quick/standard/deep）
            tools: 指定工具列表（None=全部启用）
            tracker: PipelineTracker 实例（可选，用于全链路追踪）
            use_cache: 是否使用缓存（None=使用配置文件设置，True=启用，False=禁用）

        Returns:
            TargetProfile 合并后的目标画像
        """
        start_time = time.time()

        # 确定要使用的工具
        tools_to_run = tools or self._get_enabled_tools()
        logger.info("Starting recon on %s with tools: %s (depth=%s)", target, tools_to_run, depth)

        # ── OPT-E2: 检查 profile 缓存 ──
        # 参数优先级：use_cache > 配置文件 > 默认 True
        _use_cache = use_cache if use_cache is not None else self.config.get("cache", {}).get("enabled", True)
        if _use_cache:
            cached_profile = self._load_profile_cache(target, depth, tools_to_run)
            if cached_profile:
                logger.info("Profile cache hit, skipping recon for %s", target)
                if tracker:
                    tracker.log_recon_optimization(
                        stage="recon_cache_hit",
                        optimization_id="OPT-E2",
                        input_summary=f"target={target}, depth={depth}",
                        output_summary="cache_hit=True",
                        metadata={"cache_key": self._compute_profile_cache_key(target, depth, tools_to_run)},
                    )
                    tracker.log_recon_start(target, tools_to_run)
                    tracker.log_recon_complete(profile_path="", success=True, duration_ms=0)
                return cached_profile

        # ── 侦察开始（tracker） ──
        if tracker:
            tracker.log_recon_start(target, tools_to_run)

        # 初始化适配器
        self._init_adapters(tools_to_run)

        # ── OPT-E3: 深度自适应超时 ──
        depth_timeouts = DEPTH_TIMEOUTS.get(depth, DEPTH_TIMEOUTS["standard"])
        if tracker:
            tracker.log_recon_optimization(
                stage="recon_adaptive_timeout",
                optimization_id="OPT-E3",
                input_summary=f"depth={depth}",
                output_summary=f"timeouts={depth_timeouts}",
                metadata={"depth": depth, "timeouts": depth_timeouts},
            )

        # ── OPT-E1: AIMAP 与 DeepTeam 并行执行 ──
        import concurrent.futures

        aimap_result = None
        deepteam_result = None
        probe_result = None
        probe_target = target
        probe_config_override = None

        # 判断是否需要并行
        has_aimap = "protocol_fingerprint" in tools_to_run
        has_deepteam = "deepteam" in tools_to_run
        has_native_probe = "native_probe" in tools_to_run

        if has_aimap and has_deepteam:
            # OPT-E1: 并行执行 AIMAP 和 DeepTeam
            if tracker:
                tracker.log_recon_optimization(
                    stage="recon_parallel_dispatch",
                    optimization_id="OPT-E1",
                    input_summary="tools=protocol_fingerprint+deepteam",
                    output_summary="parallel=True",
                    metadata={"parallel_tools": ["protocol_fingerprint", "deepteam"]},
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                # 提交 AIMAP
                aimap_future = executor.submit(
                    self._run_single_adapter, "protocol_fingerprint", target, tracker
                )
                # 提交 DeepTeam（不依赖 AIMAP）
                deepteam_future = executor.submit(
                    self._run_single_adapter, "deepteam", target, tracker
                )

                # 等待 AIMAP 完成（用于配置 NativeProbe）
                aimap_result = aimap_future.result()
                # DeepTeam 在后台继续执行

                # 从 AIMAP 结果提取 NativeProbe 端点
                if aimap_result and aimap_result.success and has_native_probe:
                    probe_endpoints = self.extract_probe_endpoints(aimap_result)
                    if probe_endpoints:
                        selected_ep = probe_endpoints[0]
                        probe_target = selected_ep["url"]
                        probe_config_override = {
                            "model_name": selected_ep["model_name"],
                        }
                        logger.info(
                            "AIMAP→NativeProbe: using detected endpoint %s (model=%s)",
                            probe_target, selected_ep["model_name"],
                        )
                        if tracker:
                            tracker.log_recon_optimization(
                                stage="recon_aimap_probe_bridge",
                                optimization_id="AIMAP-PROBE",
                                input_summary=f"aimap_protocols={','.join(aimap_result.data.get('detected_protocols', []))}",
                                output_summary=f"probe_endpoint={probe_target}",
                                metadata={
                                    "aimap_protocols": aimap_result.data.get("detected_protocols", []),
                                    "probe_endpoint": probe_target,
                                    "probe_model_name": selected_ep["model_name"],
                                },
                            )

                # 执行 NativeProbe（如果需要）
                if has_native_probe:
                    probe_config = self._get_tool_config("native_probe")
                    if probe_config_override:
                        probe_config.update(probe_config_override)
                    probe_config["depth"] = depth
                    probe_config["aimap_data"] = aimap_result.data if aimap_result else {}
                    probe_result = self._run_single_adapter("native_probe", probe_target, tracker, config=probe_config)

                # 等待 DeepTeam 完成
                deepteam_result = deepteam_future.result()

        else:
            # 退回串行模式（原有逻辑）
            if has_aimap:
                aimap_result = self._run_single_adapter("protocol_fingerprint", target, tracker)
                if aimap_result and aimap_result.success and has_native_probe:
                    probe_endpoints = self.extract_probe_endpoints(aimap_result)
                    if probe_endpoints:
                        selected_ep = probe_endpoints[0]
                        probe_target = selected_ep["url"]
                        probe_config_override = {
                            "model_name": selected_ep["model_name"],
                        }
                        if tracker:
                            tracker.log_recon_optimization(
                                stage="recon_aimap_probe_bridge",
                                optimization_id="AIMAP-PROBE",
                                input_summary=f"aimap_protocols={','.join(aimap_result.data.get('detected_protocols', []))}",
                                output_summary=f"probe_endpoint={probe_target}",
                                metadata={
                                    "aimap_protocols": aimap_result.data.get("detected_protocols", []),
                                    "probe_endpoint": probe_target,
                                    "probe_model_name": selected_ep["model_name"],
                                },
                            )

            if has_native_probe:
                probe_config = self._get_tool_config("native_probe")
                if probe_config_override:
                    probe_config.update(probe_config_override)
                probe_config["depth"] = depth
                probe_config["aimap_data"] = aimap_result.data if aimap_result else {}
                probe_result = self._run_single_adapter("native_probe", probe_target, tracker, config=probe_config)

            if has_deepteam:
                deepteam_config = self._get_tool_config("deepteam")
                deepteam_config["depth"] = depth
                deepteam_config["aimap_data"] = aimap_result.data if aimap_result else {}
                deepteam_result = self._run_single_adapter("deepteam", target, tracker, config=deepteam_config)

        # 收集所有结果
        results = []
        if aimap_result:
            results.append(aimap_result)
        if probe_result:
            results.append(probe_result)
        if deepteam_result:
            results.append(deepteam_result)

        # 执行未覆盖的工具（如 AIMAP 未执行但其他工具在 tools_to_run 中）
        covered_tools = {"protocol_fingerprint", "deepteam", "native_probe"}
        remaining_tools = [t for t in tools_to_run if t not in covered_tools]
        if remaining_tools:
            remaining_results = self._run_concurrent(target, remaining_tools, tracker)
            results.extend(remaining_results)

        # ── 合并结果 ──
        merge_start = time.time()
        profile = self.merger.merge(target=target, results=results, depth=depth)
        merge_duration = (time.time() - merge_start) * 1000

        # 记录合并（tracker）— 包含冲突检测和交叉验证信息
        if tracker:
            successful_tools = [r.tool for r in results if r.success]
            conflicts = []
            cross_validated = []
            for v in profile.vulnerabilities:
                if v.conflict and v.owasp_mapping:
                    severities = list(set(
                        f.get("severity", v.severity)
                        for r in results if r.success
                        for f in r.findings
                        if f.get("owasp_mapping") == v.owasp_mapping
                        or (
                            not f.get("owasp_mapping")
                            and f.get("category", "").lower().replace("-", "_")
                            == v.category.lower().replace("-", "_")
                        )
                    )) or [v.severity]
                    conflicts.append({
                        "owasp_id": v.owasp_mapping,
                        "tools": v.source_tools,
                        "severities": severities,
                        "description": v.description[:100],
                    })
                elif len(v.source_tools) >= 2 and v.owasp_mapping:
                    cross_validated.append({
                        "owasp_id": v.owasp_mapping,
                        "tools": v.source_tools,
                        "confidence": v.confidence,
                    })
            tracker.log_recon_merge(
                tools_used=successful_tools,
                vuln_count=profile.vulnerability_count,
                risk_level=profile.risk_level,
                duration_ms=merge_duration,
                conflicts=conflicts,
                cross_validated=cross_validated,
            )

        total_duration = (time.time() - start_time) * 1000
        logger.info(
            "Recon complete: %d tools, %d vulnerabilities, risk=%s, %.1fs",
            len(results),
            profile.vulnerability_count,
            profile.risk_level,
            total_duration / 1000,
        )

        # ── OPT-E2: 保存 profile 到缓存 ──
        if _use_cache:
            self._save_profile_cache(target, depth, tools_to_run, profile)

        # 记录侦察完成（tracker）
        if tracker:
            tracker.log_recon_complete(
                profile_path="",  # 由调用者填充
                success=True,
                duration_ms=total_duration,
            )

        return profile

    def run_streaming(
        self,
        target: str,
        depth: str = "standard",
        tools: Optional[List[str]] = None,
        tracker: Optional[Any] = None,
    ):
        """
        流式侦察：AIMAP 优先 → NativeProbe 配置 → 剩余工具流式执行

        用于 --auto-recon 模式：AIMAP 先执行识别协议，配置 NativeProbe 后
        再流式执行剩余工具。

        Yields:
            (tool_name: str, partial_profile: TargetProfile, is_complete: bool)
            - tool_name: 刚完成的适配器名称
            - partial_profile: 当前合并后的部分画像
            - is_complete: 是否全部完成
        """
        import concurrent.futures

        start_time = time.time()
        tools_to_run = tools or self._get_enabled_tools()
        logger.info("Starting streaming recon on %s with tools: %s", target, tools_to_run)

        if tracker:
            tracker.log_recon_start(target, tools_to_run)

        self._init_adapters(tools_to_run)

        # ── AIMAP 优先执行 → 配置 NativeProbe ──
        aimap_result = None
        probe_target = target
        probe_config_override = None

        if "protocol_fingerprint" in tools_to_run:
            aimap_result = self._run_single_adapter("protocol_fingerprint", target, tracker)

            # 从 AIMAP 结果提取 NativeProbe 端点
            if aimap_result and aimap_result.success and "native_probe" in tools_to_run:
                probe_endpoints = self.extract_probe_endpoints(aimap_result)
                if probe_endpoints:
                    selected_ep = probe_endpoints[0]
                    probe_target = selected_ep["url"]
                    probe_config_override = {
                        "model_name": selected_ep["model_name"],
                    }
                    logger.info(
                        "AIMAP→NativeProbe (streaming): using detected endpoint %s", probe_target,
                    )

                    if tracker:
                        tracker.log_recon_optimization(
                            stage="recon_aimap_probe_bridge",
                            optimization_id="AIMAP-PROBE",
                            input_summary=f"aimap_protocols={','.join(aimap_result.data.get('detected_protocols', []))}",
                            output_summary=f"probe_endpoint={probe_target}",
                            metadata={
                                "aimap_protocols": aimap_result.data.get("detected_protocols", []),
                                "probe_endpoint": probe_target,
                                "probe_model_name": selected_ep["model_name"],
                            },
                        )

        # 增量合并状态
        partial_profile = None
        completed_tools = set()
        all_results = []

        # 添加 AIMAP 结果
        if aimap_result:
            all_results.append(aimap_result)
            partial_profile = self.merger.merge_incremental(
                target=target,
                existing_profile=None,
                new_result=aimap_result,
                depth=depth,
            )
            completed_tools.add("protocol_fingerprint")

        # ── 流式执行剩余工具 ──
        remaining_tools = [t for t in tools_to_run if t != "protocol_fingerprint"]

        # 检查剩余工具是否都不可用（预检）
        available_remaining = []
        for tool in remaining_tools:
            adapter = self._get_adapter(tool)
            if adapter.check_available():
                available_remaining.append(tool)

        # 如果 AIMAP 已执行且没有可用剩余工具，直接完成
        if aimap_result and not available_remaining:
            yield ("protocol_fingerprint", partial_profile, True)
            total_duration = (time.time() - start_time) * 1000
            if tracker:
                tracker.log_recon_complete(profile_path="", success=True, duration_ms=total_duration)
            return
        elif aimap_result:
            yield ("protocol_fingerprint", partial_profile, False)

        if remaining_tools:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = {}
                skipped_tools = set()
                for tool in remaining_tools:
                    adapter = self._get_adapter(tool)
                    if not adapter.check_available():
                        logger.warning("%s not installed, skipping", tool)
                        skipped_tools.add(tool)
                        if tracker:
                            tracker.log_recon_tool(
                                tool=tool, success=False,
                                findings_count=0, duration_ms=0,
                                error="not installed",
                            )
                        continue

                    # NativeProbe 使用 AIMAP 检测到的端点和配置
                    if tool == "native_probe" and probe_config_override:
                        probe_config = self._get_tool_config("native_probe")
                        probe_config.update(probe_config_override)
                        future = executor.submit(adapter.run, probe_target, probe_config)
                    else:
                        tool_config = self._get_tool_config(tool)
                        future = executor.submit(adapter.run, target, tool_config)
                    futures[future] = tool

                # 实际会执行的工具 = 剩余工具 - 跳过的工具
                actually_running = len(futures)

                for future in concurrent.futures.as_completed(futures):
                    tool = futures[future]
                    tool_start = time.time()
                    try:
                        result = future.result()
                        all_results.append(result)
                        completed_tools.add(tool)

                        # 增量合并
                        partial_profile = self.merger.merge_incremental(
                            target=target,
                            existing_profile=partial_profile,
                            new_result=result,
                            depth=depth,
                        )

                        # 记录工具结果
                        if tracker:
                            duration_ms = (time.time() - tool_start) * 1000
                            tracker.log_recon_tool(
                                tool=tool,
                                success=result.success,
                                findings_count=len(result.findings),
                                duration_ms=duration_ms,
                            )

                        # 完成条件：所有非跳过工具都已完成
                        is_complete = len(completed_tools) == len(tools_to_run) - len(skipped_tools)
                        yield (tool, partial_profile, is_complete)

                    except Exception as e:
                        logger.error("Tool %s failed: %s", tool, str(e))
                        if tracker:
                            duration_ms = (time.time() - tool_start) * 1000
                            tracker.log_recon_tool(
                                tool=tool,
                                success=False,
                                findings_count=0,
                                duration_ms=duration_ms,
                                error=str(e),
                            )
                        is_complete = len(completed_tools) == len(tools_to_run) - len(skipped_tools)
                        if partial_profile:
                            yield (tool, partial_profile, is_complete)

        # 如果所有剩余工具都被跳过，确保最后一个 yield 标记完成
        if remaining_tools and len(completed_tools) == len(tools_to_run) - len(skipped_tools):
            # 已经通过 yield 标记完成，无需额外操作
            pass

        total_duration = (time.time() - start_time) * 1000
        logger.info(
            "Streaming recon complete: %d tools, %.1fs",
            len(completed_tools),
            total_duration / 1000,
        )

        if tracker:
            tracker.log_recon_complete(
                profile_path="",
                success=True,
                duration_ms=total_duration,
            )

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

    def run_spa_recon(
        self,
        spa_config_path: str,
        tracker: Optional[Any] = None,
        use_cache: Optional[bool] = None,
    ) -> TargetProfile:
        """
        执行 SPA 智能助手侦察

        从 YAML 配置文件加载完整的 SPA 配置（登录凭证、选择器、探测策略等），
        通过 SPAChatReconAdapter 执行浏览器自动化侦察。

        流程：
        1. 加载 SPA 配置文件（login / chat_entry / selectors / probe）
        2. 合并 recon.yaml 中的 spa_chat_recon 默认配置
        3. 执行 SPAChatReconAdapter
        4. 合并结果到 TargetProfile

        Args:
            spa_config_path: SPA 目标配置文件路径（如 config/targets/spa_target.yaml）
            tracker: PipelineTracker 实例（可选）
            use_cache: 是否使用缓存（None=使用配置文件设置，True=启用，False=禁用）

        Returns:
            TargetProfile 包含后端 LLM 模型信息、API 端点、能力等

        Example:
            engine = ReconEngine()
            profile = engine.run_spa_recon("config/targets/spa_target.yaml")
            profile.save("results/recon/spa_profile.json")
        """
        start_time = time.time()
        logger.info("Starting SPA chat recon with config: %s", spa_config_path)

        # 加载 SPA 配置
        spa_config = self.load_spa_config(spa_config_path)
        target_url = spa_config.get("connection", {}).get("url", "")

        # ── OPT-E2: 检查 profile 缓存 ──
        # 参数优先级：use_cache > 配置文件 > 默认 True
        _use_cache = use_cache if use_cache is not None else self.config.get("cache", {}).get("enabled", True)
        if _use_cache:
            cached_profile = self._load_profile_cache(target_url, "standard", ["spa_chat_recon"])
            if cached_profile:
                logger.info("Profile cache hit, skipping SPA recon for %s", target_url)
                if tracker:
                    tracker.log_recon_start(target_url, ["spa_chat_recon"])
                    tracker.log_recon_optimization(
                        stage="recon_cache_hit",
                        optimization_id="OPT-E2",
                        input_summary=f"target={target_url}, spa_config={spa_config_path}",
                        output_summary="cache_hit=True",
                        metadata={"cache_key": self._compute_profile_cache_key(target_url, "standard", ["spa_chat_recon"])},
                    )
                    tracker.log_recon_complete(profile_path="", success=True, duration_ms=0)
                return cached_profile

        if tracker:
            tracker.log_recon_start(target_url, ["spa_chat_recon"])

        # 合并 recon.yaml 中的默认配置
        tool_config = self._get_tool_config("spa_chat_recon")
        merged_config = {**tool_config, **spa_config}

        # 执行 SPA 侦察适配器
        adapter = self._get_adapter("spa_chat_recon")
        result = self._run_single_adapter(
            "spa_chat_recon",
            target_url,
            tracker,
            config=merged_config,
        )

        # 合并结果到 TargetProfile
        profile = self.merger.merge(
            target=target_url,
            results=[result] if result else [],
            depth="standard",
        )

        total_duration = (time.time() - start_time) * 1000
        logger.info(
            "SPA recon complete: %d findings, risk=%s, %.1fs",
            profile.vulnerability_count,
            profile.risk_level,
            total_duration / 1000,
        )

        # ── OPT-E2: 保存 profile 到缓存 ──
        if _use_cache:
            self._save_profile_cache(target_url, "standard", ["spa_chat_recon"], profile)

        if tracker:
            tracker.log_recon_complete(
                profile_path="",
                success=True,
                duration_ms=total_duration,
            )

        return profile

    @staticmethod
    def load_spa_config(config_path: str) -> dict:
        """
        从 YAML 文件加载 SPA 侦察配置

        支持三种格式：
        1. 极简格式（spa_target.yaml v2）：target.url / target.username / auto_detected
        2. 标准格式（spa_target.yaml v1）：target.connection / target.auth / target.spa
        3. 扁平格式（无 target 顶层键）

        Args:
            config_path: YAML 配置文件路径

        Returns:
            扁平化的配置字典，包含 connection / login / chat_entry / selectors / probe

        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 配置格式错误
        """
        import yaml
        from pathlib import Path

        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"SPA config not found: {config_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # 环境变量替换（${VAR} → 实际值，如 ${SPA_USERNAME} → 真实用户名）
        from ..utils.env_loader import resolve_env_vars
        data = resolve_env_vars(data)

        # 提取 auto_detected 段（极简格式的自动回写选择器）
        auto_detected = data.get("auto_detected", {})

        # 如果有 target 顶层键，提取内部配置
        if "target" in data:
            target_data = data["target"]

            # ── 极简格式检测：target.url 直接存在 ──
            if "url" in target_data and "connection" not in target_data:
                from urllib.parse import urlparse

                _url = target_data.get("url", "")
                _parsed = urlparse(_url)
                # 从 URL 自动提取 target_domain（与 auto_spa_recon.py 一致）
                _target_domain = (
                    target_data.get("target_domain")
                    or _parsed.hostname
                    or ""
                )
                # SSO 子域名默认 "passport"（通用 SSO 认证中心子域名）
                _sso_domain = target_data.get("sso_domain", "passport")

                result = {
                    "connection": {
                        "url": _url,
                        "browser": "chromium",
                        "headless": False,
                        "wait_until": "networkidle",
                        "ignore_https_errors": True,
                    },
                    "auth": {
                        "mode": target_data.get("auth_mode", "sso"),
                        "username": target_data.get("username", ""),
                        "password": target_data.get("password", ""),
                        "target_domain": _target_domain,
                        "sso_domain": _sso_domain,
                    },
                }
                # 从 auto_detected 读取选择器
                if auto_detected:
                    result["chat_entry"] = {
                        "mode": "selector" if auto_detected.get("chat_entry") else "auto",
                        "selector": auto_detected.get("chat_entry", ""),
                        "wait_after_click": 3000,
                    }
                    result["selectors"] = {
                        "input": auto_detected.get("input", ""),
                        "send_button": auto_detected.get("send_button", ""),
                        "response": auto_detected.get("response", ""),
                    }
                return result

            # ── 标准格式 ──
            result = {}
            for key in ("connection", "login", "auth", "chat_entry", "selectors", "probe",
                        "screenshot_dir", "save_storage_state", "spa", "interaction", "rate_control"):
                if key in target_data:
                    result[key] = target_data[key]
            # 如果有 auto_detected 且没有显式 selectors，用 auto_detected
            if auto_detected and "selectors" not in result:
                result["chat_entry"] = {
                    "mode": "selector" if auto_detected.get("chat_entry") else "auto",
                    "selector": auto_detected.get("chat_entry", ""),
                    "wait_after_click": 3000,
                }
                result["selectors"] = {
                    "input": auto_detected.get("input", ""),
                    "send_button": auto_detected.get("send_button", ""),
                    "response": auto_detected.get("response", ""),
                }
            return result
        else:
            # 扁平格式，直接返回
            return data

    def _run_single_adapter(
        self,
        tool: str,
        target: str,
        tracker: Optional[Any] = None,
        config: Optional[dict] = None,
    ) -> AdapterResult:
        """
        执行单个适配器（内部方法，含 tracker 记录 + 优化阶段追踪）

        Args:
            tool: 工具名称
            target: 目标 URL/endpoint
            tracker: PipelineTracker 实例
            config: 工具配置（可选，覆盖默认配置）

        Returns:
            AdapterResult
        """
        adapter = self._get_adapter(tool)
        tool_config = config or self._get_tool_config(tool)

        # ── 追踪适配器层面的优化项 ──
        if tracker and tool_config:
            aimap_data = tool_config.get("aimap_data", {})
            depth = tool_config.get("depth", "standard")

            if tool == "protocol_fingerprint":
                # OPT-A1: 协议探测并行化
                tracker.log_recon_optimization(
                    stage="recon_protocol_parallel",
                    optimization_id="OPT-A1",
                    input_summary=f"target={target}",
                    output_summary="ThreadPoolExecutor(max_workers=8)",
                    metadata={"depth": depth},
                )
                # OPT-A3: RAG 端点探测
                if tool_config.get("enable_rag_probe", True):
                    tracker.log_recon_optimization(
                        stage="recon_rag_probe",
                        optimization_id="OPT-A3",
                        input_summary=f"target={target}",
                        output_summary="RAG_ENDPOINT_RULES(4)",
                        metadata={"enabled": True},
                    )
                # OPT-A4: Agent 框架探测
                if tool_config.get("enable_agent_probe", True):
                    tracker.log_recon_optimization(
                        stage="recon_agent_probe",
                        optimization_id="OPT-A4",
                        input_summary=f"target={target}",
                        output_summary="AGENT_FRAMEWORK_RULES(4)",
                        metadata={"enabled": True},
                    )
                # OPT-A5: 认证深度检测
                tracker.log_recon_optimization(
                    stage="recon_auth_deep",
                    optimization_id="OPT-A5",
                    input_summary=f"target={target}",
                    output_summary="bearer+api_key+cookie+oauth+jwt+bypass",
                    metadata={"enabled": True},
                )
                # OPT-A6: 模型能力深度探测
                if tool_config.get("enable_capability_probe", True):
                    tracker.log_recon_optimization(
                        stage="recon_capability_probe",
                        optimization_id="OPT-A6",
                        input_summary=f"target={target}",
                        output_summary="function_calling+json_mode+vision+streaming",
                        metadata={"enabled": True},
                    )

            elif tool == "deepteam":
                # OPT-D1: 攻击类型全量覆盖
                tracker.log_recon_optimization(
                    stage="recon_deepteam_attack_types",
                    optimization_id="OPT-D1",
                    input_summary=f"depth={depth}",
                    output_summary=f"attack_types_by_depth={depth}",
                    metadata={"depth": depth},
                )
                # OPT-D2: Agentic 漏洞覆盖
                has_agent = "agent" in aimap_data.get("surfaces", []) or "mcp" in aimap_data.get("detected_protocols", [])
                if has_agent and depth != "quick":
                    tracker.log_recon_optimization(
                        stage="recon_deepteam_agentic",
                        optimization_id="OPT-D2",
                        input_summary="agent_surface=mcp/agent",
                        output_summary="agentic_attacks=enabled(ASI01-04)",
                        metadata={"has_agent_surface": True},
                    )
                # OPT-D4: 异步模式
                if tool_config.get("async_mode", True):
                    tracker.log_recon_optimization(
                        stage="recon_deepteam_async",
                        optimization_id="OPT-D4",
                        input_summary="async_mode=True",
                        output_summary=f"max_concurrent={tool_config.get('max_concurrent', 3)}",
                        metadata={"enabled": True},
                    )
                # OPT-D5: 攻击方法配置
                tracker.log_recon_optimization(
                    stage="recon_deepteam_attack_methods",
                    optimization_id="OPT-D5",
                    input_summary="attack_methods=auto",
                    output_summary="ATTACK_METHODS(16)",
                    metadata={"enabled": True},
                )

            elif tool == "spa_chat_recon":
                # SPA 智能助手侦察：浏览器自动化 + 网络流量捕获
                tracker.log_recon_optimization(
                    stage="recon_spa_chat_browser",
                    optimization_id="SPA-RECON",
                    input_summary=f"target={target}",
                    output_summary="playwright+traffic_capture+llm_identify",
                    metadata={
                        "browser": tool_config.get("browser", "chromium"),
                        "headless": tool_config.get("headless", False),
                        "login_mode": tool_config.get("login", {}).get("mode", "manual"),
                    },
                )

            elif tool == "native_probe":
                # 轻量级探针：零外部依赖的 静态 probe 数据
                tracker.log_recon_optimization(
                    stage="recon_native_probe",
                    optimization_id="NATIVE-PROBE",
                    input_summary=f"depth={depth}, aimap_data={'yes' if aimap_data else 'no'}",
                    output_summary="static_probe_data+pattern_detector+refusal_detector",
                    metadata={
                        "depth": depth,
                        "zero_dependency": True,
                        "probes_source": "garak_v0.15.1_extracted",
                    },
                )

        # ── 偏差⑥修复：check_available 预检 ──
        # 在执行 adapter.run() 之前检查工具依赖是否就绪
        # 避免在运行时因缺少依赖（如 playwright/deepteam）而崩溃
        if hasattr(adapter, "check_available"):
            try:
                if not adapter.check_available():
                    err_msg = f"Adapter '{tool}' is not available (check_available returned False)"
                    logger.warning("Skipping adapter '%s': %s", tool, err_msg)
                    if tracker:
                        tracker.log_recon_tool(
                            tool=tool,
                            success=False,
                            findings_count=0,
                            duration_ms=0,
                            error=err_msg,
                        )
                    return adapter._make_error_result(err_msg) if hasattr(adapter, "_make_error_result") else \
                        AdapterResult(tool=tool, success=False, errors=[err_msg])
            except Exception as check_err:
                logger.warning("Adapter '%s' check_available raised: %s — proceeding anyway", tool, check_err)

        tool_start = time.time()
        result = adapter.run(target, tool_config)
        duration_ms = (time.time() - tool_start) * 1000

        # 记录工具结果（tracker）
        if tracker:
            tracker.log_recon_tool(
                tool=tool,
                success=result.success,
                findings_count=len(result.findings),
                duration_ms=duration_ms,
                error=result.errors[0] if result.errors else "",
            )

            # ── OPT-M1: 语义去重追踪 ──
            if result.success and result.findings:
                tracker.log_recon_optimization(
                    stage="recon_merger_jaccard_dedup",
                    optimization_id="OPT-M1",
                    input_summary=f"findings={len(result.findings)}",
                    output_summary="jaccard_threshold=0.80",
                    metadata={"threshold": 0.80},
                )

        return result

    @staticmethod
    def extract_probe_endpoints(aimap_result: AdapterResult) -> List[Dict[str, Any]]:
        """
        从 AIMAP 协议识别结果提取 NativeProbe 可探测的端点

        Args:
            aimap_result: AIMAP 适配器的返回结果

        Returns:
            端点列表，每个端点包含：
            - url: 完整 endpoint URL
            - protocol: 检测到的协议
            - model_name: 模型名称
            - label: 显示标签
        """
        if not aimap_result or not aimap_result.success:
            return []

        data = aimap_result.data
        entry_points = data.get("entry_points", [])
        model_name = data.get("model_name") or ""

        endpoints = []
        for ep in entry_points:
            url = ep.get("url", "")
            protocol = ep.get("protocol", "")
            if not url:
                continue

            mname = model_name or ("llama3.2" if protocol == "ollama" else "gpt-4o")

            # 构建显示标签
            label = f"{protocol}"
            if mname:
                label += f" ({mname})"
            label += f" → {url}"

            endpoints.append({
                "url": url,
                "protocol": protocol,
                "model_name": mname,
                "label": label,
            })

        return endpoints

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
        """
        加载侦察配置（支持拆分式组件配置）

        从 config_path 加载引擎级配置，并自动加载同目录下的组件级配置：
          deepteam.yaml      → tools.deepteam
          aimap.yaml          → tools.protocol_fingerprint
          native_probe.yaml   → tools.native_probe
          spa_chat.yaml       → tools.spa_chat_recon

        兼容旧式单文件配置（tools 节内联在 recon.yaml 中）。
        """
        try:
            import yaml
            import os
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

            # 从 recon.yaml 提取引擎级配置
            recon_config = config.get("recon", config)

            # 兼容旧式：从 recon.yaml 内联 tools 节加载
            tools_config = config.get("tools", {})

            # 加载组件级配置（从同目录下的独立 YAML 文件）
            config_dir = os.path.dirname(config_path)
            component_files = [
                "deepteam.yaml",
                "aimap.yaml",
                "native_probe.yaml",
                "spa_chat.yaml",
            ]
            for filename in component_files:
                component_path = os.path.join(config_dir, filename)
                if os.path.exists(component_path):
                    try:
                        with open(component_path, "r", encoding="utf-8") as cf:
                            comp_config = yaml.safe_load(cf) or {}
                        # 取第一个顶层 key 作为工具配置
                        for key, value in comp_config.items():
                            if isinstance(value, dict):
                                tools_config.setdefault(key, value)
                    except Exception as e:
                        logger.warning(
                            "Failed to load component config %s: %s",
                            filename, e,
                        )

            recon_config["tools"] = tools_config
            # 保留 merger 配置
            if "merger" in config:
                recon_config["merger"] = config["merger"]
            return recon_config
        except FileNotFoundError:
            logger.warning("Config not found: %s, using defaults", config_path)
            return {}
        except Exception as e:
            logger.error("Failed to load config: %s", str(e))
            return {}

    @staticmethod
    def load_target(target_file: str) -> str:
        """
        从 config/targets/ 目录加载目标 URL

        Args:
            target_file: 目标配置文件路径（如 config/targets/llm_api_target.yaml）

        Returns:
            目标 URL 字符串

        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 文件格式错误或缺少 endpoint
        """
        import yaml
        from pathlib import Path

        path = Path(target_file)
        if not path.exists():
            raise FileNotFoundError(f"Target config not found: {target_file}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        target_data = data.get("target", {})
        connection = target_data.get("connection", {})

        # 提取 endpoint URL
        endpoint = connection.get("endpoint", "")
        if not endpoint:
            raise ValueError(
                f"Target config missing 'target.connection.endpoint': {target_file}"
            )
        return endpoint

    def _get_enabled_tools(self) -> List[str]:
        """获取启用的工具列表"""
        tools_config = self.config.get("tools", {})
        enabled = []
        for name, tool_config in tools_config.items():
            if isinstance(tool_config, dict) and tool_config.get("enabled", True):
                enabled.append(name)
        return enabled or list(self.ADAPTER_MAP.keys())

    # ── OPT-E2: Profile 缓存方法 ──

    @staticmethod
    def _compute_profile_cache_key(
        target: str, depth: str, tools: List[str]
    ) -> str:
        """计算 profile 缓存键（target + depth + tools 的哈希）"""
        key_str = f"{target}|{depth}|{','.join(sorted(tools))}"
        return hashlib.md5(key_str.encode("utf-8")).hexdigest()

    def _load_profile_cache(
        self, target: str, depth: str, tools: List[str]
    ) -> Optional[TargetProfile]:
        """加载 profile 缓存"""
        cache_key = self._compute_profile_cache_key(target, depth, tools)
        cache_file = Path(RECON_PROFILE_CACHE_DIR) / f"{cache_key}.json"
        if not cache_file.exists():
            return None

        # 检查缓存是否过期（默认 24 小时）
        cache_ttl = self.config.get("cache", {}).get("ttl_seconds", 86400)
        mtime = cache_file.stat().st_mtime
        if time.time() - mtime > cache_ttl:
            logger.debug("Profile cache expired: %s", cache_key)
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 从字典重建 TargetProfile
            profile = TargetProfile.from_dict(data)
            logger.info("Profile cache hit: %s", cache_key)
            return profile
        except Exception as e:
            logger.warning("Failed to load profile cache: %s", str(e))
            return None

    def _save_profile_cache(
        self,
        target: str,
        depth: str,
        tools: List[str],
        profile: TargetProfile,
    ) -> None:
        """保存 profile 到缓存"""
        cache_key = self._compute_profile_cache_key(target, depth, tools)
        cache_dir = Path(RECON_PROFILE_CACHE_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            data = profile.to_dict()
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info("Profile cache saved: %s", cache_key)
        except Exception as e:
            logger.warning("Failed to save profile cache: %s", str(e))

    def _init_adapters(self, tools: List[str]) -> None:
        """初始化指定适配器（线程安全）"""
        with self._adapters_lock:
            self._adapters = {}
            for tool in tools:
                if tool in self.ADAPTER_MAP:
                    self._adapters[tool] = self.ADAPTER_MAP[tool]()

    def _get_adapter(self, tool: str) -> BaseAdapter:
        """
        获取适配器实例（线程安全）

        在多线程环境下，使用 Lock 保护 _adapters dict 的读写操作。
        采用 double-checked locking 模式减少锁竞争。
        """
        # Fast path: adapter already initialized (no lock)
        if tool in self._adapters:
            return self._adapters[tool]
        # Slow path: acquire lock and re-check
        with self._adapters_lock:
            # Double-checked locking
            if tool in self._adapters:
                return self._adapters[tool]
            if tool not in self.ADAPTER_MAP:
                raise ValueError(f"Unknown tool: {tool}")
            self._adapters[tool] = self.ADAPTER_MAP[tool]()
            return self._adapters[tool]

    # ── P1: 自适应侦察编排 ──

    def run_adaptive(
        self,
        target_url: str,
        spa_config: Optional[str] = None,
        depth: str = "standard",
        tracker: Optional[Any] = None,
        credential_config: Optional[Dict[str, Dict[str, Any]]] = None,
        framework_id: Optional[str] = None,
        use_cache: Optional[bool] = None,
        verbose: bool = False,
    ) -> TargetProfile:
        """
        自适应侦察编排：自动选择 SPA 路径或 API 路径

        路径选择策略：
        - SPA 目标（有 spa_config 或 URL 含 /#/）：
            SPA Recon → 提取 LLM 端点 → NativeProbe + DeepTeam 并行 → 合并
        - API 目标（localhost / API 路径 / 已知端口）：
            AIMAP → NativeProbe + DeepTeam 并行 → 合并

        此方法封装了完整的自适应编排逻辑，使 PipelineOrchestrator
        只需调用此单一入口，无需关心内部路径选择细节。

        Args:
            target_url: 目标 URL
            spa_config: SPA 配置文件路径（可选）
            depth: 侦察深度 (quick/standard/deep)
            tracker: PipelineTracker 实例（可选）
            credential_config: 凭据注入配置（工具名 → 配置）
            framework_id: 安全框架 ID（如 owasp_2025）
            use_cache: 是否使用缓存
            verbose: 是否打印详细信息

        Returns:
            TargetProfile: 统一侦察画像
        """
        from ..core.utils import (
            detect_target_type,
            extract_spa_llm_endpoint,
            extract_spa_model_name,
            build_aimap_data_from_spa_profile,
        )

        target_type = detect_target_type(target_url, spa_config)
        logger.info("Adaptive recon: target_type=%s for %s", target_type, target_url)

        if target_type == "spa":
            return self._run_spa_adaptive(
                spa_config=spa_config,
                target_url=target_url,
                depth=depth,
                tracker=tracker,
                credential_config=credential_config or {},
                framework_id=framework_id,
                use_cache=use_cache,
                verbose=verbose,
            )
        else:
            return self._run_api_adaptive(
                target_url=target_url,
                depth=depth,
                tracker=tracker,
                credential_config=credential_config or {},
                use_cache=use_cache,
                verbose=verbose,
            )

    def _run_spa_adaptive(
        self,
        spa_config: Optional[str],
        target_url: str,
        depth: str,
        tracker: Optional[Any],
        credential_config: Dict[str, Dict[str, Any]],
        framework_id: Optional[str],
        use_cache: Optional[bool],
        verbose: bool,
    ) -> TargetProfile:
        """
        SPA 自适应路径：SPA Recon → 提取端点 → NativeProbe + DeepTeam 并行 → 合并

        流程：
        1. SPA Recon（浏览器自动化）：发现 LLM 端点 + 模型 + 凭据
        2. 从 SPA 结果提取 LLM API 端点和模型信息
        3. NativeProbe + DeepTeam 并行（使用 SPA 发现的端点）
        4. 合并所有结果到统一 TargetProfile
        """
        import concurrent.futures
        from ..core.utils import (
            extract_spa_llm_endpoint,
            extract_spa_model_name,
            build_aimap_data_from_spa_profile,
        )

        # ── 步骤 1：SPA Recon ──
        logger.info("SPA adaptive recon: starting browser automation")
        if verbose:
            print("  模式: SPA 智能助手侦察（浏览器自动化）")

        if spa_config:
            profile = self.run_spa_recon(
                spa_config_path=spa_config,
                tracker=tracker,
                use_cache=use_cache,
            )
        else:
            # 无 spa_config 但 URL 是 SPA — 直接用 URL 侦察
            import tempfile
            import yaml

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False, encoding="utf-8"
            ) as f:
                yaml.dump({"target": {"url": target_url, "auth_mode": "manual"}}, f)
                temp_path = f.name
            profile = self.run_spa_recon(
                spa_config_path=temp_path,
                tracker=tracker,
                use_cache=use_cache,
            )

        # ── 步骤 2：从 SPA 结果提取 LLM 端点 ──
        spa_endpoint = extract_spa_llm_endpoint(profile)
        spa_model = extract_spa_model_name(profile)

        # SPA 未发现端点时确保 surfaces 填充基础值
        if not spa_endpoint:
            logger.info("SPA adaptive: no LLM endpoint found, skipping probe/deepteam")
            if verbose:
                print("  SPA 未发现 LLM 端点，跳过 NativeProbe/DeepTeam 侦察")
            if hasattr(profile, 'surfaces') and not profile.surfaces:
                profile.surfaces = ["prompt"]
                logger.info("SPA profile surfaces defaulted to ['prompt']")
            if hasattr(profile, 'fingerprint') and profile.fingerprint:
                if not profile.fingerprint.capabilities:
                    profile.fingerprint.capabilities = ["chat"]
            return profile

        logger.info("SPA adaptive: LLM endpoint=%s, model=%s", spa_endpoint[:80], spa_model)
        if verbose:
            print(f"  SPA 发现 LLM 端点: {spa_endpoint[:80]}")
            if spa_model:
                print(f"  SPA 发现模型: {spa_model}")

        # ── 步骤 3：构建 aimap_data + 配置 ──
        spa_aimap_data = build_aimap_data_from_spa_profile(profile)

        probe_config = self._get_tool_config("native_probe")
        probe_config["depth"] = depth
        probe_config["model_name"] = spa_model or "gpt-4o"
        probe_config["aimap_data"] = spa_aimap_data
        if credential_config.get("native_probe"):
            probe_config.update(credential_config["native_probe"])

        deepteam_config = self._get_tool_config("deepteam")
        deepteam_config["depth"] = depth
        deepteam_config["model"] = spa_model or ""
        deepteam_config["aimap_data"] = spa_aimap_data
        if framework_id:
            deepteam_config["framework"] = framework_id
        if credential_config.get("deepteam"):
            deepteam_config.update(credential_config["deepteam"])

        # ── 步骤 4：NativeProbe + DeepTeam 并行 ──
        if verbose:
            print("  启动 NativeProbe + DeepTeam 侦察（使用 SPA 发现的端点）...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            probe_future = executor.submit(
                self._run_single_adapter, "native_probe", spa_endpoint, tracker, config=probe_config
            )
            deepteam_future = executor.submit(
                self._run_single_adapter, "deepteam", spa_endpoint, tracker, config=deepteam_config
            )
            probe_result = probe_future.result()
            deepteam_result = deepteam_future.result()

        # ── 步骤 5：合并结果 ──
        results = [r for r in [probe_result, deepteam_result] if r is not None]
        if results:
            merger = ProfileMerger()
            profile = merger.merge_incremental(
                target=target_url, existing_profile=profile,
                new_result=results[0], depth=depth,
            )
            if len(results) > 1:
                profile = merger.merge_incremental(
                    target=target_url, existing_profile=profile,
                    new_result=results[1], depth=depth,
                )

        return profile

    def _run_api_adaptive(
        self,
        target_url: str,
        depth: str,
        tracker: Optional[Any],
        credential_config: Dict[str, Dict[str, Any]],
        use_cache: Optional[bool],
        verbose: bool,
    ) -> TargetProfile:
        """
        API 自适应路径：AIMAP → NativeProbe + DeepTeam 并行 → 合并

        流程：
        1. 将凭据注入到工具配置中
        2. 调用标准 run() 方法执行 AIMAP + 并行适配器
        """
        if verbose:
            print(f"  模式: 标准 API 侦察（深度={depth}）")

        # 将凭据注入到工具配置中
        if credential_config:
            for tool_name, extra_config in credential_config.items():
                tool_config = self._get_tool_config(tool_name)
                tool_config.update(extra_config)

        profile = self.run(
            target=target_url,
            depth=depth,
            tracker=tracker,
            use_cache=use_cache,
        )

        return profile

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

                # 预检：工具未安装则直接跳过，不提交到线程池
                if not adapter.check_available():
                    logger.warning("%s not installed, skipping", tool)
                    results.append(AdapterResult(
                        tool=tool, success=False,
                        errors=[f"{tool} not installed"],
                    ))
                    if tracker:
                        tracker.log_recon_tool(
                            tool=tool, success=False,
                            findings_count=0, duration_ms=0,
                            error="not installed",
                        )
                    continue

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
