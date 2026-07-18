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
    ProtocolFingerprintAdapter,
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
        "protocol_fingerprint": ProtocolFingerprintAdapter,
    }

    def __init__(self, config_path: str = "config/recon/recon.yaml"):
        """
        Args:
            config_path: 侦察配置文件路径
        """
        self.config = self._load_config(config_path)
        # 加载 Garak 外部模型独立配置（config/recon/garak.yaml）
        self._garak_config = self._load_garak_config()
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
        执行完整侦察流程（AIMAP → Garak 顺序侦察）

        流程：
        1. 先执行 AIMAP（protocol_fingerprint）协议识别
        2. 从 AIMAP 结果提取 Garak 可探测端点
        3. 用检测结果配置 Garak（model_type/model_name/endpoint）
        4. 执行剩余工具（Garak + DeepTeam）
        5. 合并所有结果

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

        # ── AIMAP 优先执行 → 配置 Garak ──
        aimap_result = None
        garak_target = target
        garak_config_override = None

        if "protocol_fingerprint" in tools_to_run:
            aimap_start = time.time()
            aimap_result = self._run_single_adapter("protocol_fingerprint", target, tracker)
            aimap_duration = (time.time() - aimap_start) * 1000

            # 记录 AIMAP 结果
            if tracker:
                tracker.log_recon_tool(
                    tool="protocol_fingerprint",
                    success=aimap_result.success if aimap_result else False,
                    findings_count=len(aimap_result.findings) if aimap_result else 0,
                    duration_ms=aimap_duration,
                    error=aimap_result.errors[0] if aimap_result and aimap_result.errors else "",
                )

            # 从 AIMAP 结果提取 Garak 端点
            if aimap_result and aimap_result.success and "garak" in tools_to_run:
                garak_endpoints = self.extract_garak_endpoints(aimap_result)
                if garak_endpoints:
                    # 使用第一个检测到的端点配置 Garak
                    selected_ep = garak_endpoints[0]
                    garak_target = selected_ep["url"]
                    garak_config_override = {
                        "model_type": selected_ep["model_type"],
                        "model_name": selected_ep["model_name"],
                    }
                    logger.info(
                        "AIMAP→Garak: using detected endpoint %s (type=%s, model=%s)",
                        garak_target, selected_ep["model_type"], selected_ep["model_name"],
                    )

                    # 记录 AIMAP→Garak 桥接（tracker）
                    if tracker:
                        tracker.log_recon_aimap_garak_bridge(
                            aimap_protocols=aimap_result.data.get("detected_protocols", []),
                            garak_endpoint=garak_target,
                            garak_model_type=selected_ep["model_type"],
                            garak_model_name=selected_ep["model_name"],
                        )

        # ── 执行剩余工具（Garak + DeepTeam，排除已执行的 AIMAP） ──
        remaining_tools = [t for t in tools_to_run if t != "protocol_fingerprint"]
        results = []
        if aimap_result:
            results.append(aimap_result)

        if remaining_tools:
            # 如果有 Garak 配置覆盖，临时修改配置
            if garak_config_override and "garak" in remaining_tools:
                garak_config = self._get_tool_config("garak")
                garak_config.update(garak_config_override)
                # 使用 AIMAP 检测到的端点作为 Garak 目标
                garak_result = self._run_single_adapter("garak", garak_target, tracker, config=garak_config)
                results.append(garak_result)
                remaining_tools = [t for t in remaining_tools if t != "garak"]

            # 执行剩余工具（DeepTeam 等）
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
                    # 从原始结果中提取各工具的 severity
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
        流式侦察：AIMAP 优先 → Garak 配置 → 剩余工具流式执行

        用于 --auto-recon 模式：AIMAP 先执行识别协议，配置 Garak 后
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

        # ── AIMAP 优先执行 → 配置 Garak ──
        aimap_result = None
        garak_target = target
        garak_config_override = None

        if "protocol_fingerprint" in tools_to_run:
            aimap_result = self._run_single_adapter("protocol_fingerprint", target, tracker)

            # 从 AIMAP 结果提取 Garak 端点
            if aimap_result and aimap_result.success and "garak" in tools_to_run:
                garak_endpoints = self.extract_garak_endpoints(aimap_result)
                if garak_endpoints:
                    selected_ep = garak_endpoints[0]
                    garak_target = selected_ep["url"]
                    garak_config_override = {
                        "model_type": selected_ep["model_type"],
                        "model_name": selected_ep["model_name"],
                    }
                    logger.info(
                        "AIMAP→Garak (streaming): using detected endpoint %s", garak_target,
                    )

                    if tracker:
                        tracker.log_recon_aimap_garak_bridge(
                            aimap_protocols=aimap_result.data.get("detected_protocols", []),
                            garak_endpoint=garak_target,
                            garak_model_type=selected_ep["model_type"],
                            garak_model_name=selected_ep["model_name"],
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

                    # Garak 使用 AIMAP 检测到的端点和配置
                    if tool == "garak" and garak_config_override:
                        garak_config = self._get_tool_config("garak")
                        garak_config.update(garak_config_override)
                        future = executor.submit(adapter.run, garak_target, garak_config)
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

    def _run_single_adapter(
        self,
        tool: str,
        target: str,
        tracker: Optional[Any] = None,
        config: Optional[dict] = None,
    ) -> AdapterResult:
        """
        执行单个适配器（内部方法，含 tracker 记录）

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

        return result

    @staticmethod
    def extract_garak_endpoints(aimap_result: AdapterResult) -> List[Dict[str, Any]]:
        """
        从 AIMAP 协议识别结果提取 Garak 可探测的端点

        Args:
            aimap_result: AIMAP 适配器的返回结果

        Returns:
            端点列表，每个端点包含：
            - url: 完整 endpoint URL
            - protocol: 检测到的协议
            - model_type: Garak 模型类型 (ollama/openai/...)
            - model_name: 模型名称
            - label: 显示标签
        """
        if not aimap_result or not aimap_result.success:
            return []

        data = aimap_result.data
        protocols = data.get("detected_protocols", [])
        entry_points = data.get("entry_points", [])
        model_name = data.get("model_name") or ""
        provider = data.get("provider") or ""

        # 协议 → Garak model_type 映射
        protocol_to_model_type = {
            "ollama": "ollama",
            "vllm": "openai",
            "openai_compatible": "openai",
            "openwebui": "openai",
            "langserve": "openai",
            "gradio": "openai",
            "streamlit": "openai",
            "tgi": "openai",
            "mcp": "openai",
        }

        endpoints = []
        for ep in entry_points:
            url = ep.get("url", "")
            protocol = ep.get("protocol", "")
            if not url:
                continue

            mtype = protocol_to_model_type.get(protocol, "openai")
            mname = model_name or ("llama3.2" if mtype == "ollama" else "gpt-4o")

            # 构建显示标签
            label = f"{protocol}"
            if mname:
                label += f" ({mname})"
            label += f" → {url}"

            endpoints.append({
                "url": url,
                "protocol": protocol,
                "model_type": mtype,
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

    def _load_garak_config(self) -> dict:
        """
        加载 Garak 外部模型独立配置（config/recon/garak.yaml）

        Returns:
            garak 配置字典，文件不存在返回空
        """
        try:
            import yaml
            garak_path = Path("config/recon/garak.yaml")
            if not garak_path.exists():
                logger.debug("Garak config not found: %s, using defaults", garak_path)
                return {}
            with open(garak_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            logger.info("Loaded Garak config from %s", garak_path)
            return config
        except Exception as e:
            logger.warning("Failed to load Garak config: %s", str(e))
            return {}

    @staticmethod
    def load_target(target_file: str) -> str:
        """
        从 config/targets/ 目录加载目标 URL

        Args:
            target_file: 目标配置文件路径（如 config/targets/custom_model_endpoint.yaml）

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
        """获取工具配置（Garak 合并独立配置文件）"""
        base = self.config.get("tools", {}).get(tool, {})
        if tool == "garak":
            # 合并 config/recon/garak.yaml 的外部模型配置
            # 优先级：recon.yaml > garak.yaml > 默认值
            merged = dict(self._garak_config)
            merged.update({k: v for k, v in base.items() if k not in ("enabled", "timeout")})
            merged["enabled"] = base.get("enabled", True)
            merged["timeout"] = base.get("timeout", 300)
            return merged
        return base

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
