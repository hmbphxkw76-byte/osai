# -*- coding: utf-8 -*-
"""
AI-300 Red Teaming Framework v3.0
==================================

基于 PyRIT 0.14.0 的 OffSec AI-300 (OSAI+) 考试全覆盖红队评估框架。

核心特性：
- Smart Match v3.0：payload 自动分类 → PyRIT 原生攻击策略选择
- 直接复用 PyRIT 0.14.0 原生攻击（Crescendo/TAP/PromptSending/Sequential）
- 完全对齐 OffSec AI-300 考试 11 个 Module
- 完整覆盖 OWASP Top 10 for LLM Applications + Agentic Top 10
- 数据驱动，攻击载荷修改后全流程自动化
- 自动生成符合 OffSec 标准的专业红队评估报告

架构改进（v3.0）：
- SmartMatcher：从"执行计划构建器"变为"PyRIT 攻击策略选择器"
- AttackOrchestrator：不再手动循环执行，全部使用 PyRIT 原生攻击
- 继承 PyRIT 全部能力：重试、渐进升级、自动回退、树搜索剪枝、早停

使用方式：
    from pyrit_ai300 import AI300Engine

    engine = AI300Engine()
    results = engine.run(scope="llm01")
    engine.generate_report(output_path="results/assessment_report.md")
"""

__version__ = "3.0.0"
__author__ = "AI-300 Framework Team"

import logging
from typing import Any, Dict, Optional

from .orchestrators import AttackOrchestrator, SmartMatcher, select_attack_strategy, PyRITAttack, AttackProbeFamily

logger = logging.getLogger(__name__)
from .reporting import ReportGenerator
from .payloads import PayloadManager, classify_payload, classify_payloads
from .pipeline import PipelineTracker
from .reconnaissance import ReconEngine, TargetProfile
from .attack import ProfileLoader

__all__ = [
    "AI300Engine",
    "AttackOrchestrator",
    "SmartMatcher",
    "select_attack_strategy",
    "PyRITAttack",
    "AttackProbeFamily",
    "ReportGenerator",
    "PayloadManager",
    "PipelineTracker",
    "classify_payload",
    "classify_payloads",
    "ReconEngine",
    "TargetProfile",
    "ProfileLoader",
]


class AI300Engine:
    """
    AI-300 框架主引擎

    整合所有组件，提供统一的执行接口。

    使用方式：
        engine = AI300Engine()
        results = engine.run(scope="llm01")
        engine.generate_report()
    """

    # OWASP Scope 定义
    OWASP_SCOPES = {
        "llm": ["llm01", "llm02", "llm03", "llm04", "llm05",
                "llm06", "llm07", "llm08", "llm09", "llm10"],
        "agentic": ["asi01", "asi02", "asi03", "asi04", "asi05",
                    "asi06", "asi07", "asi08", "asi09", "asi10"],
    }

    def __init__(
        self,
        config_path: str = None,
        target_config: str = "config/targets/ollama_local.yaml",
        tracker: Optional[Any] = None,
        profile_path: Optional[str] = None,
        target_url: Optional[str] = None,
        model: Optional[str] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
        scorer_url: Optional[str] = None,
        scorer_key: Optional[str] = None,
        scorer_model: Optional[str] = None,
    ):
        """
        初始化 AI-300 引擎

        Args:
            config_path: 场景配置文件路径
            target_config: 目标配置文件路径
            tracker: PipelineTracker 实例（可选，默认自动创建）
            profile_path: TargetProfile JSON 路径（可选，来自 recon 命令）
            target_url: 直接指定目标 URL（可选，跳过 YAML 配置）
            model: 覆盖目标模型名（可选，跳过 YAML config 中的 model）
            objective: 自定义攻击目标（可选，替换 payload 中的 {objective} 占位符）
            placeholders: 用户自定义占位符字典（可选，如 {"domain": "evil.com", "task": "whoami"}）
            scorer_url: 外部评分 LLM 端点 URL（可选，如 https://open.bigmodel.cn/api/paas/v4）
            scorer_key: 外部评分 LLM 的 API Key（可选）
            scorer_model: 外部评分 LLM 的模型名称（可选，如 glm-4-flash）
        """
        self.config_path = config_path
        self.target_config = target_config
        self.orchestrator = None
        self.report_generator = None
        self._results = []
        self.tracker = tracker
        self.profile_path = profile_path
        self._profile_params = None
        self._target_url = target_url
        self._model = model
        self._objective = objective
        self._placeholders = placeholders
        self._scorer_url = scorer_url
        self._scorer_key = scorer_key
        self._scorer_model = scorer_model

        # 加载 Profile（如果提供）
        if profile_path:
            from .attack import ProfileLoader
            self._profile_params = ProfileLoader.load(profile_path)
            logger.info("Loaded target profile from %s", profile_path)

            # 侦察驱动：用侦察发现的 endpoint 覆盖 target_config
            profile_endpoint = self._profile_params.get("target_endpoint")
            if profile_endpoint:
                self._target_url = profile_endpoint
                logger.info("Recon-driven target endpoint: %s", profile_endpoint)

            # 记录画像加载（tracker）
            if self.tracker and hasattr(self.tracker, 'log_profile_loaded'):
                self.tracker.log_profile_loaded(
                    profile_path=profile_path,
                    recommendations=self._profile_params.get("attack_recommendations", []),
                )

    def load_config(self, config_path: str) -> None:
        """加载配置文件"""
        self.config_path = config_path
        # 自动创建追踪器（如果未提供）
        if self.tracker is None:
            from .pipeline import PipelineTracker
            self.tracker = PipelineTracker(verbose=True)
        self.orchestrator = AttackOrchestrator(
            config_path=config_path,
            scorer_url=self._scorer_url,
            scorer_key=self._scorer_key,
            scorer_model=self._scorer_model,
        )

    def run(self, scope: str = "all") -> list:
        """
        执行 OWASP 标准攻击

        Args:
            scope: OWASP scope（默认 "all"）
                   单个 ID: "llm01", "asi01"
                   分组: "llm", "agentic"
                   全部: "all"

        Returns:
            攻击结果列表
        """
        if self.orchestrator is None:
            self.load_config(self.config_path)

        self._results = self._run_scope(scope)
        return self._results

    def _run_scope(self, scope: str) -> list:
        """执行指定 OWASP scope 的攻击"""
        # 解析 scope 为 ref 列表
        refs = self.orchestrator._payload_mgr.get_scope_refs(scope)

        if not refs:
            logger.warning("No payloads found for scope: %s", scope)
            return []

        # 加载目标配置（侦察驱动覆盖）
        target_cfg = self._build_target_config()
        target_endpoint = target_cfg.get("target", {}).get("connection", {}).get("endpoint", "N/A")

        # 追踪：scope 开始
        if self.tracker and self.tracker.console:
            self.tracker.console.print()
            self.tracker.console.print(
                f"[bold cyan]######## OWASP Scope: {scope} | Payloads: {len(refs)} ########[/bold cyan]"
            )

        # 构建攻击列表（从 OWASP refs）
        # 提取目标模型名（用于 SmartMatcher 策略选择）
        target_model_name = ""
        if target_cfg.get("target", {}).get("connection", {}).get("model"):
            target_model_name = target_cfg["target"]["connection"]["model"]
        elif self._profile_params:
            target_model_name = self._profile_params.get("target_model", "")

        if not target_model_name:
            logger.warning(
                "Target model name not found in config or profile. "
                "SmartMatcher will use default context_window=8192. "
                "Use --model <name> or check target config."
            )
        else:
            logger.info("Target model for SmartMatcher: %s", target_model_name)

        attacks = AttackOrchestrator.build_attack_list_from_refs(
            refs, self.orchestrator._payload_mgr, target_model=target_model_name,
        )

        # 执行攻击链
        # 对于单文件模式（ref_path），owasp_ids 提取 OWASP ID 部分（如 llm04）
        # 对于 ID 模式，owasp_ids 就是 scope 本身
        if scope.count(":") < 2:
            owasp_ids = [scope]
        else:
            owasp_ids = list(set(
                ref.split(":")[2] if len(ref.split(":")) > 2 else ref.split(":")[-1]
                for ref in refs
            ))
        scope_results = {
            "scope": scope,
            "owasp_ids": owasp_ids,
            "target_endpoint": target_endpoint,
            "attacks": [],
            "summary": {
                "total_attacks": len(attacks),
                "total_payloads": 0,
                "successful_payloads": 0,
                "failed_payloads": 0,
            },
        }

        try:
            for attack in attacks:
                target = self.orchestrator.build_target(target_cfg)
                mode = attack.get("mode", "chain")
                asi_category = attack.get("asi_category", "")

                # 追踪：攻击开始
                if self.tracker and self.tracker.console:
                    attack_name = attack.get("name", "unnamed")
                    self.tracker.console.print(
                        f"\n######## 攻击信息 ########\n  [bold yellow]Attack:[/bold yellow] {attack_name} [dim](mode: {mode})[/dim]"
                    )

                # 构建评分器（ASI 感知）
                scorers = self.orchestrator.build_scorers(
                    attack.get("scorers", []),
                    objective_target=target,
                    asi_category=asi_category,
                )

                # 根据模式传递不同参数
                if mode == "smart_match":
                    result = self.orchestrator.execute_attack(
                        attack_config=attack,
                        target=target,
                        converters=None,
                        scorers=scorers,
                        tracker=self.tracker,
                        profile_params=self._profile_params,
                        objective=self._objective,
                        placeholders=self._placeholders,
                    )
                elif mode == "presets":
                    result = self.orchestrator.execute_attack(
                        attack_config=attack,
                        target=target,
                        converters=None,
                        scorers=scorers,
                        tracker=self.tracker,
                        profile_params=self._profile_params,
                        objective=self._objective,
                        placeholders=self._placeholders,
                    )
                else:
                    result = self.orchestrator.execute_attack(
                        attack_config=attack,
                        target=target,
                        converters=self.orchestrator.build_converters(
                            attack.get("converters", []),
                            converter_target=target,
                        ),
                        scorers=scorers,
                        tracker=self.tracker,
                        profile_params=self._profile_params,
                        objective=self._objective,
                        placeholders=self._placeholders,
                    )

                scope_results["attacks"].append(result)
                scope_results["summary"]["total_payloads"] += result.get("payloads_tested", result.get("total_executions", 0))
                scope_results["summary"]["successful_payloads"] += result.get("success_count", 0)
                scope_results["summary"]["failed_payloads"] += result.get("failure_count", 0)

        finally:
            # 追踪：scope 完成
            if self.tracker and self.tracker.console:
                success = scope_results["summary"]["successful_payloads"]
                total = scope_results["summary"]["total_payloads"]
                rate = (success / total * 100) if total > 0 else 0
                self.tracker.console.print()
                self.tracker.console.print(
                    f"[bold green]######## Scope 完成: {scope} ########[/bold green]\n"
                    f"  Payloads: {total} | Successful: {success} | Rate: {rate:.1f}%"
                )

        return [scope_results]

    def _build_target_config(self) -> Dict[str, Any]:
        """
        构建目标配置（支持侦察驱动覆盖）

        优先级：
        1. --target-url CLI 参数（最高）
        2. 侦察画像中的 endpoint（profile_params）
        3. target_config.yaml 文件（默认）

        Returns:
            目标配置字典
        """
        # 加载基础配置
        target_cfg = AttackOrchestrator.load_yaml(self.target_config)

        # 侦察驱动：覆盖 endpoint 和 model
        if self._profile_params:
            profile_endpoint = self._profile_params.get("target_endpoint")
            profile_model = self._profile_params.get("target_model")
            if profile_endpoint or profile_model:
                if "target" not in target_cfg:
                    target_cfg["target"] = {}
                if "connection" not in target_cfg["target"]:
                    target_cfg["target"]["connection"] = {}
                if profile_endpoint:
                    target_cfg["target"]["connection"]["endpoint"] = profile_endpoint
                    logger.info("Recon-driven endpoint: %s", profile_endpoint)
                if profile_model:
                    target_cfg["target"]["connection"]["model"] = profile_model
                    logger.info("Recon-driven model: %s", profile_model)

        # CLI --target-url 最高优先级
        if self._target_url:
            if "target" not in target_cfg:
                target_cfg["target"] = {}
            if "connection" not in target_cfg["target"]:
                target_cfg["target"]["connection"] = {}
            target_cfg["target"]["connection"]["endpoint"] = self._target_url
            logger.info("CLI target-url override: %s", self._target_url)

        # CLI --model 覆盖模型名
        if self._model:
            if "target" not in target_cfg:
                target_cfg["target"] = {}
            if "connection" not in target_cfg["target"]:
                target_cfg["target"]["connection"] = {}
            target_cfg["target"]["connection"]["model"] = self._model
            logger.info("CLI model override: %s", self._model)

        return target_cfg

    def generate_report(
        self,
        output_path: Optional[str] = None,
        format: str = "markdown",
    ) -> str:
        """
        生成评估报告

        Args:
            output_path: 输出文件路径。为 None 时自动生成带时间戳的文件名。
            format: 输出格式

        Returns:
            报告内容
        """
        self.report_generator = ReportGenerator(results=self._results)
        return self.report_generator.generate(output_path=output_path, format=format)

    @property
    def results(self) -> list:
        """获取执行结果"""
        return self._results
