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

    engine = AI300Engine(config_path="config/catalog/catalog.yaml")
    results = engine.run()
    engine.generate_report(output_path="results/assessment_report.md")
"""

__version__ = "3.0.0"
__author__ = "AI-300 Framework Team"

import logging
from typing import Any, Optional

from .orchestrators import AttackOrchestrator, SmartMatcher, select_attack_strategy, PyRITAttack, AttackProbeFamily

logger = logging.getLogger(__name__)
from .reporting import ReportGenerator
from .payloads import PayloadManager, classify_payload, classify_payloads
from .pipeline import PipelineTracker

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
]


class AI300Engine:
    """
    AI-300 框架主引擎

    整合所有组件，提供统一的执行接口。

    使用方式：
        engine = AI300Engine()
        engine.load_config("config/catalog/catalog.yaml")
        results = engine.run()
        engine.generate_report()
    """

    # AI-300 Module 列表（对齐 catalog.yaml 中的模块键名）
    MODULES = [
        "single_agent", "multi_agent", "rag", "embeddings",
        "mcp", "supply_chain", "infrastructure",
    ]

    def __init__(
        self,
        config_path: str = None,
        target_config: str = "config/targets/ollama_local.yaml",
        tracker: Optional[Any] = None,
    ):
        """
        初始化 AI-300 引擎

        Args:
            config_path: 场景配置文件路径
            target_config: 目标配置文件路径
            tracker: 流水线追踪器（可选，默认自动创建）
        """
        self.config_path = config_path
        self.target_config = target_config
        self.orchestrator = None
        self.report_generator = None
        self._results = []
        self.tracker = tracker

    def load_config(self, config_path: str) -> None:
        """加载配置文件"""
        self.config_path = config_path
        # 自动创建追踪器（如果未提供）
        if self.tracker is None:
            from .pipeline import PipelineTracker
            self.tracker = PipelineTracker(verbose=True)
        self.orchestrator = AttackOrchestrator(config_path=config_path)

    def run(self, module: str = None) -> list:
        """
        执行攻击场景

        Args:
            module: 指定 Module 名称（可选，不指定则运行所有）

        Returns:
            攻击结果列表
        """
        if self.orchestrator is None:
            self.load_config(self.config_path)

        if module:
            self._results = [self._run_module(module)]
        else:
            self._results = self._run_all_modules()

        return self._results

    def _run_all_modules(self) -> list:
        """运行所有 AI-300 Module"""
        all_results = []
        for module in self.MODULES:
            try:
                result = self._run_module(module)
                all_results.append(result)
            except Exception as e:
                logger.error("Module %s failed: %s", module, str(e))
                all_results.append({
                    "module": module,
                    "status": "error",
                    "error": str(e),
                })
        return all_results

    def _run_module(self, module_name: str) -> dict:
        """
        运行指定 Module 的完整攻击场景
        """
        # 加载攻击目录配置
        attack_catalog = AttackOrchestrator.load_yaml(self.config_path)
        if not attack_catalog or "catalog" not in attack_catalog:
            raise ValueError(f"Attack catalog not found for module: {module_name}")

        module_config = attack_catalog["catalog"].get(module_name, {})

        # 构建攻击列表
        attacks = AttackOrchestrator.build_attack_list(module_config)

        # 加载目标配置
        target_cfg = AttackOrchestrator.load_yaml(self.target_config)

        # 追踪：模块开始
        if self.tracker and self.tracker.console:
            self.tracker.console.print()
            self.tracker.console.print(
                f"[bold cyan]═══ Module: {module_name} — {module_config.get('name', '')} ═══[/bold cyan]"
            )
            self.tracker.console.print(
                f"[dim]OWASP: {module_config.get('owasp', 'N/A')} | Attacks: {len(attacks)}[/dim]"
            )

        # 执行攻击链
        scenario_results = {
            "module": module_name,
            "module_name": module_config.get("name", module_name),
            "owasp_mapping": module_config.get("owasp", ""),
            "attacks": [],
            "summary": {
                "total_attacks": len(attacks),
                "total_payloads": 0,
                "successful_payloads": 0,
                "failed_payloads": 0,
            },
        }

        for attack in attacks:
            target = self.orchestrator.build_target(target_cfg)
            mode = attack.get("mode", "chain")

            # 追踪：攻击开始
            if self.tracker and self.tracker.console:
                attack_name = attack.get("name", "unnamed")
                self.tracker.console.print(
                    f"\n  [bold yellow]Attack:[/bold yellow] {attack_name} [dim](mode: {mode})[/dim]"
                )

            # 根据模式传递不同参数
            if mode == "smart_match":
                result = self.orchestrator.execute_attack(
                    attack_config=attack,
                    target=target,
                    converters=None,
                    scorers=self.orchestrator.build_scorers(attack.get("scorers", []), objective_target=target),
                    tracker=self.tracker,
                )
            elif mode == "presets":
                result = self.orchestrator.execute_attack(
                    attack_config=attack,
                    target=target,
                    converters=None,
                    scorers=self.orchestrator.build_scorers(attack.get("scorers", []), objective_target=target),
                )
            else:
                result = self.orchestrator.execute_attack(
                    attack_config=attack,
                    target=target,
                    converters=self.orchestrator.build_converters(attack.get("converters", [])),
                    scorers=self.orchestrator.build_scorers(attack.get("scorers", []), objective_target=target),
                )

            scenario_results["attacks"].append(result)
            scenario_results["summary"]["total_payloads"] += result.get("payloads_tested", result.get("total_executions", 0))
            scenario_results["summary"]["successful_payloads"] += result.get("success_count", 0)
            scenario_results["summary"]["failed_payloads"] += result.get("failure_count", 0)

        # 追踪：模块完成
        if self.tracker and self.tracker.console:
            success = scenario_results["summary"]["successful_payloads"]
            total = scenario_results["summary"]["total_payloads"]
            rate = (success / total * 100) if total > 0 else 0
            self.tracker.console.print()
            self.tracker.console.print(
                f"[bold green]Module Complete:[/bold green] {module_name} | "
                f"Payloads: {total} | Successful: {success} | Rate: {rate:.1f}%"
            )

        return scenario_results

    def generate_report(
        self,
        output_path: str = "results/ai300_assessment_report.md",
        format: str = "markdown",
    ) -> str:
        """
        生成评估报告

        Args:
            output_path: 输出文件路径
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
