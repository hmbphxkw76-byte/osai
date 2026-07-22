# -*- coding: utf-8 -*-
"""
AI-300 Red Teaming Framework v3.7
==================================

基于 PyRIT 0.14.0 的 OffSec AI-300 (OSAI+) 考试全覆盖红队评估框架。

核心特性：
- Smart Match v3.5：payload 自动分类 → PyRIT 原生攻击策略选择 → 全链路优化
- 直接复用 PyRIT 0.14.0 原生攻击（Crescendo/TAP/PromptSending/Sequential）
- 完全对齐 OffSec AI-300 考试 11 个 Module
- 完整覆盖 OWASP Top 10 for LLM Applications + Agentic Top 10 + MITRE ATLAS
- 数据驱动，攻击载荷修改后全流程自动化
- 自动生成符合 OffSec 标准的专业红队评估报告（CVSS 3.1 + ATLAS + Mermaid）

架构改进（v3.7 - 全链路编排 + 凭据管理）：
- 侦察层：19 项优化（AIMAP/NativeProbe/DeepTeam + ProfileMerger + 交叉验证）
- 载荷层：
  * PayloadFilter (REV-1) → 基于攻击面过滤不相关 OWASP 类别
  * ASRRanker (REV-2) → 按目标模型 ASR 降序排序
  * ModelSpecificSelector (REV-3) → 模型家族特定载荷选择
- 评分层：
  * EnsembleScorer (REV-4) → 多评分器并行 + 三种投票策略
  * SemanticScorer (REV-5) → LLM 语义安全判定 + 关键词降级
- 报告层：
  * CVSSCalculator (REV-6) → CVSS 3.1 量化评分 + 向量字符串
  * ATLASMapper (REV-7) → MITRE ATLAS 全量战术/技术映射
  * AttackChainGenerator (REV-8) → Mermaid 攻击路径可视化
  * RemediationROI (REV-10) → 修复建议 ROI 排序
- 凭据层（v3.6 新增）：
  * CredentialManager → 跨阶段凭据发现/验证/注入
  * JWT 过期检查 + HTTP 预检验证
  * 凭据自动注入 NativeProbe/DeepTeam/PyRIT Target
- 编排层（v3.7 新增）：
  * PipelineOrchestrator → 认证→侦察→攻击→报告一键执行
  * 凭据优先复用 + 侦察驱动攻击 + 结果突出显示
  * CLI: ai300 pipeline --target-url ... --scope all

架构成熟度：L5（专家级）

使用方式：
    # 全链路一键执行
    from pyrit_ai300 import PipelineOrchestrator
    orchestrator = PipelineOrchestrator()
    result = orchestrator.run(target_url="http://target.com", scope="all")

    # 或分步执行
    from pyrit_ai300 import AI300Engine
    engine = AI300Engine()
    results = engine.run(scope="llm01")
    engine.generate_report(output_path="results/assessment_report.md")
"""

__version__ = "3.7.0"
__author__ = "AI-300 Framework Team"

# v3.1: 统一 UTF-8 设置（Windows 兼容），替代各模块中重复的 sys.stdout.reconfigure
from .utils.platform import setup_windows_utf8
setup_windows_utf8()

# v3.8: 自动加载 .env 文件（敏感配置通过环境变量注入，避免硬编码泄露）
from .utils.env_loader import load_dotenv, resolve_env_vars
load_dotenv()

# L5: 结构化日志初始化（JSON/TEXT 双模式，通过 AI300_LOG_FORMAT 环境变量切换）
from .utils.structured_log import setup_structured_logging
setup_structured_logging()

import logging
from typing import Any, Dict, List, Optional

from .attack import AttackOrchestrator, SmartMatcher, select_attack_strategy, PyRITAttack, AttackProbeFamily
from .attack.feedback import GeneticMutator
from .utils.pyrit_log_adapter import PyRITLogAdapter

logger = logging.getLogger(__name__)
from .reporting import ReportGenerator
from .payloads import PayloadManager, classify_payload, classify_payloads
from .pipeline import PipelineTracker, PipelineOrchestrator, PipelineResult
from .recon import ReconEngine, TargetProfile
from .attack import ProfileLoader
from .scenarios import ScenarioRunner, ScenarioResult

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
    "PipelineOrchestrator",
    "PipelineResult",
    "classify_payload",
    "classify_payloads",
    "ReconEngine",
    "TargetProfile",
    "ProfileLoader",
    # P2-12: Scenarios
    "ScenarioRunner",
    "ScenarioResult",
    # P1-3: Genetic Mutator
    "GeneticMutator",
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

    def __init__(
        self,
        config_path: str = None,
        target_config: str = "config/targets/llm_api_target.yaml",
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

        # L5: PyRIT 原生日志适配器
        self._log_adapter = PyRITLogAdapter(logger)

        # 加载 Profile（如果提供）
        if profile_path:
            from .attack import ProfileLoader
            self._profile_params = ProfileLoader.load(profile_path)
            logger.info("Loaded target profile from %s", profile_path)

            # 侦察驱动：用侦察发现的 endpoint 覆盖 target_config
            # 但不能覆盖 SPA 目标 — SPA 目标需要保持浏览器自动化模式
            # （PlaywrightTarget），不能切换为 LLM API 模式（OpenAIChatTarget）
            profile_endpoint = self._profile_params.get("target_endpoint")
            if profile_endpoint:
                from .core.utils import detect_target_type
                _original_type = detect_target_type(
                    self._target_url or "", None
                )
                if _original_type == "spa":
                    # SPA 目标：保持 SPA URL 不被 LLM endpoint 覆盖
                    logger.info(
                        "Recon found LLM endpoint '%s' but target is SPA, "
                        "keeping SPA URL: %s",
                        profile_endpoint, self._target_url,
                    )
                else:
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

        # 提取目标模型名（用于 SmartMatcher 策略选择）
        target_model_name = ""
        if target_cfg.get("target", {}).get("connection", {}).get("model"):
            target_model_name = target_cfg["target"]["connection"]["model"]
        elif self._profile_params:
            target_model_name = self._profile_params.get("target_model", "")

        # 追踪：scope 开始（PyRIT 原生日志格式）
        self._log_adapter.log_scope_start(
            scope, len(refs),
            target_endpoint=target_endpoint,
            target_model=target_model_name,
        )

        if not target_model_name:
            logger.warning(
                "Target model name not found in config or profile. "
                "SmartMatcher will use default context_window=8192. "
                "Use --model <name> or check target config."
            )
        else:
            logger.info("Target model for SmartMatcher: %s", target_model_name)

        # REV-1: 从侦察画像提取攻击面，用于载荷过滤
        surfaces = None
        if self._profile_params:
            surfaces = self._profile_params.get("surfaces", [])

        attacks = AttackOrchestrator.build_attack_list_from_refs(
            refs, self.orchestrator._payload_mgr,
            target_model=target_model_name,
            surfaces=surfaces,
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
                        f"\n[bold yellow]Attack:[/bold yellow] {attack_name} [dim](mode: {mode})[/dim]"
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
            # P0-1: 闭环反馈接线 — FeedbackAnalyzer → ASRUpdater → PayloadMutator
            self._run_feedback_loop(scope_results, target_model_name)

            # 追踪：scope 完成
            success = scope_results["summary"]["successful_payloads"]
            total = scope_results["summary"]["total_payloads"]
            self._log_adapter.log_scope_complete(
                scope, total, success, total - success,
                execution_time_ms=0,
            )

        return [scope_results]

    def _build_target_config(self) -> Dict[str, Any]:
        """
        构建目标配置（支持侦察驱动覆盖）

        优先级：
        1. --target-url CLI 参数（最高）
        2. 侦察画像中的 endpoint（profile_params）
        3. target_config.yaml 文件（默认）

        目标类型一致性保障：
        - SPA URL（含 #/、公网域名等）→ type=spa_chat, connection.url
        - API URL（localhost、已知端口等）→ type=ollama/openai, connection.endpoint
        - 侦察发现的 model 可安全覆盖（不影响目标类型）
        - 侦察发现的 endpoint 不覆盖 SPA 目标（保持 PlaywrightTarget）

        Returns:
            目标配置字典
        """
        # 加载基础配置
        target_cfg = AttackOrchestrator.load_yaml(self.target_config)

        # ── 极简格式归一化（先归一化，再覆盖，避免提前创建 connection 阻止归一化）──
        # 支持三种极简格式（无 target.connection 层，字段直接放在 target 下）：
        #   1. spa_target.yaml  → target.url 存在
        #   2. llm_api_target.yaml → target.endpoint 存在（ollama/openai）
        #   3. http_target.yaml  → target.http_request 存在（http）
        # 归一化为标准格式：target.connection + target.auth + target.selectors
        target_data = target_cfg.get("target", {})
        if "connection" not in target_data:
            if "url" in target_data:
                # ── 1. SPA 极简格式 ──
                auto = target_cfg.get("auto_detected", {})
                from urllib.parse import urlparse
                _parsed = urlparse(target_data["url"])
                _domain = _parsed.hostname or target_data["url"].split("/")[2]
                target_cfg["target"]["connection"] = {
                    "url": target_data["url"],
                    "browser": "chromium",
                    "headless": True,
                    "wait_until": "networkidle",
                    "ignore_https_errors": True,
                }
                target_cfg["target"]["type"] = "spa_chat"
                # 凭据文件路径：侦察后自动导出到 credentials/{domain}.txt
                target_cfg["target"]["auth"] = {
                    "mode": "header_file",
                    "header_file": f"config/targets/credentials/{_domain}.txt",
                }
                # 从 auto_detected 读取选择器
                if auto:
                    target_cfg["target"]["selectors"] = {
                        "input": auto.get("input", ""),
                        "send_button": auto.get("send_button", ""),
                        "response": auto.get("response", ""),
                    }
                logger.info("Normalized minimal spa_target.yaml format → standard format")

            elif "endpoint" in target_data:
                # ── 2. LLM API 极简格式（ollama/openai）──
                target_cfg["target"]["connection"] = {
                    "endpoint": target_data["endpoint"],
                    "model": target_data.get("model", ""),
                    "api_key": target_data.get("api_key", "not-needed"),
                }
                logger.info("Normalized minimal llm_api_target.yaml format → standard format")

            elif "http_request" in target_data:
                # ── 3. HTTP 极简格式 ──
                target_cfg["target"]["connection"] = {
                    "http_request": target_data["http_request"],
                    "use_tls": target_data.get("use_tls", True),
                }
                logger.info("Normalized minimal http_target.yaml format → standard format")

        # ── 侦察驱动覆盖（仅 model，不覆盖 endpoint 以保护 SPA 目标类型）──
        if self._profile_params:
            profile_model = self._profile_params.get("target_model")
            if profile_model:
                if "target" not in target_cfg:
                    target_cfg["target"] = {}
                if "connection" not in target_cfg["target"]:
                    target_cfg["target"]["connection"] = {}
                target_cfg["target"]["connection"]["model"] = profile_model
                logger.info("Recon-driven model: %s", profile_model)

        # ── CLI --target-url 最高优先级（根据类型设置正确的 type 和 connection）──
        if self._target_url:
            from .core.utils import detect_target_type
            _url_type = detect_target_type(self._target_url, None)

            if "target" not in target_cfg:
                target_cfg["target"] = {}
            if "connection" not in target_cfg["target"]:
                target_cfg["target"]["connection"] = {}

            if _url_type == "spa":
                # SPA 目标：设置 type=spa_chat 和 connection.url
                target_cfg["target"]["type"] = "spa_chat"
                target_cfg["target"]["connection"]["url"] = self._target_url
                _conn = target_cfg["target"]["connection"]
                _conn.setdefault("browser", "chromium")
                _conn.setdefault("headless", True)
                _conn.setdefault("wait_until", "networkidle")
                _conn.setdefault("ignore_https_errors", True)
                logger.info("CLI target-url (SPA): %s → type=spa_chat", self._target_url)
            else:
                # API 目标：设置 type=ollama（如未设置）和 connection.endpoint
                if "type" not in target_cfg["target"]:
                    target_cfg["target"]["type"] = "ollama"
                target_cfg["target"]["connection"]["endpoint"] = self._target_url
                logger.info(
                    "CLI target-url (API): %s → type=%s",
                    self._target_url, target_cfg["target"]["type"],
                )

        # ── CLI --model 覆盖模型名 ──
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

    # ──────────────────────────────────────────────────────────────────────────
    # P0-1: 闭环反馈接线
    # ──────────────────────────────────────────────────────────────────────────

    def _run_feedback_loop(
        self,
        scope_results: Dict[str, Any],
        target_model: str,
    ) -> None:
        """
        P0-1: 闭环反馈接线

        执行完整闭环：
        1. FeedbackAnalyzer 分析攻击结果 → 生成优化建议
        2. ASRUpdater 更新载荷 ASR 基线（贝叶斯平滑）
        3. PayloadMutator 从成功载荷生成变异体
        4. 将反馈建议应用到 profile_params（供下次执行使用）

        闭环设计原则：
        - 错误隔离：任何环节失败不中断主流程
        - 增量更新：ASR 更新基于贝叶斯平滑，不会突变
        - 离线友好：PayloadMutator 使用纯规则变异，无需 LLM
        """
        try:
            # ── 步骤 1: FeedbackAnalyzer 分析 ──
            from .pipeline.feedback_analyzer import FeedbackAnalyzer
            analyzer = FeedbackAnalyzer()
            report = analyzer.analyze([scope_results])

            if report.total_payloads == 0:
                logger.debug("Feedback loop skipped: no payloads executed")
                return

            logger.info(
                "P0-1 Feedback: %d attacks, %d payloads, %.1f%% success rate",
                report.total_attacks,
                report.total_payloads,
                report.success_rate * 100,
            )

            # 将反馈建议应用到 profile_params
            if self._profile_params:
                self._profile_params = analyzer.apply_to_profile_params(
                    report, self._profile_params,
                )
                logger.info(
                    "P0-1 Feedback applied: preferred_families=%s, aggression=%s",
                    report.recommended_families[:3],
                    report.recommended_aggression,
                )

            # ── 步骤 2: ASRUpdater 更新 ASR 基线 ──
            try:
                from .payloads.asr_updater import ASRUpdater
                updater = ASRUpdater(data_dir="data/owasp")
                update_stats = updater.update_from_feedback(
                    feedback_report=report,
                    target_model=target_model,
                )
                if update_stats.get("updated", 0) > 0:
                    logger.info(
                        "P0-1 ASR update: %d updated, %d skipped, %d errors",
                        update_stats["updated"],
                        update_stats["skipped"],
                        update_stats["errors"],
                    )
            except Exception as e:
                logger.warning("P0-1 ASR update failed (non-blocking): %s", e)

            # ── 步骤 3: PayloadMutator 生成变异体 ──
            if report.success_count > 0:
                try:
                    mutation_result = analyzer.generate_mutations(
                        [scope_results],
                        strategies=["paraphrase", "tone_shift"],
                        max_payloads=10,
                    )
                    if mutation_result and hasattr(mutation_result, "mutations") and mutation_result.mutations:
                        logger.info(
                            "P0-1 Mutator: %d variants generated from successful payloads",
                            len(mutation_result.mutations),
                        )
                except Exception as e:
                    logger.debug("P0-1 Mutator skipped: %s", e)

            # ── 步骤 4: P1-5 MCTS 载荷发现 ──
            # 使用成功载荷作为种子，通过 MCTS 探索新的载荷变异空间
            if report.success_count > 0:
                try:
                    self._run_mcts_discovery(scope_results, target_model)
                except Exception as e:
                    logger.debug("P1-5 MCTS discovery skipped: %s", e)

            # ── 步骤 5: P1-7 BatchScorer 交叉验证 ──
            # 使用不同评分器对攻击结果重新评分，检测主评分器偏差
            try:
                self._run_cross_validation(scope_results)
            except Exception as e:
                logger.debug("P1-7 Cross-validation skipped: %s", e)

        except Exception as e:
            logger.warning("P0-1 Feedback loop failed (non-blocking): %s", e)

    def _run_mcts_discovery(
        self,
        scope_results: Dict[str, Any],
        target_model: str,
    ) -> None:
        """
        P1-5: MCTS 载荷发现

        从攻击结果中提取成功载荷作为种子，使用 MCTS 探索变异空间，
        生成高 ASR 的载荷变体补充载荷库。

        设计原则：
        - 纯规则变异，无需 LLM
        - 基于 ASR 历史指导搜索方向
        - 错误隔离，不中断主流程
        """
        from .payloads.mcts_generator import MCTSGenerator

        # 提取成功载荷作为种子
        seed_payloads: List[str] = []
        for attack in scope_results.get("attacks", []):
            for r in attack.get("results", []):
                if r.get("status") == "success" and r.get("payload"):
                    seed_payloads.append(r["payload"])

        if not seed_payloads:
            return

        # 去重并限制种子数量
        seen = set()
        unique_seeds = []
        for p in seed_payloads:
            key = p[:80]
            if key not in seen:
                seen.add(key)
                unique_seeds.append(p)
        unique_seeds = unique_seeds[:5]  # 最多 5 个种子

        generator = MCTSGenerator(data_dir="data/owasp", max_depth=3, max_children=5)
        variants = generator.generate_variants(
            seed_payloads=unique_seeds,
            target_model=target_model,
            max_iterations=50,
            top_k=10,
        )

        if variants:
            logger.info(
                "P1-5 MCTS: %d variants discovered from %d seeds (top ASR=%.2f)",
                len(variants),
                len(unique_seeds),
                variants[0]["estimated_asr"],
            )

    def _run_cross_validation(
        self,
        scope_results: Dict[str, Any],
    ) -> None:
        """
        P1-7: BatchScorer 交叉验证

        使用不同类型的评分器对攻击结果重新评分，
        检测主评分器与交叉验证评分器之间的不一致，
        生成置信度报告。

        设计原则：
        - 使用 PyRIT BatchScorer（批量评分工具）
        - 错误隔离，不中断主流程
        - 结果写入 scope_results 供报告使用
        """
        from .attack.feedback.batch_cross_validator import BatchCrossValidator

        # 从攻击结果中提取主评分器类型和 ASI 类别
        for attack in scope_results.get("attacks", []):
            asi_category = attack.get("asi_category", "")
            if not asi_category:
                continue

            # 从攻击配置中推断主评分器类型
            scorer_configs = attack.get("scorers", [])
            primary_scorer_type = "refusal"  # 默认
            if scorer_configs and isinstance(scorer_configs[0], dict):
                primary_scorer_type = scorer_configs[0].get("name", "refusal")

            # 使用 AttackOrchestrator 的 ScorerBuilder
            scorer_builder = None
            if self.orchestrator:
                scorer_builder = self.orchestrator._scorer_builder

            validator = BatchCrossValidator(scorer_builder=scorer_builder)
            report = validator.validate(
                primary_scorer_type=primary_scorer_type,
                asi_category=asi_category,
            )

            if report.total_scored > 0:
                logger.info(
                    "P1-7 Cross-validation for %s: %s vs %s — confidence=%.0f%%",
                    asi_category,
                    report.primary_scorer_type,
                    report.cross_scorer_type,
                    report.confidence * 100,
                )
                # 将交叉验证结果写入攻击结果
                attack["cross_validation"] = {
                    "primary_scorer": report.primary_scorer_type,
                    "cross_scorer": report.cross_scorer_type,
                    "confidence": report.confidence,
                    "disagreement_rate": report.disagreement_rate,
                    "total_scored": report.total_scored,
                }
