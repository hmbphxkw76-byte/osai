# -*- coding: utf-8 -*-
"""
AI-300 Framework - Pipeline Orchestrator v1.0
全链路编排器：认证 → 侦察 → 攻击 → 报告

核心职责：
1. 凭据检查：从 credentials/ 目录发现并验证已有凭据（JWT 过期检查）
2. 侦察阶段：AIMAP / Garak / DeepTeam 并行执行，凭据自动注入
3. 攻击阶段：PyRIT 攻击，凭据自动注入到 OpenAI/HTTP/Playwright Target
4. 报告生成：CVSS 3.1 + ATLAS + Mermaid + ROI 完整报告

设计原则（最佳实践）：
- 凭据优先复用：有效凭据直接使用，避免重复登录
- 侦察驱动攻击：侦察画像自动驱动 REV-1 载荷过滤 + REV-2 ASR 排序
- 结果突出显示：每个阶段的关键指标用 Rich 格式清晰展示
- 错误隔离：单个阶段失败可配置为跳过或终止
- L5 质量：完整类型注解、docstring、日志、错误处理

使用方式：
    orchestrator = PipelineOrchestrator()
    result = orchestrator.run(
        target_url="https://www.example.com/#/home",
        scope="llm01",
        depth="standard",
    )

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .credential_manager import CredentialManager, CredentialResolution

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# Rich 格式化（可选依赖）
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ── 阶段常量 & 协议类型（从 core.protocols 导入，保持后向兼容）──
from ..core.protocols import (
    PHASE_CREDENTIAL as PHASE_CREDENTIAL,
    PHASE_RECON as PHASE_RECON,
    PHASE_ATTACK as PHASE_ATTACK,
    PHASE_REPORT as PHASE_REPORT,
    ALL_PHASES as ALL_PHASES,
    StageInput as StageInput,
    StageOutput as StageOutput,
    PipelineResult as PipelineResult,
)

# 后向兼容别名：PhaseResult = StageOutput
PhaseResult = StageOutput


class PipelineOrchestrator:
    """
    AI Red Team 全链路编排器

    编排完整的 AI 红队评估流水线：
    凭据检查 → 侦察（AIMAP/Garak/DeepTeam）→ 攻击（PyRIT）→ 报告

    最佳实践策略：
    1. 凭据优先复用：从 credentials/ 目录读取已有凭据，JWT 有效则直接使用
    2. 凭据自动注入：Garak（环境变量）/ DeepTeam（请求头）/ PyRIT（api_key）
    3. 侦察驱动攻击：侦察画像自动驱动载荷过滤 + ASR 排序
    4. 结果突出显示：每个阶段的关键指标用 Rich 格式清晰展示

    使用方式：
        orchestrator = PipelineOrchestrator()
        result = orchestrator.run(
            target_url="https://www.example.com/#/home",
            scope="llm01",
            depth="standard",
        )
        print(result.summary_table())

    高级用法（指定阶段执行）：
        result = orchestrator.run(
            target_url="http://localhost:11434",
            scope="all",
            phases=["recon", "attack"],  # 跳过凭据检查
        )
    """

    def __init__(
        self,
        credentials_dir: str = "config/targets/credentials",
        recon_config: str = "config/recon/recon.yaml",
        verbose: bool = True,
    ):
        """
        Args:
            credentials_dir: 凭据目录路径
            recon_config: 侦察配置文件路径
            verbose: 是否输出详细日志
        """
        self.credential_manager = CredentialManager(credentials_dir)
        self.recon_config = recon_config
        self.verbose = verbose
        self._console = Console() if (HAS_RICH and verbose) else None

    def run(
        self,
        target_url: Optional[str] = None,
        target_file: Optional[str] = None,
        spa_config: Optional[str] = None,
        scope: str = "llm01",
        depth: str = "standard",
        phases: Optional[List[str]] = None,
        output: Optional[str] = None,
        format: str = "markdown",
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
        model: Optional[str] = None,
        scorer_url: Optional[str] = None,
        scorer_key: Optional[str] = None,
        scorer_model: Optional[str] = None,
        skip_recon: bool = False,
        profile_path: Optional[str] = None,
        use_cache: Optional[bool] = None,
        framework_id: Optional[str] = None,
        enable_human_review: bool = False,
    ) -> PipelineResult:
        """
        执行全链路 AI 红队评估

        Args:
            target_url: 目标 URL（如 https://student.syxy.ouchn.cn/#/home）
            target_file: 目标配置文件路径（如 config/targets/llm_api_target.yaml）
            spa_config: SPA 配置文件路径（如 config/targets/spa_target.yaml）
            scope: OWASP 攻击范围（如 llm01 / llm / all）
            depth: 侦察深度（quick/standard/deep）
            phases: 指定执行阶段（None=全部）
            output: 报告输出路径
            format: 报告格式（markdown/html）
            objective: 攻击目标（替换 {goal} 占位符）
            placeholders: 自定义占位符字典
            model: 覆盖目标模型名
            scorer_url: 外部评分 LLM 端点
            scorer_key: 外部评分 LLM API Key
            scorer_model: 外部评分 LLM 模型名
            skip_recon: 跳过侦察阶段（使用已有 profile_path）
            profile_path: 已有侦察画像路径（跳过侦察时使用）
            use_cache: 是否使用侦察缓存（None=使用配置文件设置，True=启用，False=禁用）

        Returns:
            PipelineResult 全链路执行结果
        """
        start_time = time.time()
        result = PipelineResult()

        # P2: 存储框架 ID 供侦察/报告阶段使用
        self._framework_id = framework_id or ""
        # Phase 4.3: 人工审查开关
        self._enable_human_review = enable_human_review

        # 确定目标
        resolved_target = self._resolve_target(target_url, target_file, spa_config)
        result.target = resolved_target

        # 确定执行阶段
        active_phases = phases or ALL_PHASES
        if skip_recon and PHASE_RECON in active_phases:
            active_phases = [p for p in active_phases if p != PHASE_RECON]

        self._print_header(resolved_target, scope, depth, active_phases)

        # ── 阶段 1：凭据检查 ──
        if PHASE_CREDENTIAL in active_phases:
            phase_result = self._run_credential_phase(resolved_target)
            result.phases.append(phase_result)
            result.credential_resolution = phase_result.data.get("resolution")

            # 凭据失败不阻塞流程（无凭据的目标可直接侦察）
            if not phase_result.success:
                logger.warning("Credential phase failed, continuing without credentials")

        # ── 阶段 2：侦察 ──
        if PHASE_RECON in active_phases:
            phase_result = self._run_recon_phase(
                target_url=resolved_target,
                target_file=target_file,
                spa_config=spa_config,
                depth=depth,
                credential_resolution=result.credential_resolution,
                use_cache=use_cache,
            )
            result.phases.append(phase_result)
            if phase_result.success:
                result.profile_path = phase_result.data.get("profile_path", "")
            elif not phase_result.success and phase_result.errors:
                logger.error("Recon phase failed: %s", phase_result.errors[0])

        elif profile_path:
            # 跳过侦察但使用已有画像
            result.profile_path = profile_path
            logger.info("Using existing profile: %s", profile_path)

        # ── 阶段 3：攻击 ──
        if PHASE_ATTACK in active_phases:
            phase_result = self._run_attack_phase(
                target_url=resolved_target,
                target_file=target_file,
                spa_config=spa_config,
                scope=scope,
                profile_path=result.profile_path,
                credential_resolution=result.credential_resolution,
                objective=objective,
                placeholders=placeholders,
                model=model,
                scorer_url=scorer_url,
                scorer_key=scorer_key,
                scorer_model=scorer_model,
            )
            result.phases.append(phase_result)

        # ── Phase 4.3: 人工审查（可选）──
        if self._enable_human_review and PHASE_ATTACK in active_phases:
            self._run_human_review_phase(result)

        # ── 阶段 4：报告 ──
        if PHASE_REPORT in active_phases:
            # BUG-FIX: 设置 _current_result 供报告阶段收集攻击结果
            self._current_result = result
            phase_result = self._run_report_phase(
                output=output,
                format=format,
                target_url=resolved_target,
            )
            result.phases.append(phase_result)
            if phase_result.success:
                result.report_path = phase_result.data.get("report_path", "")

        # 汇总
        result.total_duration_ms = (time.time() - start_time) * 1000
        result.overall_success = all(p.success for p in result.phases) if result.phases else False

        self._print_summary(result)
        return result

    # ── 阶段实现 ──

    def _run_credential_phase(self, target_url: str) -> PhaseResult:
        """
        阶段 1：凭据检查

        最佳实践：
        - 从 credentials/ 目录按域名匹配凭据文件
        - 检查 JWT 过期时间（预留 5 分钟缓冲）
        - 有效凭据直接复用，过期/缺失返回空（不阻塞流程）
        """
        start = time.time()
        self._print_phase_start("🔐 凭据检查", target_url)

        try:
            resolution = self.credential_manager.resolve(target_url)

            # 打印凭据状态
            self.credential_manager.print_status(resolution)

            duration_ms = (time.time() - start) * 1000
            summary = resolution.summary() if resolution.profile else "no_credentials"

            self._print_phase_complete("凭据检查", duration_ms, resolution.has_credentials)

            return PhaseResult(
                phase=PHASE_CREDENTIAL,
                success=True,  # 凭据检查本身总是"成功"的（即使无凭据）
                duration_ms=duration_ms,
                summary=summary,
                data={"resolution": resolution},
            )

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error("Credential phase error: %s", str(e), exc_info=True)
            return PhaseResult(
                phase=PHASE_CREDENTIAL,
                success=False,
                duration_ms=duration_ms,
                errors=[str(e)],
                summary=f"error: {e}",
            )

    def _run_recon_phase(
        self,
        target_url: str,
        target_file: Optional[str],
        spa_config: Optional[str],
        depth: str,
        credential_resolution: Optional[CredentialResolution],
        use_cache: Optional[bool] = None,
    ) -> PhaseResult:
        """
        阶段 2：侦察（自适应编排 v2）

        委托到 ReconEngine.run_adaptive()，由引擎内部自动选择
        SPA 路径或 API 路径，编排器仅负责凭据注入、结果保存和日志输出。
        """
        start = time.time()
        self._print_phase_start("🔍 侦察", target_url)

        try:
            from ..recon import ReconEngine
            from .tracker import PipelineTracker

            tracker = PipelineTracker(verbose=self.verbose)
            engine = ReconEngine(config_path=self.recon_config)

            # 构建侦察配置（注入凭据）
            recon_config_extra = self._inject_credentials_to_config(credential_resolution)

            # 获取框架 ID
            framework_id = getattr(self, '_framework_id', None)

            # ── 委托到 ReconEngine.run_adaptive() ──
            profile = engine.run_adaptive(
                target_url=target_url,
                spa_config=spa_config,
                depth=depth,
                tracker=tracker,
                credential_config=recon_config_extra,
                framework_id=framework_id,
                use_cache=use_cache,
                verbose=self.verbose,
            )

            # 检测目标类型用于结果摘要
            from ..core.utils import detect_target_type
            target_type = detect_target_type(target_url, spa_config)

            # 保存画像
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            profile_path = f"results/recon/pipeline_profile_{timestamp}.json"
            profile.save(profile_path)

            if tracker.recon_log:
                tracker.recon_log.profile_path = profile_path

            duration_ms = (time.time() - start) * 1000

            # 摘要信息
            owasp_mappings = profile.get_owasp_mappings() if hasattr(profile, 'get_owasp_mappings') else []
            summary = (
                f"漏洞={profile.vulnerability_count}, "
                f"风险={profile.risk_level}, "
                f"OWASP={','.join(owasp_mappings[:5])}"
            )

            self._print_recon_results(profile, profile_path)
            self._print_phase_complete("侦察", duration_ms, True)

            return PhaseResult(
                phase=PHASE_RECON,
                success=True,
                duration_ms=duration_ms,
                summary=summary,
                data={
                    "profile_path": profile_path,
                    "vulnerability_count": profile.vulnerability_count,
                    "risk_level": profile.risk_level,
                    "owasp_mappings": owasp_mappings,
                    "target_type": target_type,
                },
            )

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error("Recon phase error: %s", str(e), exc_info=True)
            self._print_phase_error("侦察", e)
            return PhaseResult(
                phase=PHASE_RECON,
                success=False,
                duration_ms=duration_ms,
                errors=[str(e)],
                summary=f"error: {e}",
            )

    @staticmethod
    def _detect_target_type(
        target_url: str,
        spa_config: Optional[str],
    ) -> str:
        """自动检测目标类型（委托到 core.utils，保持后向兼容）"""
        from ..core.utils import detect_target_type
        return detect_target_type(target_url, spa_config)

    @staticmethod
    def _extract_spa_llm_endpoint(profile: Any) -> Optional[str]:
        """从 SPA 侦察画像中提取 LLM API 端点（委托到 core.utils）"""
        from ..core.utils import extract_spa_llm_endpoint
        return extract_spa_llm_endpoint(profile)

    @staticmethod
    def _extract_spa_model_name(profile: Any) -> Optional[str]:
        """从 SPA 侦察画像中提取模型名称（委托到 core.utils）"""
        from ..core.utils import extract_spa_model_name
        return extract_spa_model_name(profile)

    @staticmethod
    def _build_aimap_data_from_spa_profile(profile: Any) -> Dict[str, Any]:
        """从 SPA 侦察画像构建等价 aimap_data（委托到 core.utils）"""
        from ..core.utils import build_aimap_data_from_spa_profile
        return build_aimap_data_from_spa_profile(profile)

    def _run_attack_phase(
        self,
        target_url: str,
        target_file: Optional[str],
        scope: str,
        profile_path: Optional[str],
        credential_resolution: Optional[CredentialResolution],
        objective: Optional[str],
        placeholders: Optional[Dict[str, str]],
        model: Optional[str],
        scorer_url: Optional[str],
        scorer_key: Optional[str],
        scorer_model: Optional[str],
        spa_config: Optional[str] = None,
    ) -> PhaseResult:
        """
        阶段 3：攻击

        最佳实践：
        - 侦察画像驱动：REV-1 载荷过滤 + REV-2 ASR 排序
        - 凭据注入：有效凭据注入到 OpenAIChatTarget（api_key）或 HTTPTarget（Authorization 头）
        - PyRIT 原生攻击策略：Smart Match / Crescendo / TAP / Sequential
        - 目标类型一致性：SPA 目标始终使用 spa_chat 类型，不回退到 LLM API 配置

        修复 bug：之前 target_file 为 None 时默认使用 llm_api_target.yaml，
        导致 SPA 目标被当作 LLM API 处理（Model: llama3.2:latest, Endpoint: localhost:11434）
        """
        start = time.time()
        self._print_phase_start("⚔️ 攻击", f"{target_url} | scope={scope}")

        try:
            from .. import AI300Engine
            from .tracker import PipelineTracker

            tracker = PipelineTracker(verbose=self.verbose)

            # 根据目标类型选择正确的配置文件
            # SPA 目标 → spa_config 或 spa_target.yaml（使用 PlaywrightTarget）
            # API 目标 → target_file 或 llm_api_target.yaml（使用 OpenAIChatTarget）
            target_type = self._detect_target_type(target_url, spa_config)
            if target_type == "spa":
                target_cfg = spa_config or "config/targets/spa_target.yaml"
                logger.info("Attack phase: SPA target detected, using config: %s", target_cfg)
            else:
                target_cfg = target_file or "config/targets/llm_api_target.yaml"
                logger.info("Attack phase: API target detected, using config: %s", target_cfg)

            engine = AI300Engine(
                target_config=target_cfg,
                tracker=tracker,
                profile_path=profile_path,
                target_url=target_url,
                model=model,
                objective=objective,
                placeholders=placeholders,
                scorer_url=scorer_url,
                scorer_key=scorer_key,
                scorer_model=scorer_model,
            )

            # ── 凭据注入到攻击目标 ──
            if credential_resolution and credential_resolution.has_credentials:
                self._inject_credentials_to_attack(credential_resolution, engine)

            # 执行攻击
            results = engine.run(scope=scope)

            duration_ms = (time.time() - start) * 1000

            # 汇总攻击结果
            total_payloads = 0
            successful = 0
            failed = 0
            all_pyrit_attack_results = []
            for result_item in results:
                summary_data = result_item.get("summary", {})
                total_payloads += summary_data.get("total_payloads", 0)
                successful += summary_data.get("successful_payloads", 0)
                failed += summary_data.get("failed_payloads", 0)
                # REV-16: 收集 PyRIT 原生 AttackResult 对象
                pyrit_results = result_item.get("pyrit_attack_results", [])
                if pyrit_results:
                    all_pyrit_attack_results.extend(pyrit_results)

            success_rate = (successful / total_payloads * 100) if total_payloads > 0 else 0
            summary = f"载荷={total_payloads}, 成功={successful} ({success_rate:.0f}%), 失败={failed}"

            # REV-16: 使用 PyRIT 原生 output 模块渲染详细攻击结果
            self._print_attack_results_native(
                total_payloads, successful, failed, success_rate,
                all_pyrit_attack_results, scope,
            )
            self._print_phase_complete("攻击", duration_ms, True)

            # 保存原始结果到 data
            return PhaseResult(
                phase=PHASE_ATTACK,
                success=True,
                duration_ms=duration_ms,
                summary=summary,
                data={
                    "total_payloads": total_payloads,
                    "successful": successful,
                    "failed": failed,
                    "success_rate": success_rate,
                    "scope": scope,
                    "results": results,
                    # REV-16: 保留 AttackResult 供报告阶段使用
                    "pyrit_attack_results": all_pyrit_attack_results,
                },
            )

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error("Attack phase error: %s", str(e), exc_info=True)
            self._print_phase_error("攻击", e)
            return PhaseResult(
                phase=PHASE_ATTACK,
                success=False,
                duration_ms=duration_ms,
                errors=[str(e)],
                summary=f"error: {e}",
            )

    def _run_report_phase(
        self,
        output: Optional[str],
        format: str,
        target_url: str,
    ) -> PhaseResult:
        """
        阶段 4：报告生成

        生成包含 CVSS 3.1 + ATLAS + Mermaid + ROI 的完整评估报告。
        """
        start = time.time()
        self._print_phase_start("📄 报告生成", format)

        try:
            from ..reporting import ReportGenerator

            # 确定输出路径
            if not output:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                ext = "html" if format == "html" else "md"
                output = f"results/pipeline_report_{timestamp}.{ext}"

            # 收集攻击结果（从 PipelineResult 中提取攻击阶段数据）
            attack_data = None
            pyrit_attack_results = []
            _pipeline_result = getattr(self, '_current_result', None)
            if _pipeline_result:
                for p in _pipeline_result.phases:
                    if p.phase == PHASE_ATTACK:
                        attack_data = p.data.get("results", [])
                        # REV-16: 收集 PyRIT 原生 AttackResult 供报告使用
                        pyrit_attack_results = p.data.get("pyrit_attack_results", [])
                        break

            if not attack_data:
                return PhaseResult(
                    phase=PHASE_REPORT,
                    success=False,
                    duration_ms=(time.time() - start) * 1000,
                    errors=["No attack results to generate report"],
                    summary="no_attack_data",
                )

            generator = ReportGenerator(results=attack_data)
            # REV-16: 传递 PyRIT AttackResult 对象供报告嵌入原生 Markdown
            if pyrit_attack_results:
                generator.set_pyrit_attack_results(pyrit_attack_results)
            # Phase 4.3: 传递人工审查发现供报告嵌入审查清单
            _hr_report = getattr(self, '_human_review_report', None)
            if _hr_report:
                generator.set_human_review_findings(_hr_report)
            # P2: 传递框架 ID 给报告生成器（用于风险评估结构化）
            _fw_id = getattr(self, '_framework_id', '')
            if _fw_id:
                generator._framework_id = _fw_id
            generator.generate(output_path=output, format=format)

            duration_ms = (time.time() - start) * 1000
            self._print_phase_complete("报告生成", duration_ms, True)
            self._print_info(f"报告路径: {output}")

            return PhaseResult(
                phase=PHASE_REPORT,
                success=True,
                duration_ms=duration_ms,
                summary=f"format={format}, path={output}",
                data={"report_path": output, "format": format},
            )

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error("Report phase error: %s", str(e), exc_info=True)
            return PhaseResult(
                phase=PHASE_REPORT,
                success=False,
                duration_ms=duration_ms,
                errors=[str(e)],
                summary=f"error: {e}",
            )

    def _run_human_review_phase(self, result: PipelineResult) -> None:
        """
        Phase 4.3: 人工审查高风险发现

        从攻击结果中提取高风险发现，生成审查清单。
        非交互式模式下自动标记为 pending_review，不阻塞流水线。
        审查发现存储在 self._human_review_report 中，供报告阶段使用。

        Args:
            result: PipelineResult 全链路结果
        """
        start = time.time()
        self._print_phase_start("🔍 人工审查", "高风险发现筛选")

        try:
            from .human_review import HumanReviewer

            # 从 PipelineResult 中提取攻击阶段的结果数据
            attack_data = None
            for p in result.phases:
                if p.phase == PHASE_ATTACK:
                    attack_data = p.data.get("results", [])
                    break

            if not attack_data:
                self._print_info("无攻击结果，跳过人工审查")
                return

            # 创建审查器（非交互式，不阻塞流水线）
            reviewer = HumanReviewer(interactive=False)
            review_report = reviewer.review(attack_data)

            # 存储审查报告供报告阶段使用
            self._human_review_report = review_report

            duration_ms = (time.time() - start) * 1000
            total = review_report.get("total_findings", 0)
            confirmed = review_report.get("confirmed", 0)
            rejected = review_report.get("rejected", 0)
            pending = review_report.get("pending", 0)

            summary = f"高风险发现={total}, 已确认={confirmed}, 已拒绝={rejected}, 待审查={pending}"
            self._print_phase_complete("人工审查", duration_ms, True)

            if total > 0:
                self._print_info(f"审查清单: {review_report.get('review_file', 'N/A')}")

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error("Human review phase error: %s", str(e), exc_info=True)
            self._print_phase_error("人工审查", e)

    # ── 凭据注入方法（委托到 core.utils）──

    @staticmethod
    def _inject_credentials_to_config(
        resolution: Optional[CredentialResolution],
    ) -> Dict[str, Dict[str, Any]]:
        """将凭据注入到侦察工具配置中（委托到 core.utils）"""
        from ..core.utils import inject_credentials_to_recon
        return inject_credentials_to_recon(resolution)

    def _inject_credentials_to_attack(
        self,
        resolution: CredentialResolution,
        engine: Any,
    ) -> None:
        """将凭据注入到攻击阶段的目标配置中（委托到 core.utils）"""
        from ..core.utils import inject_credentials_to_attack as _inject
        _inject(resolution, engine)
        if resolution and resolution.has_credentials:
            logger.info("Credentials injected to attack phase: %s", resolution.summary())

    # ── 辅助方法 ──

    @staticmethod
    def _resolve_target(
        target_url: Optional[str],
        target_file: Optional[str],
        spa_config: Optional[str],
    ) -> str:
        """
        解析目标 URL

        优先级：target_url > spa_config > target_file

        Returns:
            目标 URL 字符串
        """
        if target_url:
            return target_url

        if spa_config:
            # 从 SPA 配置提取 URL
            try:
                from ..recon import ReconEngine
                spa_data = ReconEngine.load_spa_config(spa_config)
                url = spa_data.get("connection", {}).get("url", "")
                if url and url.startswith("http"):
                    return url
                logger.warning("SPA config loaded but URL is empty or invalid: %s", url)
                return ""
            except Exception as e:
                logger.warning("Failed to load SPA config for URL resolution: %s", str(e))
                return ""

        if target_file:
            try:
                from ..recon import ReconEngine
                return ReconEngine.load_target(target_file)
            except Exception:
                return target_file

        return ""

    def _print_header(
        self,
        target: str,
        scope: str,
        depth: str,
        phases: List[str],
    ) -> None:
        """打印流水线头部信息"""
        if self._console:
            panel = Panel(
                f"[bold]目标:[/bold] {target}\n"
                f"[bold]范围:[/bold] {scope}\n"
                f"[bold]深度:[/bold] {depth}\n"
                f"[bold]阶段:[/bold] {' → '.join(phases)}",
                title="[bold cyan]AI Red Team 全链路评估[/bold cyan]",
                border_style="cyan",
                box=box.DOUBLE,
            )
            self._console.print(panel)
        else:
            print()
            print("═" * 60)
            print("  AI Red Team 全链路评估")
            print("═" * 60)
            print(f"  目标: {target}")
            print(f"  范围: {scope}")
            print(f"  深度: {depth}")
            print(f"  阶段: {' → '.join(phases)}")
            print("═" * 60)
            print()

    def _print_phase_start(self, title: str, detail: str) -> None:
        """打印阶段开始"""
        if self._console:
            self._console.print(f"\n[bold yellow]▶ {title}[/bold yellow] [dim]({detail})[/dim]")
        else:
            print(f"\n  ▶ {title} ({detail})")

    def _print_phase_complete(
        self,
        phase_name: str,
        duration_ms: float,
        success: bool,
    ) -> None:
        """打印阶段完成"""
        icon = "✅" if success else "❌"
        duration_s = duration_ms / 1000
        if self._console:
            color = "green" if success else "red"
            self._console.print(
                f"  [{color}]{icon} {phase_name}完成[/{color}] [dim]({duration_s:.1f}s)[/dim]"
            )
        else:
            print(f"  {icon} {phase_name}完成 ({duration_s:.1f}s)")

    def _print_phase_error(self, phase_name: str, error: Exception) -> None:
        """打印阶段错误"""
        if self._console:
            self._console.print(f"  [red]❌ {phase_name}失败: {error}[/red]")
        else:
            print(f"  ❌ {phase_name}失败: {error}")

    def _print_info(self, message: str) -> None:
        """打印信息"""
        if self._console:
            self._console.print(f"  [dim]{message}[/dim]")
        else:
            print(f"  {message}")

    def _print_recon_results(self, profile: Any, profile_path: str) -> None:
        """打印侦察结果摘要"""
        if self._console:
            table = Table(title="侦察结果摘要", box=box.ROUNDED)
            table.add_column("指标", style="cyan")
            table.add_column("值", style="white")
            table.add_row("漏洞数量", str(profile.vulnerability_count))
            table.add_row("风险等级", profile.risk_level)
            table.add_row("使用工具", ", ".join(profile.tools_used))
            owasp = profile.get_owasp_mappings() if hasattr(profile, 'get_owasp_mappings') else []
            table.add_row("OWASP 映射", ", ".join(owasp[:10]))
            table.add_row("画像路径", profile_path)
            self._console.print(table)

            # 模型信息
            fp = profile.fingerprint if hasattr(profile, 'fingerprint') else None
            if fp and (fp.model_name or fp.provider):
                self._console.print("\n  [bold]🤖 AI 模型信息:[/bold]")
                if fp.model_name:
                    self._console.print(f"     模型: {fp.model_name}")
                if fp.model_family:
                    self._console.print(f"     家族: {fp.model_family}")
                if fp.provider:
                    self._console.print(f"     API:  {fp.provider}")
        else:
            print(f"  侦察结果: 漏洞={profile.vulnerability_count}, 风险={profile.risk_level}")
            print(f"  画像路径: {profile_path}")

    def _print_attack_results(
        self,
        total: int,
        success: int,
        failed: int,
        rate: float,
    ) -> None:
        """打印攻击结果摘要（保留用于兼容性）"""
        if self._console:
            table = Table(title="攻击结果摘要", box=box.ROUNDED)
            table.add_column("指标", style="cyan")
            table.add_column("值", style="white")
            table.add_row("总载荷数", str(total))
            table.add_row("成功", f"[green]{success}[/green]")
            table.add_row("失败", f"[red]{failed}[/red]")
            table.add_row("成功率", f"[bold yellow]{rate:.1f}%[/bold yellow]")
            self._console.print(table)
        else:
            print(f"  攻击结果: {success}/{total} ({rate:.0f}%)")

    def _print_attack_results_native(
        self,
        total: int,
        success: int,
        failed: int,
        rate: float,
        pyrit_attack_results: list,
        scope: str,
    ) -> None:
        """
        REV-16: 使用 PyRIT 原生 output 模块渲染攻击结果

        先打印摘要表格，再调用 PyRIT output_attack_async 渲染详细结果。
        对齐 OWASP LLM Top 10，叠加分类信息。
        """
        # 1. 摘要表格（保留 Rich 格式）
        self._print_attack_results(total, success, failed, rate)

        # 2. PyRIT 原生详细输出
        if not pyrit_attack_results:
            logger.debug("No PyRIT AttackResult objects to render")
            return

        try:
            from ..reporting import AttackOutputAdapter, OWASP_LLM_MAPPINGS

            adapter = AttackOutputAdapter()

            # 构建 OWASP 映射
            scope_upper = scope.upper() if scope else ""
            owasp_meta = OWASP_LLM_MAPPINGS.get(scope_upper, {})
            owasp_mapping = {}
            if owasp_meta:
                owasp_mapping[scope] = owasp_meta.get("title", scope)

            # 调用 PyRIT 原生 output
            adapter.print_results_console(
                pyrit_attack_results,
                owasp_mapping=owasp_mapping,
                include_adversarial=True,
                include_auxiliary_scores=False,
                include_pruned=False,
            )
        except ImportError:
            logger.debug("AttackOutputAdapter not available, skipping native output")
        except Exception as e:
            logger.warning("PyRIT native output failed: %s", e)

    def _print_summary(self, result: PipelineResult) -> None:
        """打印全链路摘要"""
        if self._console:
            self._console.print()
            self._console.print(result.summary_table())
        else:
            print()
            print(result.summary_table())

    # ── 便捷方法 ──

    def run_recon_only(
        self,
        target_url: Optional[str] = None,
        target_file: Optional[str] = None,
        spa_config: Optional[str] = None,
        depth: str = "standard",
    ) -> PipelineResult:
        """
        仅执行侦察阶段（凭据检查 + 侦察）

        适用于先侦察后手动攻击的场景。

        Returns:
            PipelineResult
        """
        return self.run(
            target_url=target_url,
            target_file=target_file,
            spa_config=spa_config,
            depth=depth,
            phases=[PHASE_CREDENTIAL, PHASE_RECON],
        )

    def run_attack_only(
        self,
        target_url: Optional[str] = None,
        target_file: Optional[str] = None,
        scope: str = "llm01",
        profile_path: Optional[str] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
        model: Optional[str] = None,
        scorer_url: Optional[str] = None,
        scorer_key: Optional[str] = None,
        scorer_model: Optional[str] = None,
    ) -> PipelineResult:
        """
        仅执行攻击阶段（凭据检查 + 攻击 + 报告）

        适用于已有侦察画像、直接攻击的场景。

        Returns:
            PipelineResult
        """
        return self.run(
            target_url=target_url,
            target_file=target_file,
            scope=scope,
            profile_path=profile_path,
            skip_recon=True,
            objective=objective,
            placeholders=placeholders,
            model=model,
            scorer_url=scorer_url,
            scorer_key=scorer_key,
            scorer_model=scorer_model,
        )
