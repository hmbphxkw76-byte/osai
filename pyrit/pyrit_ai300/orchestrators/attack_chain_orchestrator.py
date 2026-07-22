# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Chain Orchestrator (REV-13 / GAP-13)
多阶段攻击链编排器：支持跨 OWASP 类型的攻击链编排

核心功能：
1. YAML 定义多阶段攻击链（如 LLM01注入 → LLM06工具调用 → ASI01 Agent劫持）
2. 前一阶段输出作为后一阶段输入（上下文传递）
3. 支持条件分支（前一阶段成功/失败决定后续路径）
4. 攻击链可视化（Mermaid 图）

设计原则：
- 每个阶段是一个独立的攻击执行单元
- 阶段间通过 ChainContext 传递数据
- 支持早停：某阶段失败可终止链
- 支持 Fallback：某阶段失败可切换到备用载荷

攻击链示例 YAML:
    chain:
      - name: "initial_injection"
        owasp_id: "LLM01"
        scope: "llm01"
        objective: "bypass safety filter"
        on_success: "continue"
        on_failure: "stop"

      - name: "tool_exploitation"
        owasp_id: "LLM06"
        scope: "llm06"
        objective: "exploit tool calling to extract data"
        context_from: "initial_injection"  # 使用前一阶段的输出
        on_success: "continue"
        on_failure: "fallback"
        fallback_scope: "llm06"

      - name: "agent_hijack"
        owasp_id: "ASI01"
        scope: "asi01"
        objective: "hijack agent for unauthorized actions"
        context_from: "tool_exploitation"
        on_success: "continue"
        on_failure: "stop"

使用方式：
    orchestrator = AttackChainOrchestrator()
    result = orchestrator.execute_chain(
        chain_config="config/attack/chains/injection_to_hijack.yaml",
        target_url="http://localhost:11434",
        target_model="gpt-4o",
    )

对齐文档：docs/architecture_review.md §5.2 GAP-13
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


# ── 阶段控制常量 ──
ON_SUCCESS_CONTINUE = "continue"
ON_SUCCESS_SKIP = "skip"
ON_FAILURE_STOP = "stop"
ON_FAILURE_CONTINUE = "continue"
ON_FAILURE_FALLBACK = "fallback"


@dataclass
class ChainStageConfig:
    """攻击链阶段配置"""
    name: str = ""
    owasp_id: str = ""
    scope: str = ""
    objective: str = ""
    context_from: str = ""       # 从哪个阶段获取上下文
    on_success: str = ON_SUCCESS_CONTINUE
    on_failure: str = ON_FAILURE_STOP
    fallback_scope: str = ""     # 失败时的备用 scope
    payloads: List[str] = field(default_factory=list)  # 指定载荷列表
    model_override: str = ""     # 覆盖目标模型

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainStageConfig":
        """从字典创建配置"""
        return cls(
            name=data.get("name", ""),
            owasp_id=data.get("owasp_id", ""),
            scope=data.get("scope", ""),
            objective=data.get("objective", ""),
            context_from=data.get("context_from", ""),
            on_success=data.get("on_success", ON_SUCCESS_CONTINUE),
            on_failure=data.get("on_failure", ON_FAILURE_STOP),
            fallback_scope=data.get("fallback_scope", ""),
            payloads=data.get("payloads", []),
            model_override=data.get("model_override", ""),
        )


@dataclass
class ChainStageResult:
    """攻击链阶段执行结果"""
    stage_name: str = ""
    owasp_id: str = ""
    success: bool = False
    duration_ms: float = 0.0
    payloads_tested: int = 0
    payloads_succeeded: int = 0
    response_text: str = ""      # 最佳响应文本（供后续阶段使用）
    context_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.payloads_tested == 0:
            return 0.0
        return self.payloads_succeeded / self.payloads_tested


@dataclass
class ChainResult:
    """攻击链整体执行结果"""
    chain_name: str = ""
    stages: List[ChainStageResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    overall_success: bool = False
    stages_succeeded: int = 0
    stages_failed: int = 0
    context_chain: Dict[str, str] = field(default_factory=dict)  # stage_name → response

    @property
    def success_rate(self) -> float:
        """链成功率"""
        total = len(self.stages)
        if total == 0:
            return 0.0
        return self.stages_succeeded / total

    def summary(self) -> str:
        """生成摘要"""
        lines = [
            f"Attack Chain: {self.chain_name}",
            f"  Total stages: {len(self.stages)}",
            f"  Succeeded: {self.stages_succeeded}",
            f"  Failed: {self.stages_failed}",
            f"  Success rate: {self.success_rate:.1%}",
            f"  Duration: {self.total_duration_ms / 1000:.1f}s",
            f"  Overall: {'✅ SUCCESS' if self.overall_success else '⚠️ PARTIAL'}",
        ]
        for s in self.stages:
            icon = "✅" if s.success else "❌"
            lines.append(f"    {icon} {s.stage_name} ({s.owasp_id}): "
                        f"{s.payloads_succeeded}/{s.payloads_tested} payloads, "
                        f"{s.duration_ms / 1000:.1f}s")
        return "\n".join(lines)

    def to_mermaid(self) -> str:
        """生成 Mermaid 流程图"""
        lines = ["graph LR"]
        for i, stage in enumerate(self.stages):
            node_id = f"S{i}"
            icon = "✅" if stage.success else "❌"
            label = f'{stage.stage_name} [{stage.owasp_id}] {icon}'
            lines.append(f'    {node_id}["{label}"]')
            if i > 0:
                prev_id = f"S{i - 1}"
                prev_stage = self.stages[i - 1]
                edge_label = "success" if prev_stage.success else "fallback"
                lines.append(f'    {prev_id} -->|{edge_label}| {node_id}')
        return "\n".join(lines)


class AttackChainOrchestrator:
    """
    多阶段攻击链编排器 (REV-13)

    支持 YAML 定义的多阶段攻击链，每阶段执行不同 OWASP 类别的攻击，
    前一阶段的输出可作为后续阶段的输入上下文。

    使用方式：
        orchestrator = AttackChainOrchestrator()
        result = orchestrator.execute_chain(
            chain_config="config/attack/chains/injection_to_hijack.yaml",
            target_url="http://localhost:11434",
            target_model="gpt-4o",
        )
        print(result.summary())
        print(result.to_mermaid())
    """

    def __init__(
        self,
        attack_executor: Optional[Any] = None,
    ):
        """
        Args:
            attack_executor: 攻击执行器（AttackOrchestrator 实例）
                             如果为 None，execute_chain 会尝试延迟创建
        """
        self._executor = attack_executor

    @property
    def executor(self) -> Any:
        """获取攻击执行器"""
        return self._executor

    @executor.setter
    def executor(self, value: Any) -> None:
        self._executor = value

    # ──────────────────────────────────────────────────────────────────────────
    # 链配置加载
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def load_chain_config(config_path: str) -> List[ChainStageConfig]:
        """
        从 YAML 文件加载攻击链配置

        Args:
            config_path: YAML 配置文件路径

        Returns:
            阶段配置列表
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Chain config not found: {config_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            raise ValueError(f"Invalid chain config: {config_path}")

        chain_data = data.get("chain", [])
        if not isinstance(chain_data, list):
            raise ValueError("Chain config must contain 'chain' list")

        stages = [ChainStageConfig.from_dict(stage) for stage in chain_data]
        logger.info("Loaded chain config: %d stages from '%s'", len(stages), config_path)
        return stages

    @staticmethod
    def validate_chain(stages: List[ChainStageConfig]) -> List[str]:
        """
        验证攻击链配置

        Returns:
            错误列表（空列表=有效）
        """
        errors: List[str] = []

        if not stages:
            errors.append("Chain has no stages")
            return errors

        stage_names = set()
        for i, stage in enumerate(stages):
            if not stage.name:
                errors.append(f"Stage {i}: missing 'name'")
            if stage.name in stage_names:
                errors.append(f"Stage {i}: duplicate name '{stage.name}'")
            stage_names.add(stage.name)

            if not stage.scope and not stage.payloads:
                errors.append(f"Stage '{stage.name}': missing 'scope' or 'payloads'")

            if stage.context_from and stage.context_from not in stage_names:
                if stage.context_from not in [s.name for s in stages[:i]]:
                    errors.append(
                        f"Stage '{stage.name}': context_from '{stage.context_from}' "
                        f"not found in preceding stages"
                    )

            if stage.on_failure == ON_FAILURE_FALLBACK and not stage.fallback_scope:
                errors.append(
                    f"Stage '{stage.name}': on_failure=fallback but no fallback_scope"
                )

        return errors

    # ──────────────────────────────────────────────────────────────────────────
    # 链执行
    # ──────────────────────────────────────────────────────────────────────────

    def execute_chain(
        self,
        chain_config: Any,
        target_url: str = "",
        target_model: str = "",
        target_file: Optional[str] = None,
        spa_config: Optional[str] = None,
        profile_path: Optional[str] = None,
    ) -> ChainResult:
        """
        执行多阶段攻击链

        Args:
            chain_config: YAML 文件路径或 ChainStageConfig 列表
            target_url: 目标 URL
            target_model: 目标模型名称
            target_file: 目标配置文件路径
            spa_config: SPA 配置文件路径
            profile_path: 侦察画像路径

        Returns:
            ChainResult 链执行结果
        """
        # 加载配置
        if isinstance(chain_config, str):
            stages = self.load_chain_config(chain_config)
        elif isinstance(chain_config, list):
            stages = chain_config
        else:
            raise ValueError("chain_config must be path or list of ChainStageConfig")

        # 验证
        errors = self.validate_chain(stages)
        if errors:
            raise ValueError(f"Invalid chain config: {'; '.join(errors)}")

        chain_name = " → ".join(s.name for s in stages)
        result = ChainResult(chain_name=chain_name)
        start_time = time.time()

        logger.info("Starting attack chain: %s (%d stages)", chain_name, len(stages))

        context_pool: Dict[str, str] = {}  # stage_name → response_text

        for i, stage in enumerate(stages):
            logger.info(
                "Chain stage %d/%d: '%s' (OWASP: %s, scope: %s)",
                i + 1, len(stages), stage.name, stage.owasp_id, stage.scope,
            )

            # 获取上下文
            context_response = ""
            if stage.context_from and stage.context_from in context_pool:
                context_response = context_pool[stage.context_from]

            # 执行阶段
            stage_result = self._execute_stage(
                stage=stage,
                target_url=target_url,
                target_model=stage.model_override or target_model,
                target_file=target_file,
                spa_config=spa_config,
                profile_path=profile_path,
                context_response=context_response,
            )

            result.stages.append(stage_result)

            # 保存上下文
            if stage_result.response_text:
                context_pool[stage.name] = stage_result.response_text
                result.context_chain[stage.name] = stage_result.response_text

            # 统计
            if stage_result.success:
                result.stages_succeeded += 1
            else:
                result.stages_failed += 1

            # 阶段控制
            if stage_result.success:
                if stage.on_success == ON_SUCCESS_SKIP and i < len(stages) - 1:
                    logger.info("Stage '%s' succeeded, skipping remaining stages", stage.name)
                    break
            else:
                if stage.on_failure == ON_FAILURE_STOP:
                    logger.warning("Stage '%s' failed, stopping chain", stage.name)
                    break
                elif stage.on_failure == ON_FAILURE_FALLBACK and stage.fallback_scope:
                    logger.info(
                        "Stage '%s' failed, executing fallback scope '%s'",
                        stage.name, stage.fallback_scope,
                    )
                    fallback_stage = ChainStageConfig(
                        name=f"{stage.name}_fallback",
                        owasp_id=stage.owasp_id,
                        scope=stage.fallback_scope,
                        objective=f"Fallback: {stage.objective}",
                        on_success=ON_SUCCESS_CONTINUE,
                        on_failure=ON_FAILURE_CONTINUE,
                    )
                    fallback_result = self._execute_stage(
                        stage=fallback_stage,
                        target_url=target_url,
                        target_model=target_model,
                        target_file=target_file,
                        spa_config=spa_config,
                        profile_path=profile_path,
                        context_response=context_response,
                    )
                    result.stages.append(fallback_result)
                    if fallback_result.success:
                        result.stages_succeeded += 1
                    else:
                        result.stages_failed += 1

        # 最终结果
        result.total_duration_ms = (time.time() - start_time) * 1000
        result.overall_success = result.stages_failed == 0 and result.stages_succeeded > 0

        logger.info(
            "Attack chain complete: %d/%d stages succeeded (%.1f%%) in %.1fs",
            result.stages_succeeded, len(result.stages),
            result.success_rate * 100,
            result.total_duration_ms / 1000,
        )

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 内部方法
    # ──────────────────────────────────────────────────────────────────────────

    def _execute_stage(
        self,
        stage: ChainStageConfig,
        target_url: str,
        target_model: str,
        target_file: Optional[str],
        spa_config: Optional[str],
        profile_path: Optional[str],
        context_response: str = "",
    ) -> ChainStageResult:
        """
        执行单个攻击链阶段

        P2-10: 对齐 PyRIT Workflow
        - 使用 AI300Engine.run(scope=...) 作为执行接口
        - 将 context_response 注入到 objective 中（上下文传递）
        - 将 memory_labels 注入到攻击中（跨阶段持久化）
        """
        stage_start = time.time()
        result = ChainStageResult(
            stage_name=stage.name,
            owasp_id=stage.owasp_id,
        )

        try:
            if self._executor is None:
                logger.warning(
                    "No attack executor set, stage '%s' will be simulated", stage.name,
                )
                # 模拟模式（用于测试和预览）
                result.payloads_tested = len(stage.payloads) or 1
                result.payloads_succeeded = 0
                result.success = False
                result.response_text = f"[simulated] {stage.objective}"
                result.context_data = {"simulated": True}
            elif hasattr(self._executor, 'run'):
                # P2-10: 对齐 AI300Engine 接口
                # AI300Engine.run(scope=...) 返回 scope_results 列表
                objective = stage.objective
                if context_response:
                    # 上下文注入：将前一阶段的响应作为当前阶段的上下文
                    objective = f"{stage.objective}\n\n[Context from previous stage]\n{context_response[:500]}"

                # 调用 AI300Engine.run
                attack_results = self._executor.run(scope=stage.scope)

                # 解析结果（scope_results 格式）
                if isinstance(attack_results, list):
                    for scope_result in attack_results:
                        attacks = scope_result.get("attacks", []) if isinstance(scope_result, dict) else []
                        for attack in attacks:
                            for r in attack.get("results", []):
                                result.payloads_tested += 1
                                if r.get("status") == "success" or r.get("is_success"):
                                    result.payloads_succeeded += 1
                                    if not result.response_text:
                                        result.response_text = r.get("response", "")

                    result.success = result.payloads_succeeded > 0
                    result.context_data = {"scope": stage.scope, "results": attack_results}
                else:
                    result.success = False
                    result.errors.append("Unexpected attack result type")
            else:
                # P2-10: 对齐 PipelineOrchestrator 接口
                # PipelineOrchestrator.run() 返回 PipelineResult
                attack_results = self._executor.run(
                    target_url=target_url,
                    target_file=target_file,
                    spa_config=spa_config,
                    scope=stage.scope,
                    model=target_model,
                    objective=stage.objective,
                    profile_path=profile_path,
                )

                # 从 PipelineResult 中提取攻击结果
                if hasattr(attack_results, 'phases'):
                    for phase in attack_results.phases:
                        if phase.phase == "attack" and phase.data.get("results"):
                            for scope_result in phase.data["results"]:
                                if isinstance(scope_result, dict):
                                    attacks = scope_result.get("attacks", [])
                                    for attack in attacks:
                                        for r in attack.get("results", []):
                                            result.payloads_tested += 1
                                            if r.get("status") == "success" or r.get("is_success"):
                                                result.payloads_succeeded += 1
                                                if not result.response_text:
                                                    result.response_text = r.get("response", "")

                    result.success = result.payloads_succeeded > 0
                    result.context_data = {"pipeline_result": attack_results}
                else:
                    result.success = False
                    result.errors.append("Unexpected result type from executor")

        except Exception as e:
            result.success = False
            result.errors.append(str(e))
            logger.error("Stage '%s' failed: %s", stage.name, e)

        result.duration_ms = (time.time() - stage_start) * 1000

        logger.info(
            "Stage '%s' %s: %d/%d payloads in %.1fs",
            stage.name,
            "✅" if result.success else "❌",
            result.payloads_succeeded,
            result.payloads_tested,
            result.duration_ms / 1000,
        )

        return result
