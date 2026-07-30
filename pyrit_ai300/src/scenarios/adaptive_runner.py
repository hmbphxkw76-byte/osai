"""
Adaptive Runner — P3+P4: 原生 AI300AdaptiveScenario 执行入口
============================================================

P3: 消除双轨 — pipeline.py 调用此模块替代 ScenarioOrchestrator.execute_batch()
P4: 原生优先 — 使用 DatasetAttackConfiguration(seed_groups=) 内联传入 attack_plans

核心设计（方案 A — PyRIT 原生优先）：
  PyRIT DatasetAttackConfiguration 原生支持 seed_groups= 参数，
  用于内联传入种子组（不触碰 Memory）。本模块将 pipeline 交互选择
  的 attack_plans 转换为 AttackSeedGroup 列表，通过 dataset_config
  参数传入 Scenario，完全对齐 PyRIT 原生数据流。

v8.0 拆分优化 — prepare / execute 分离：
  prepare_scenario_async():
    1. attack_plans → AttackSeedGroup 列表（SeedGroupBuilder.build）
    2. DatasetAttackConfiguration(seed_groups=...) 内联配置
    3. 创建 AI300AdaptiveScenario（含 Converter 变体）
    4. 注册基础技术到 AttackTechniqueRegistry（v3.0: 不含变体）
    5. scenario.set_params_from_args(dataset_config=..., max_retries=..., max_concurrency=...)
    6. scenario.initialize_async() → 原生构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS)
    → 返回 ScenarioPreparation（含 scenario + seed_groups + 诊断信息）

  execute_scenario_async():
    7. scenario.run_async() → 原生执行（含 tqdm + max_retries + 自动恢复）
    8. P0-A: 失败类型分析 → 提取失败类型统计 + 更新 selector（供 resume 使用）
    9. ScenarioResult → BatchAttackResult（向后兼容）

  run_adaptive_scenario_async():
    向后兼容包装器 = prepare + execute（不含展示）

v3.0 优化：
  - P0-A: 失败类型分析接入 — extract_failure_type_from_result 激活
  - P1-B: 移除 per_attack_timeout 传递（原生 max_retries + max_concurrency 足够）
  - 变体注册改为 include_variants=False（v3.0: 变体在 _build_techniques_dict 中动态创建）

保留自建：
  - OWASP 映射（通过 memory_labels）
"""

import asyncio
import logging
import math
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from src.payloads.models import BatchAttackResult

logger = logging.getLogger(__name__)

# P0-2: 最大总执行时间上限（秒），防止无限等待
_MAX_TOTAL_TIMEOUT = 3600  # 60 分钟

# P0-1: L2 预过滤的安全缓冲数
_L2_FILTER_BUFFER = 2


@dataclass
class AdaptiveRunResult:
    """
    原生 AdaptiveScenario 执行结果

    封装原生 ScenarioResult + 向后兼容的 BatchAttackResult
    """

    native_result: Any = None  # 原生 ScenarioResult
    batch_result: BatchAttackResult = field(default_factory=BatchAttackResult)
    scenario_result_id: str = ""
    execution_time: float = 0.0
    converter_variants_used: int = 0
    total_techniques_tried: int = 0
    # P0-A: 失败类型统计
    failure_type_distribution: dict[str, int] = field(default_factory=dict)
    most_common_failure_type: str | None = None

    @property
    def succeeded(self) -> int:
        return self.batch_result.succeeded

    @property
    def failed(self) -> int:
        return self.batch_result.failed

    @property
    def success_rate(self) -> float:
        return self.batch_result.success_rate


@dataclass
class ScenarioPreparation:
    """
    Scenario 准备结果 — 由 prepare_scenario_async 创建，由 execute_scenario_async 消费。

    在 scenario.initialize_async() 完成后、run_async() 之前返回，
    让调用方（s6_execute.py）可以展示 PyRIT 实际解析的技术池/变体/跳过统计，
    并在执行前审查一致性。
    """

    scenario: Any  # 已初始化的 AI300AdaptiveScenario
    attack_seed_groups: list  # L2/L3 过滤后的 seed groups
    original_seed_count: int = 0  # 过滤前的 seed group 数量
    skipped_by_stop: int = 0  # L2/L3 跳过的数量
    stop_reasons: list[str] = field(default_factory=list)
    owasp_threshold: float = 0.0  # P3: L2 阈值（运行时停止用）
    stop_on_first_success: bool = False  # P3: L3 全局首成功即停


async def prepare_scenario_async(
    *,
    objective_target: Any,
    judge_target: Any,
    attack_plans: list[Any] | None = None,
    seed_groups: list[Any] | None = None,
    owasp_id: str = "",
    exam_id: str = "",
    max_attempts_per_objective: int = 3,
    max_retries: int = 0,
    max_concurrency: int = 4,
    verbose: bool = False,
    converter_target: Any = None,
    memory_labels: dict[str, str] | None = None,
    target_type: str | None = None,
    strategy_mode: str = "academic",
    model_name: str = "gpt-4o",
    model_tier: str = "unknown",
    owasp_success_threshold: float = 0.0,
    stop_on_first_success: bool = False,
    warm_start_asr: dict[str, float] | None = None,
) -> ScenarioPreparation:
    """
    准备 Scenario — 转换 attack_plans → seed_groups → 创建并初始化 Scenario。

    执行步骤：
      1. 注册基础技术到 AttackTechniqueRegistry（v3.0: 不含变体）
      2. 创建 AI300AdaptiveScenario
      3. scenario.initialize_async() → 原生构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS)

    返回 ScenarioPreparation，调用方可在执行前展示诊断信息。

    Args:
        objective_target: 目标 PromptTarget
        judge_target: 评审 LLM Target（仅用于 objective scoring）
        attack_plans: 攻击计划列表（向后兼容，用于提取 OWASP 映射）
        seed_groups: 种子组列表（原生路径，优先使用）
        owasp_id: OWASP 分类 ID
        exam_id: 考试 ID
        max_attempts_per_objective: 每个 objective 最大尝试次数
        max_retries: Scenario 级别重试次数
        max_concurrency: 原生 AttackExecutor 并发数（默认 4）
        verbose: 是否详细输出
        converter_target: LLM 辅助 Converter 的 Target
        memory_labels: 额外 memory_labels
        target_type: PyRIT Target 类型名（如 "openai_chat"）
        strategy_mode: 策略模式 (academic/exam/balanced)
        model_name: 目标模型名
        model_tier: 模型分层 (strong/moderate/weak)
        owasp_success_threshold: L2 OWASP 分类成功率阈值
        stop_on_first_success: L3 全局首成功即停

    Returns:
        ScenarioPreparation 封装已初始化的 scenario + seed_groups

    Raises:
        ValueError: 如果无 seed groups 或初始化失败
    """
    from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
    from src.scenarios.technique_factories import register_ai300_techniques
    from src.scenarios.scenario_result_bridge import (
        build_memory_labels,
    )
    from src.scenarios.failure_type_selector import extract_failure_type_from_result  # noqa: F401 — 保留导入以触发模块初始化
    # v5.0: Target 路由展示已统一到 s6_execute.py，此处不再导入 target_aware_router
    # v3.0: PayloadStrategyMatcher 在 Adaptive 路径恢复使用
    from src.analysis.strategy_matcher import PayloadStrategyMatcher

    # P1-2: converter_target 自动创建 — 优先使用 TARGET_* 环境变量
    if converter_target is None:
        _target_endpoint = os.getenv("TARGET_ENDPOINT", "")
        _target_model = os.getenv("TARGET_MODEL", "")
        _target_api_key = os.getenv("TARGET_API_KEY", "")
        if _target_endpoint and _target_model and _target_api_key:
            try:
                from src.targets import create_prompt_target, TargetParams
                from src.targets.rate_limited_target import RateLimitConfig, wrap_target_with_rate_limiting
                _conv_rpm = os.getenv("CONVERTER_MAX_RPM")
                _conv_rpm = int(_conv_rpm) if _conv_rpm else None
                _conv_params = TargetParams(
                    temperature=0.7,
                    discover_capabilities=False,
                    max_requests_per_minute=_conv_rpm,
                )
                converter_target, _ = await create_prompt_target(
                    target_url=_target_endpoint,
                    api_key=_target_api_key,
                    model_name=_target_model,
                    params=_conv_params,
                )
                converter_target = wrap_target_with_rate_limiting(
                    converter_target,
                    config=RateLimitConfig(max_concurrent_requests=int(os.getenv("API_MAX_CONCURRENCY", "10"))),
                    semaphore_key=f"converter:{_target_endpoint}",
                )
                logger.info(f"P1-2: Auto-created converter_target from TARGET_* (model={_target_model})")
            except Exception as e:
                logger.warning(f"P1-2: Failed to create converter_target from TARGET_*: {e}, falling back to judge_target")
                converter_target = judge_target
        else:
            converter_target = judge_target
            logger.warning(
                "P1-2: converter_target 未指定且 TARGET_* 环境变量不完整，回退到 judge_target。"
                "安全对齐模型可能拒绝生成攻击内容，导致 LLM Converter 500 错误。"
            )

    # ──────────────────────────────────────────────────────────
    # 方案 A 核心：attack_plans → AttackSeedGroup → DatasetAttackConfiguration(seed_groups=)
    # ──────────────────────────────────────────────────────────
    from pyrit.scenario import DatasetAttackConfiguration
    from src.executor.attack.component.seed_group_builder import SeedGroupBuilder
    from src.scenarios.ai300_technique import AI300Technique

    attack_seed_groups: list[Any] = []
    pipeline_techniques: set[str] = set()

    if seed_groups:
        attack_seed_groups = list(seed_groups)
    elif attack_plans:
        for plan in attack_plans:
            objective = plan.prompt_item.objective
            sg = SeedGroupBuilder.build(plan, objective, include_conversation=True)
            attack_seed_groups.append(sg)
            pipeline_techniques.add(plan.attack_technique)

    if not attack_seed_groups:
        raise ValueError("No attack seed groups to execute (both attack_plans and seed_groups are empty)")

    # ──────────────────────────────────────────────────────────
    # PyRIT AtomicAttack 要求：同一技术下每个 seed group 的 objective 文本
    # 必须唯一（SHA256 去重）。
    # ──────────────────────────────────────────────────────────
    from pyrit.common.utils import to_sha256

    seen_objectives: set[str] = set()
    deduped_seed_groups: list[Any] = []
    duplicates_removed = 0

    for sg in attack_seed_groups:
        obj_value = None
        for seed in sg.seeds:
            if hasattr(seed, "value") and seed.__class__.__name__ == "SeedObjective":
                obj_value = seed.value
                break
        if obj_value is None:
            deduped_seed_groups.append(sg)
            continue

        obj_hash = to_sha256(obj_value)
        if obj_hash in seen_objectives:
            duplicates_removed += 1
            continue
        seen_objectives.add(obj_hash)
        deduped_seed_groups.append(sg)

    if duplicates_removed > 0:
        logger.info(
            f"AdaptiveRunner: removed {duplicates_removed} duplicate objective(s) "
            f"({len(attack_seed_groups)} → {len(deduped_seed_groups)} unique)"
        )

    attack_seed_groups = deduped_seed_groups

    # ──────────────────────────────────────────────────────────
    # P0-1: L2/L3 停止策略预过滤
    # ──────────────────────────────────────────────────────────
    original_seed_count = len(attack_seed_groups)
    skipped_by_stop = 0
    stop_reasons: list[str] = []

    if stop_on_first_success and len(attack_seed_groups) > 1:
        skipped_by_stop = len(attack_seed_groups) - 1
        attack_seed_groups = attack_seed_groups[:1]
        stop_reasons.append(f"L3 全局首成功即停: 保留 1/{original_seed_count} seed_groups")
        logger.info(f"P0-1 L3: stop_on_first_success=True, filtered to 1 seed group (from {original_seed_count})")
    elif owasp_success_threshold > 0.0 and attack_plans:
        owasp_to_indices: dict[str, list[int]] = defaultdict(list)
        for idx, plan in enumerate(attack_plans[:original_seed_count]):
            oid = getattr(plan, "owasp_id", None) or "UNKNOWN"
            owasp_to_indices[oid].append(idx)

        filtered_indices: list[int] = []
        for oid, indices in owasp_to_indices.items():
            total_for_owasp = len(indices)
            raw_required = math.ceil(total_for_owasp * owasp_success_threshold)
            required = min(raw_required, 5)
            keep_count = min(total_for_owasp, required + _L2_FILTER_BUFFER)
            filtered_indices.extend(indices[:keep_count])
            if keep_count < total_for_owasp:
                stop_reasons.append(
                    f"L2 OWASP {oid}: 保留 {keep_count}/{total_for_owasp} "
                    f"(threshold={owasp_success_threshold:.0%}, required={required})"
                )

        if filtered_indices and len(filtered_indices) < original_seed_count:
            filtered_seed_groups = []
            for idx in filtered_indices:
                if idx < len(attack_seed_groups):
                    filtered_seed_groups.append(attack_seed_groups[idx])
            skipped_by_stop = original_seed_count - len(filtered_seed_groups)
            attack_seed_groups = filtered_seed_groups
            logger.info(
                f"P0-1 L2: owasp_success_threshold={owasp_success_threshold}, "
                f"filtered to {len(attack_seed_groups)} seed groups (from {original_seed_count}, skipped {skipped_by_stop})"
            )

    # 创建内联 DatasetAttackConfiguration（不触碰 Memory）
    dataset_config = DatasetAttackConfiguration(seed_groups=attack_seed_groups)
    logger.info(
        f"AdaptiveRunner: {len(attack_seed_groups)} inline seed groups "
        f"(source: {'seed_groups' if seed_groups else 'attack_plans'}"
        + (f", L2/L3 filtered: {original_seed_count}→{len(attack_seed_groups)}" if skipped_by_stop > 0 else "")
        + ")"
    )
    if stop_reasons:
        print(f"  [STOP]  停止策略预过滤: 跳过 {skipped_by_stop} 个 seed groups")
        for reason in stop_reasons:
            print(f"          • {reason}")

    # 将 pipeline 选中的技术映射到 AI300Technique 枚举
    valid_technique_values = {t.value for t in AI300Technique}
    scenario_techniques: list[Any] = []
    for tech_name in pipeline_techniques:
        if tech_name in valid_technique_values:
            for member in AI300Technique:
                if member.value == tech_name:
                    scenario_techniques.append(member)
                    break
        else:
            logger.debug(f"Technique '{tech_name}' not in AI300Technique enum, skipping")

    if not scenario_techniques:
        scenario_techniques = None
        logger.info("No mappable pipeline techniques, using AI300Technique.DEFAULT")
    else:
        logger.info(f"Mapped {len(scenario_techniques)} pipeline techniques: {[t.value for t in scenario_techniques]}")

    # ──────────────────────────────────────────────────────────
    # P3: 自动补充高 ASR 技术到执行池
    # 当载荷仅映射到低 ASR 技术（如 prompt_sending ASR=2%）时，
    # 自动补充 Tier S/A 技术（crescendo/red_teaming）以提升攻击成功率。
    # 设计原则: 载荷驱动为主，但技术池不应仅由载荷决定 —
    # 高 ASR 多轮技术（crescendo ASR=82-95%）对弱模型最有效，
    # 应始终在执行池中，即使载荷未映射到它们。
    # ──────────────────────────────────────────────────────────
    _HIGH_ASR_TECH_VALUES: frozenset[str] = frozenset({
        "crescendo", "red_teaming", "tap", "tree_of_attacks_pruned", "pair",
    })
    if scenario_techniques is not None:
        existing_values = {t.value for t in scenario_techniques}
        missing_high_asr = _HIGH_ASR_TECH_VALUES - existing_values
        if missing_high_asr:
            # 检查目标是否支持多轮（crescendo/red_teaming 需要 MULTI_TURN 能力）
            _supports_multi_turn = True
            if objective_target is not None:
                try:
                    from src.executor.attack.core.modality_router import ModalityRouter
                    from pyrit.prompt_target.common.target_capabilities import CapabilityName as _CN
                    _caps = ModalityRouter.get_capabilities(objective_target)
                    _supports_multi_turn = _caps.includes(capability=_CN.MULTI_TURN)
                except Exception:
                    pass

            added_techs: list[str] = []
            for tech_val in _HIGH_ASR_TECH_VALUES:
                if tech_val in missing_high_asr:
                    # crescendo/red_teaming/tap/pair 需要多轮支持
                    if tech_val in ("crescendo", "red_teaming", "tap", "pair", "tree_of_attacks_pruned"):
                        if not _supports_multi_turn:
                            continue
                    for member in AI300Technique:
                        if member.value == tech_val:
                            scenario_techniques.append(member)
                            added_techs.append(tech_val)
                            break

            if added_techs:
                logger.info(
                    f"P3: Auto-supplemented {len(added_techs)} high-ASR techniques "
                    f"to execution pool: {added_techs} "
                    f"(payload-only techniques had low ASR, supplemented for success rate)"
                )

    # ──────────────────────────────────────────────────────────
    # 注册 judge_target 到 TargetRegistry — PyRIT 原生 target 解析
    # ──────────────────────────────────────────────────────────
    try:
        from pyrit.registry import TargetRegistry
        registry = TargetRegistry.get_registry_singleton()
        registry.instances.register(judge_target, name="adversarial_chat")
        registry.instances.register(judge_target, name="objective_scorer_chat")
        logger.info("Registered judge_target as 'adversarial_chat' + 'objective_scorer_chat' in TargetRegistry")
    except Exception as e:
        logger.warning(f"Failed to register judge_target in TargetRegistry: {e}")

    # ──────────────────────────────────────────────────────────
    # v3.0: PayloadStrategyMatcher 在 Adaptive 路径恢复使用
    # ──────────────────────────────────────────────────────────
    strategy_matcher = PayloadStrategyMatcher(target_type=target_type)
    matched_techniques: set[str] = set()
    if attack_plans:
        for plan in attack_plans:
            plan_owasp = getattr(plan, "owasp_id", "") or owasp_id
            plan_tech_hint = ""
            prompt_item = getattr(plan, "prompt_item", None)
            if prompt_item:
                meta = getattr(prompt_item, "metadata", {}) or {}
                plan_tech_hint = meta.get("technique", meta.get("technique_group", ""))

            matched = strategy_matcher.match(
                owasp_id=plan_owasp,
                technique_hint=plan_tech_hint,
            )
            if matched.attack_technique:
                matched_techniques.add(matched.attack_technique)

        if matched_techniques:
            logger.info(
                f"PayloadStrategyMatcher: matched {len(matched_techniques)} techniques "
                f"from {len(attack_plans)} plans (target_type={target_type})"
            )

    # 创建 objective_scorer（从 judge_target 构建 SelfAskTrueFalseScorer）
    objective_scorer = None
    try:
        from pyrit.score import SelfAskTrueFalseScorer
        objective_scorer = SelfAskTrueFalseScorer(chat_target=judge_target)
        logger.debug("Created SelfAskTrueFalseScorer from judge_target")
    except Exception as e:
        logger.warning(f"Failed to create objective_scorer from judge_target: {e}")

    # 1. 注册基础技术到 AttackTechniqueRegistry
    try:
        register_ai300_techniques(
            tags=["all"],
            reset=False,
            converter_target=converter_target,
            include_variants=False,
            target_type=target_type,
            objective_target=objective_target,
        )
    except Exception as e:
        logger.warning(f"Technique registration failed (non-fatal): {e}")

    # 2. 构建 memory_labels（OWASP 映射 + P6: 扩展标签）
    # P6: 注入 model_name/strategy_mode/target_type 供跨运行 ASR 追踪
    labels = build_memory_labels(
        owasp_id=owasp_id,
        exam_id=exam_id,
        model_name=model_name,
        strategy_mode=strategy_mode,
        target_type=target_type or "",
    )
    if memory_labels:
        labels.update(memory_labels)

    # 3. 创建 AI300AdaptiveScenario
    scenario = AI300AdaptiveScenario(
        converter_target=converter_target,
        objective_scorer=objective_scorer,
        target_type=target_type,
        owasp_id=owasp_id,
        strategy_mode=strategy_mode,
        model_name=model_name,
        model_tier=model_tier,
        warm_start_asr=warm_start_asr,
    )

    # ──────────────────────────────────────────────────────────
    # 原生参数传递：dataset_config + scenario_techniques + max_retries + max_concurrency
    # ──────────────────────────────────────────────────────────
    scenario_params: dict[str, Any] = {
        "objective_target": objective_target,
        "max_attempts_per_objective": max_attempts_per_objective,
        "memory_labels": labels,
        "dataset_config": dataset_config,
        "max_retries": max_retries,
        "max_concurrency": max_concurrency,
    }
    if scenario_techniques is not None:
        scenario_params["scenario_techniques"] = scenario_techniques

    scenario.set_params_from_args(args=scenario_params)

    # 4. 初始化 Scenario — 原生构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS)
    await scenario.initialize_async()

    logger.info(
        f"AdaptiveRunner: scenario initialized "
        f"({len(attack_seed_groups)} seed groups, "
        f"{len(getattr(scenario, '_atomic_attacks', []))} atomic attacks)"
    )

    return ScenarioPreparation(
        scenario=scenario,
        attack_seed_groups=attack_seed_groups,
        original_seed_count=original_seed_count,
        skipped_by_stop=skipped_by_stop,
        stop_reasons=stop_reasons,
        owasp_threshold=owasp_success_threshold,
        stop_on_first_success=stop_on_first_success,
    )


async def execute_scenario_async(
    preparation: ScenarioPreparation,
    *,
    attack_plans: list[Any] | None = None,
    owasp_id: str = "",
    per_attack_timeout: int = 180,
    max_attempts_per_objective: int = 3,
) -> AdaptiveRunResult:
    """
    执行已准备的 Scenario — run_async + 结果转换 + 失败类型分析。

    Args:
        preparation: prepare_scenario_async 返回的 ScenarioPreparation
        attack_plans: 攻击计划列表（用于结果转换的 total_plans 统计）
        owasp_id: OWASP 分类 ID
        per_attack_timeout: [v3.0 deprecated] 单次攻击超时（仅用于 asyncio.wait_for 总超时计算）
        max_attempts_per_objective: 每个 objective 最大尝试次数（用于总超时计算）

    Returns:
        AdaptiveRunResult 封装原生结果 + 向后兼容 BatchAttackResult
    """
    from src.scenarios.failure_type_selector import extract_failure_type_from_result

    scenario = preparation.scenario
    attack_seed_groups = preparation.attack_seed_groups
    start_time = time.time()

    # P3-HIGH: 注入运行时停止策略事件处理器
    # 替代预过滤，实现真正的运行时停止
    runtime_stop_handler = None
    try:
        from src.scenarios.runtime_stop_handler import RuntimeStopEventHandler
        _owasp_threshold = getattr(preparation, "owasp_threshold", 0.0)
        _stop_on_first = getattr(preparation, "stop_on_first_success", False)
        if _owasp_threshold > 0 or _stop_on_first:
            runtime_stop_handler = RuntimeStopEventHandler(
                owasp_threshold=_owasp_threshold,
                stop_on_first_success=_stop_on_first,
            )
            # 尝试注册到 Scenario 的 AttackExecutor
            _executor = getattr(scenario, "_attack_executor", None)
            if _executor is not None and hasattr(_executor, "_register_event_handler"):
                _executor._register_event_handler(runtime_stop_handler)
                logger.info(
                    f"P3: RuntimeStopEventHandler registered "
                    f"(L2={_owasp_threshold:.0%}, L3={_stop_on_first})"
                )
    except Exception as e:
        logger.debug(f"P3: RuntimeStopEventHandler registration failed: {e}")

    # 5. 执行 Scenario（原生 run_async — 含 tqdm + max_retries + 自动恢复）
    #
    # P0-2: asyncio.wait_for 超时保护
    scenario_result_id = getattr(scenario, "_scenario_result_id", None)
    scenario_error = None
    total_timeout = min(
        per_attack_timeout * len(attack_seed_groups) * max_attempts_per_objective,
        _MAX_TOTAL_TIMEOUT,
    )
    logger.info(
        f"P0-2: scenario.run_async() timeout={total_timeout}s "
        f"({per_attack_timeout}s × {len(attack_seed_groups)} groups × {max_attempts_per_objective} attempts, "
        f"capped at {_MAX_TOTAL_TIMEOUT}s)"
    )
    native_result = None
    try:
        native_result = await asyncio.wait_for(
            scenario.run_async(),
            timeout=total_timeout,
        )
    except asyncio.TimeoutError:
        logger.error(
            f"P0-2: Scenario execution timed out after {total_timeout}s "
            f"({per_attack_timeout}s × {len(attack_seed_groups)} × {max_attempts_per_objective})"
        )
        scenario_error = f"Scenario timed out after {total_timeout}s"
        try:
            from pyrit.memory import CentralMemory
            memory = CentralMemory.get_memory_instance()
            sid = scenario_result_id or getattr(scenario, "_scenario_result_id", None)
            if sid:
                scenario_results = memory.get_scenario_results(scenario_result_ids=[sid])
                if scenario_results:
                    native_result = scenario_results[0]
                    logger.info(
                        f"P0-2: Retrieved partial ScenarioResult from memory "
                        f"(scenario_result_id={sid}, {len(scenario_results)} results found)"
                    )
            else:
                logger.warning("No scenario_result_id available, cannot retrieve partial results")
        except Exception as e2:
            logger.warning(f"Failed to retrieve partial results from memory: {e2}")
    except Exception as e:
        logger.error(f"Scenario execution failed: {e}")
        scenario_error = str(e)
        # L5: 使用 scenario_result_id 精确检索当前运行的部分结果
        try:
            from pyrit.memory import CentralMemory
            memory = CentralMemory.get_memory_instance()
            sid = scenario_result_id or getattr(scenario, "_scenario_result_id", None)
            if sid:
                scenario_results = memory.get_scenario_results(
                    scenario_result_ids=[sid]
                )
                if scenario_results:
                    native_result = scenario_results[0]
                    logger.info(
                        f"Retrieved partial ScenarioResult from memory "
                        f"(scenario_result_id={sid}, {len(scenario_results)} results found)"
                    )
            else:
                logger.warning("No scenario_result_id available, cannot retrieve partial results")
        except Exception as e2:
            logger.warning(f"Failed to retrieve partial results from memory: {e2}")

    elapsed = time.time() - start_time

    # 6. 结果转换（向后兼容 BatchAttackResult）
    batch_result = _convert_native_to_batch_result(
        native_result,
        attack_plans=attack_plans,
        owasp_id=owasp_id,
    )
    if scenario_error:
        batch_result.errors.append({"error": f"Scenario failed: {scenario_error}"})

    # ──────────────────────────────────────────────────────────
    # P0-A: 失败类型分析 + P4: ConverterHealthMonitor
    # ──────────────────────────────────────────────────────────
    converter_variants = 0
    total_techniques = 0
    failure_type_counter: Counter = Counter()
    most_common_failure_type: str | None = None

    # P4: ConverterHealthMonitor — 执行后分析 Converter 健康状态
    converter_health: Any = None
    converter_health_stats: dict[str, Any] | None = None
    try:
        from src.scenarios.converter_health_monitor import (
            ConverterHealthMonitor,
            extract_converter_name_from_error,
            extract_chain_name_from_error,
        )
        converter_health = ConverterHealthMonitor()
    except Exception as e:
        logger.debug(f"P4: ConverterHealthMonitor creation failed: {e}")

    if native_result is not None:
        display_groups = native_result.get_display_groups() if hasattr(native_result, "get_display_groups") else {}
        for group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue
                total_techniques += 1

                # Converter 检测：从 identifier.children['request_converters'] 提取
                identifier = None
                if hasattr(r, "get_attack_strategy_identifier"):
                    identifier = r.get_attack_strategy_identifier()
                if identifier is not None:
                    children = getattr(identifier, "children", None) or {}
                    if children.get("request_converters"):
                        converter_variants += 1

                # P0-A: 失败类型提取
                outcome = getattr(r, "outcome", None)
                if outcome is not None:
                    outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                    if outcome_str != "SUCCESS":
                        failure_type = extract_failure_type_from_result(r)
                        failure_type_counter[failure_type] += 1

                        # P4: ConverterHealthMonitor — 记录 Converter 失败
                        if converter_health is not None:
                            error_msg = str(
                                getattr(r, "error_message", "")
                                or getattr(r, "outcome_reason", "")
                            )
                            if error_msg:
                                conv_name = extract_converter_name_from_error(error_msg)
                                if conv_name:
                                    converter_health.record_failure(conv_name, error_msg)
                                chain_name = extract_chain_name_from_error(error_msg)
                                if chain_name:
                                    converter_health.record_failure(chain_name, error_msg)

                # P0-A: 也检查 SequentialAttackResult 的 child_attack_results
                child_results = getattr(r, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_outcome = getattr(child, "outcome", None)
                    if child_outcome is not None:
                        child_outcome_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                        if child_outcome_str != "SUCCESS":
                            child_failure_type = extract_failure_type_from_result(child)
                            failure_type_counter[child_failure_type] += 1

                            # P4: ConverterHealthMonitor — 子结果也记录
                            if converter_health is not None:
                                child_error = str(
                                    getattr(child, "error_message", "")
                                    or getattr(child, "outcome_reason", "")
                                )
                                if child_error:
                                    conv_name = extract_converter_name_from_error(child_error)
                                    if conv_name:
                                        converter_health.record_failure(conv_name, child_error)
                                    chain_name = extract_chain_name_from_error(child_error)
                                    if chain_name:
                                        converter_health.record_failure(chain_name, child_error)

    # 计算最常见的失败类型
    if failure_type_counter:
        most_common_failure_type = failure_type_counter.most_common(1)[0][0]
        logger.info(
            f"P0-A: Failure type analysis — "
            f"total failures: {sum(failure_type_counter.values())}, "
            f"distribution: {dict(failure_type_counter)}, "
            f"most common: {most_common_failure_type}"
        )

        # P0-A: 更新 selector 的失败类型（供 resume 场景使用）
        selector = getattr(scenario, "_selector", None)
        if selector and hasattr(selector, "update_failure_type"):
            selector.update_failure_type(most_common_failure_type)
            logger.debug(
                f"P0-A: Updated selector failure_type to '{most_common_failure_type}' "
                f"(for resume scenarios)"
            )

    # P3: 输出运行时停止策略统计
    if runtime_stop_handler is not None:
        stop_stats = runtime_stop_handler.get_stats()
        if stop_stats.get("should_stop"):
            logger.info(
                f"P3: Runtime stop triggered — reason: {stop_stats['stop_reason']}"
            )

    # P4: 输出 Converter 健康统计
    if converter_health is not None:
        converter_health_stats = converter_health.get_stats()
        disabled = converter_health.get_disabled_converters()
        if disabled:
            logger.warning(
                f"P4: ConverterHealthMonitor — {len(disabled)} converters disabled: "
                f"{disabled}"
            )
        if converter_health_stats:
            logger.info(
                f"P4: ConverterHealthMonitor stats — {converter_health_stats}"
            )

    return AdaptiveRunResult(
        native_result=native_result,
        batch_result=batch_result,
        scenario_result_id=getattr(native_result, "id", ""),
        execution_time=elapsed,
        converter_variants_used=converter_variants,
        total_techniques_tried=total_techniques,
        failure_type_distribution=dict(failure_type_counter),
        most_common_failure_type=most_common_failure_type,
    )


async def run_adaptive_scenario_async(
    *,
    objective_target: Any,
    judge_target: Any,
    attack_plans: list[Any] | None = None,
    seed_groups: list[Any] | None = None,
    owasp_id: str = "",
    exam_id: str = "",
    max_attempts_per_objective: int = 3,
    per_attack_timeout: int = 180,
    max_retries: int = 0,
    max_concurrency: int = 4,
    verbose: bool = False,
    converter_target: Any = None,
    memory_labels: dict[str, str] | None = None,
    target_type: str | None = None,
    strategy_mode: str = "academic",
    model_name: str = "gpt-4o",
    model_tier: str = "unknown",
    owasp_success_threshold: float = 0.0,
    stop_on_first_success: bool = False,
    warm_start_asr: dict[str, float] | None = None,
) -> AdaptiveRunResult:
    """
    向后兼容包装器 — prepare + execute（不含展示）。

    供 group_fallback_executor.py 等非 pipeline 调用方使用。
    pipeline 应直接调用 prepare_scenario_async + execute_scenario_async，
    以便在两步之间插入"执行前准备"展示。
    """
    preparation = await prepare_scenario_async(
        objective_target=objective_target,
        judge_target=judge_target,
        attack_plans=attack_plans,
        seed_groups=seed_groups,
        owasp_id=owasp_id,
        exam_id=exam_id,
        max_attempts_per_objective=max_attempts_per_objective,
        max_retries=max_retries,
        max_concurrency=max_concurrency,
        verbose=verbose,
        converter_target=converter_target,
        memory_labels=memory_labels,
        target_type=target_type,
        strategy_mode=strategy_mode,
        model_name=model_name,
        model_tier=model_tier,
        owasp_success_threshold=owasp_success_threshold,
        stop_on_first_success=stop_on_first_success,
        warm_start_asr=warm_start_asr,
    )
    return await execute_scenario_async(
        preparation,
        attack_plans=attack_plans,
        owasp_id=owasp_id,
        per_attack_timeout=per_attack_timeout,
        max_attempts_per_objective=max_attempts_per_objective,
    )


def _convert_native_to_batch_result(
    native_result: Any,
    *,
    attack_plans: list[Any] | None = None,
    owasp_id: str = "",
) -> BatchAttackResult:
    """
    P4: 将原生 ScenarioResult 转换为 BatchAttackResult（向后兼容）

    Args:
        native_result: 原生 ScenarioResult
        attack_plans: 攻击计划列表（用于 total_plans 统计）
        owasp_id: OWASP 分类 ID

    Returns:
        BatchAttackResult 实例
    """
    if native_result is None:
        return BatchAttackResult(
            total_plans=len(attack_plans or []),
            executed=0,
            succeeded=0,
            failed=0,
            errored=0,
            results=[],
            errors=[],
        )

    # 从原生 ScenarioResult 提取攻击结果
    all_results: list[Any] = []
    if hasattr(native_result, "get_display_groups"):
        display_groups = native_result.get_display_groups()
        for group_name, results in display_groups.items():
            all_results.extend(results)
    elif hasattr(native_result, "attack_results"):
        all_results = list(native_result.attack_results)

    # 统计成功/失败
    succeeded = 0
    failed = 0
    errored = 0
    for r in all_results:
        if r is None:
            continue
        outcome = getattr(r, "outcome", None)
        if outcome is not None:
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
            if outcome_str == "SUCCESS":
                succeeded += 1
            elif outcome_str == "ERROR":
                errored += 1
            else:
                failed += 1
        else:
            failed += 1

    total_plans = len(attack_plans) if attack_plans else len(all_results)

    return BatchAttackResult(
        total_plans=total_plans,
        executed=len(all_results),
        succeeded=succeeded,
        failed=failed,
        errored=errored,
        results=all_results,
        errors=[],
    )
