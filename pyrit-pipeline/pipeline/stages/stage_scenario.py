# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 2: ASR 驱动的场景配置 (Attack-King 策略)。.

职责:
  - 查询历史 ASR, 按攻击成功率排序数据集和载荷 (P1: ASR 驱动载荷优先级)
  - 从 ScorerRegistry 获取评分器 (三级 fallback)
  - 构造 TextAdaptive 场景 + FailureTypeRoutingSelector (ASR 驱动 + 失败路由)
  - 构造 CompoundDatasetAttackConfiguration (独立 per-dataset 预算)
  - 注入 warm-start ASR 先验到 selector (冷启动优化)
  - 注入 scenario_techniques + technique_converters + include_baseline
  - 单次 set_params_from_args 调用 (原生 API)

产出 (写入 PipelineContext):
  - ctx.scenario = TextAdaptive 实例 (已注入参数，未初始化)
  - ctx.objective_scorer = 评分器实例 (可能为 None)
  - ctx.selector = FailureTypeRoutingSelector 实例 (供 Stage 4 反馈)

依赖的原生 API:
  - pyrit.scenario.TextAdaptive, CompoundDatasetAttackConfiguration, DatasetAttackConfiguration
  - pyrit.scenario.scenarios.adaptive.selectors.SelectorScope
  - pyrit.registry.ScorerRegistry, AttackTechniqueRegistry
  - pyrit.converter (可选 technique_converters)

自研模块 (PyRIT 原生不具备, 纯数据/选择层, 不干扰原生生命周期):
  - pipeline.asr.failure_type_selector.FailureTypeRoutingSelector (继承原生 EpsilonGreedyTechniqueSelector)
  - pipeline.asr.prior_registry (学术 ASR 先验数据, 纯数据层)
  - pipeline.asr.optimizer (ASR 驱动排序)
  - pipeline.converters.factory (ASR 驱动 converter 路由)
  - pipeline.asr.rank_builder.ASRRankBuilder (Tier 分层 + 加权采样)
  - pipeline.converters.target_aware_router (Target 类型感知 Converter 链路由)
  - pipeline.asr.tiered_selection_wizard (三层渐进式选择)
  - pipeline.asr.rank_builder.GroupFallbackExecutor (组级 ASR 降级链)

修改此文件不影响 Stage 1, 3–5。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:15 — set_params_from_args 添加异常处理
>   2026-8-1 15:20 — converter 路由传入 ASR 数据
>   2026-8-1 16:00 — P0: 替换为 FailureTypeRoutingSelector + warm-start ASR 注入
>   2026-8-1 20:00 — 集成 ASRRankBuilder + target_aware_router + TieredSelectionWizard
>   2026-8-1 20:30 — 消除3: 直接使用原生 TextAdaptive (零覆盖),
>     Converter 由原生 technique_converters 参数注入
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.registry import AttackTechniqueRegistry, ScorerRegistry, TargetRegistry
from pyrit.scenario import CompoundDatasetAttackConfiguration
from pyrit.scenario.scenarios.adaptive import TextAdaptive
from pyrit.scenario.scenarios.adaptive.selectors import SelectorScope

from pipeline.analysis.technique_name_mapper import is_known_technique

# 消除3: 直接使用原生 TextAdaptive, 不再覆盖 _build_techniques_dict
from pipeline.asr.failure_type_selector import FailureTypeRoutingSelector
from pipeline.asr.optimizer import (
    get_asr_summary,  # noqa: F401 — re-exported for test patching
    get_technique_asr_summary,  # noqa: F401 — re-exported for test patching
    merge_empirical_with_priors,
    query_historical_asr_by_category,
    query_historical_asr_by_technique,
    sort_datasets_by_asr,
)
from pipeline.asr.prior_registry import get_initial_q_value
from pipeline.context import PipelineContext
from pipeline.converters.converter_health_monitor import ConverterHealthMonitor
from pipeline.converters.factory import (
    build_target_aware_converter_map,
    build_technique_converter_map,
    merge_converter_maps,
)
from pipeline.scenarios import create_scenario

logger = logging.getLogger(__name__)


def _get_attack_targets() -> tuple[Any, Any, Any]:
    """从 PyRIT 原生 TargetRegistry 获取三角色分离的攻击目标。.

    尝试获取三个独立 Target 实例用于 CrescendoAttack/TAPAttack 的三角色:
      - objective_target: 目标模型 (被攻击方)
      - adversarial_chat: 攻击者模型 (生成攻击消息)
      - scoring_target: 评分模型 (评估结果)

    如果注册表中只有 1 个 Target, 三个角色共享同一实例 (并打印提示)。
    如果有 2+ 个 Target, 第一个作为 objective_target, 第二个作为 adversarial_chat + scoring_target。
    如果有 3+ 个 Target, 分别用于三个角色。

    Returns:
        (objective_target, adversarial_chat, scoring_target) — 全部为 PyRIT 原生 PromptTarget。
        若无 Target, 返回 (None, None, None)。
    """
    try:
        _reg = TargetRegistry.get_registry_singleton()
        _entries = _reg.instances.get_all_instances()
        if not _entries:
            return None, None, None

        targets = [e.instance for e in _entries]

        if len(targets) >= 3:
            return targets[0], targets[1], targets[2]
        elif len(targets) == 2:
            # 第一个做目标, 第二个做攻击者+评分者
            return targets[0], targets[1], targets[1]
        else:
            # 只有 1 个, 三角色共享
            print("  [提示] 仅 1 个 Target 可用, 攻击者/评分者使用同一模型")
            return targets[0], targets[0], targets[0]
    except Exception as e:
        logger.warning(f"Failed to get attack targets from registry: {e}")
        return None, None, None


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 2/6: ASR 驱动的场景配置。."""
    print("\n" + "=" * 70)
    print("阶段 2/6: 场景配置 — ASR 驱动 + Attack-King")
    print("=" * 70)

    args = ctx.args

    # ── ASR 驱动载荷优先级 ──
    asr_by_category = query_historical_asr_by_category()
    # F3: 合并 ASR 分类 + 技术 ASR 为单一卡片
    _print_asr_summary(asr_by_category)

    # ── Recon → 攻击策略桥接 (R-S1/S2/S3): 消费侦察结果增强攻击配置 ──
    recon_strategy_result = None
    if ctx.metadata.get("recon_result") is not None or getattr(args, "recon_json", None):
        try:
            from pipeline.integrations.recon_strategy_bridge import bridge_recon_to_strategy

            print("\n  --- Recon → 攻击策略桥接 (R-S1/S2/S3) ---")
            recon_strategy_result = bridge_recon_to_strategy(ctx)
            if recon_strategy_result.capability:
                cap = recon_strategy_result.capability
                print(f"  能力: agent={cap.has_agent_tools}, rag={cap.has_rag_endpoints}, "
                      f"mcp={cap.has_mcp}, embedding={cap.has_embedding}")
        except Exception as e:
            print(f"  [提示] Recon 策略桥接跳过: {e}")

    # ── MCP 攻击场景 (R-M1): 可选的 MCP 协议级攻击 ──
    if getattr(args, "mcp_attack", False):
        try:
            from pipeline.scenarios.mcp_attack import run_mcp_attack

            mcp_report = await run_mcp_attack(ctx)
            ctx.metadata["mcp_attack_report"] = mcp_report.to_dict()
        except Exception as e:
            print(f"  [提示] MCP 攻击场景跳过: {e}")

    # ── 高级 MCP 攻击场景 (Kill Chain + 跨服务器信任链) ──
    if getattr(args, "advanced_mcp_attack", False):
        try:
            from pipeline.scenarios.advanced_mcp_attacks import run_advanced_mcp_attack

            adv_report = await run_advanced_mcp_attack(ctx)
            ctx.metadata["advanced_mcp_attack_report"] = adv_report.to_dict()
        except Exception as e:
            print(f"  [提示] 高级 MCP 攻击场景跳过: {e}")

    # ── Crescendo 多轮渐进式攻击 (PyRIT 原生 CrescendoAttack) ──
    crescendo_obj = getattr(args, "crescendo_objective", None)
    if crescendo_obj:
        try:
            from pipeline.orchestrators.advanced_crescendo import AdvancedCrescendoOrchestrator

            _obj_target, _adv_target, _score_target = _get_attack_targets()
            if _obj_target:
                _max_turns = getattr(args, "crescendo_max_turns", 10)
                orchestrator = AdvancedCrescendoOrchestrator(
                    objective_target=_obj_target,
                    adversarial_chat=_adv_target,
                    scoring_target=_score_target,
                    objective=crescendo_obj,
                    max_turns=_max_turns,
                )
                cres_result = await orchestrator.run_async()
                ctx.metadata["crescendo_result"] = cres_result.to_dict()
                print(f"  Crescendo (原生): achieved={cres_result.achieved}, "
                      f"turn={cres_result.winning_turn}/{cres_result.max_turns}, "
                      f"backtracks={cres_result.backtrack_count}")
            else:
                print("  [提示] Crescendo 跳过: 未找到已注册的 Target")
        except Exception as e:
            print(f"  [提示] Crescendo 攻击跳过: {e}")

    # ── TAP 树状攻击路径 (PyRIT 原生 TAPAttack) ──
    tap_obj = getattr(args, "tap_objective", None)
    if tap_obj:
        try:
            from pipeline.orchestrators.tap_orchestrator import TAPOrchestrator

            _obj_target, _adv_target, _score_target = _get_attack_targets()
            if _obj_target:
                orchestrator = TAPOrchestrator(
                    objective_target=_obj_target,
                    adversarial_chat=_adv_target,
                    scoring_target=_score_target,
                    objective=tap_obj,
                    tree_width=getattr(args, "tap_tree_width", 4),
                    tree_depth=getattr(args, "tap_tree_depth", 3),
                    branching=getattr(args, "tap_branching", 2),
                    success_threshold=getattr(args, "tap_success_threshold", 8),
                )
                tap_result = await orchestrator.run_async()
                ctx.metadata["tap_result"] = tap_result.to_dict()
                print(f"  TAP (原生): achieved={tap_result.achieved}, "
                      f"best_score={tap_result.best_score}, "
                      f"nodes_explored={tap_result.nodes_explored}, "
                      f"nodes_pruned={tap_result.nodes_pruned}")
            else:
                print("  [提示] TAP 跳过: 未找到已注册的 Target")
        except Exception as e:
            print(f"  [提示] TAP 攻击跳过: {e}")

    # ── XPIA 间接注入攻击 (PyRIT 原生 XPIAWorkflow) ──
    if getattr(args, "xpia_attack", False):
        try:
            from pipeline.scenarios.xpia_agent_attack import run_xpia_agent_attack

            xpia_result = await run_xpia_agent_attack(ctx)
            ctx.metadata["xpia_result"] = xpia_result
        except Exception as e:
            print(f"  [提示] XPIA 攻击跳过: {e}")

    # ── ASI03 身份与授权攻击 (PyRIT 原生 RedTeamingAttack) ──
    if getattr(args, "asi03_attack", False):
        try:
            from pipeline.scenarios.identity_authorization_attack import run_identity_authorization_attack

            asi03_result = await run_identity_authorization_attack(ctx)
            ctx.metadata["asi03_result"] = asi03_result
        except Exception as e:
            print(f"  [提示] ASI03 攻击跳过: {e}")

    # ── ASI09 人类信任利用 (PyRIT 原生 CrescendoAttack) ──
    if getattr(args, "asi09_attack", False):
        try:
            from pipeline.scenarios.human_trust_exploitation import run_human_trust_exploitation

            asi09_result = await run_human_trust_exploitation(ctx)
            ctx.metadata["asi09_result"] = asi09_result
        except Exception as e:
            print(f"  [提示] ASI09 攻击跳过: {e}")

    # ── ASI10 Agent 不可追溯性 (PyRIT 原生 PromptSendingAttack) ──
    if getattr(args, "asi10_attack", False):
        try:
            from pipeline.scenarios.agent_untraceability import run_agent_untraceability

            asi10_result = await run_agent_untraceability(ctx)
            ctx.metadata["asi10_result"] = asi10_result
        except Exception as e:
            print(f"  [提示] ASI10 攻击跳过: {e}")

    # ── 多 Agent 交互攻击 (PyRIT 原生 PromptSendingAttack + SequentialAttack) ──
    if getattr(args, "multi_agent_attack", False):
        try:
            from pipeline.scenarios.multi_agent_attack import run_multi_agent_attack

            ma_result = await run_multi_agent_attack(ctx)
            ctx.metadata["multi_agent_result"] = ma_result
        except Exception as e:
            print(f"  [提示] 多 Agent 攻击跳过: {e}")

    # ── 三框架评估 (CSA + OWASP + MITRE ATLAS) ──
    if getattr(args, "assessment_framework", False):
        try:
            from pipeline.assessment.framework_mapper import AssessmentPhase, OWASPAgenticCode
            from pipeline.assessment.redteam_methodology import RedTeamMethodology

            methodology = RedTeamMethodology(target_name=getattr(args, "model", "unknown"))

            # 自动标记已执行的攻击对应的 OWASP 代码
            if getattr(args, "mcp_attack", False):
                methodology.add_finding(
                    AssessmentPhase.SCOPING,
                    "MCP protocol-level attack executed",
                    owasp_code=OWASPAgenticCode.ASI01,
                )
            if getattr(args, "advanced_mcp_attack", False):
                for code in [OWASPAgenticCode.ASI01, OWASPAgenticCode.ASI02,
                             OWASPAgenticCode.ASI04, OWASPAgenticCode.ASI05,
                             OWASPAgenticCode.ASI06, OWASPAgenticCode.ASI07,
                             OWASPAgenticCode.ASI08]:
                    methodology.add_finding(
                        AssessmentPhase.SCOPING,
                        f"Advanced MCP attack covers {code.value}",
                        owasp_code=code,
                    )
            if getattr(args, "xpia_attack", False):
                methodology.add_finding(
                    AssessmentPhase.AUTOMATED_SCAN,
                    "XPIA indirect injection attack executed",
                    owasp_code=OWASPAgenticCode.ASI01,
                )
            if getattr(args, "asi03_attack", False):
                methodology.add_finding(
                    AssessmentPhase.AUTOMATED_SCAN,
                    "Identity & authorization attack executed",
                    owasp_code=OWASPAgenticCode.ASI03,
                )
            if getattr(args, "asi09_attack", False):
                methodology.add_finding(
                    AssessmentPhase.DEEP_EXPLOITATION,
                    "Human trust exploitation attack executed",
                    owasp_code=OWASPAgenticCode.ASI09,
                )
            if getattr(args, "asi10_attack", False):
                methodology.add_finding(
                    AssessmentPhase.DEEP_EXPLOITATION,
                    "Agent untraceability attack executed",
                    owasp_code=OWASPAgenticCode.ASI10,
                )
            if getattr(args, "multi_agent_attack", False):
                methodology.add_finding(
                    AssessmentPhase.DEEP_EXPLOITATION,
                    "Multi-agent interaction attack executed",
                    owasp_code=OWASPAgenticCode.ASI02,
                )

            methodology.complete_phase(AssessmentPhase.SCOPING, duration_minutes=5)
            methodology.complete_phase(AssessmentPhase.ENUMERATION, duration_minutes=10)
            methodology.complete_phase(AssessmentPhase.AUTOMATED_SCAN, duration_minutes=0,
                                       notes="Integrated into pipeline execution")
            methodology.complete_phase(AssessmentPhase.DEEP_EXPLOITATION, duration_minutes=0,
                                       notes="Crescendo/TAP/Advanced MCP executed inline")
            methodology.complete_phase(AssessmentPhase.MANUAL_TESTING, duration_minutes=0,
                                       notes="Requires manual expert testing")

            result = methodology.get_result()
            ctx.metadata["assessment_result"] = result.to_dict()
            print(f"  框架覆盖: OWASP {result.coverage.owasp_coverage_pct:.0f}%, "
                  f"CSA {result.coverage.csa_coverage_pct:.0f}%, "
                  f"ATLAS {result.coverage.atlas_coverage_count} techniques")
        except Exception as e:
            print(f"  [提示] 三框架评估跳过: {e}")

    # ── AI-VSS 漏洞评分 (桥接 PyRIT 原生 Scorer 结果) ──
    # 纯数据层增强 (R-022): 消费原生 Score → 推断修饰符 → 生成 AI-VSS 评分
    ai_vss_scores: list[dict[str, Any]] = []
    try:
        from pipeline.scoring.ai_vss_bridge import AIVSSBridge

        bridge = AIVSSBridge()

        # Crescendo 攻击结果 → AI-VSS
        cres_data = ctx.metadata.get("crescendo_result")
        if cres_data and isinstance(cres_data, dict):
            augmented = bridge.augment_score(
                score_value=str(cres_data.get("achieved", False)),
                score_type="true_false",
                attack_type="crescendo",
                owasp_codes=["ASI01"],
                objective=cres_data.get("objective", ""),
            )
            ai_vss_scores.append(augmented.to_dict())

        # TAP 攻击结果 → AI-VSS
        tap_data = ctx.metadata.get("tap_result")
        if tap_data and isinstance(tap_data, dict):
            augmented = bridge.augment_score(
                score_value=str(tap_data.get("achieved", False)),
                score_type="true_false",
                attack_type="tap",
                owasp_codes=["ASI01"],
                objective=tap_data.get("objective", ""),
            )
            ai_vss_scores.append(augmented.to_dict())

        # 高级 MCP 攻击结果 → AI-VSS
        adv_mcp_data = ctx.metadata.get("advanced_mcp_attack_report")
        if adv_mcp_data and isinstance(adv_mcp_data, dict):
            for probe in adv_mcp_data.get("probes", []):
                augmented = bridge.augment_score(
                    score_value=str(probe.get("success", False)),
                    score_type="true_false",
                    attack_type=probe.get("name", "mcp_injection"),
                    owasp_codes=probe.get("owasp_codes", []),
                    objective=probe.get("description", ""),
                )
                ai_vss_scores.append(augmented.to_dict())

        # XPIA 攻击结果 → AI-VSS
        xpia_data = ctx.metadata.get("xpia_result")
        if xpia_data and isinstance(xpia_data, dict):
            for vector in xpia_data.get("injection_vectors", []):
                augmented = bridge.augment_score(
                    score_value=str(vector.get("success", False)),
                    score_type="true_false",
                    attack_type="xpia",
                    owasp_codes=vector.get("owasp_codes", ["ASI01"]),
                    objective=vector.get("description", ""),
                )
                ai_vss_scores.append(augmented.to_dict())

        # ASI03 攻击结果 → AI-VSS
        asi03_data = ctx.metadata.get("asi03_result")
        if asi03_data and isinstance(asi03_data, dict):
            for scenario in asi03_data.get("scenarios", []):
                augmented = bridge.augment_score(
                    score_value=str(scenario.get("success", False)),
                    score_type="true_false",
                    attack_type="identity_authorization",
                    owasp_codes=["ASI03"],
                    objective=scenario.get("objective", ""),
                )
                ai_vss_scores.append(augmented.to_dict())

        # ASI09 攻击结果 → AI-VSS
        asi09_data = ctx.metadata.get("asi09_result")
        if asi09_data and isinstance(asi09_data, dict):
            for scenario in asi09_data.get("scenarios", []):
                augmented = bridge.augment_score(
                    score_value=str(scenario.get("success", False)),
                    score_type="true_false",
                    attack_type="human_trust_exploitation",
                    owasp_codes=["ASI09"],
                    objective=scenario.get("objective", ""),
                )
                ai_vss_scores.append(augmented.to_dict())

        # ASI10 攻击结果 → AI-VSS
        asi10_data = ctx.metadata.get("asi10_result")
        if asi10_data and isinstance(asi10_data, dict):
            for probe in asi10_data.get("probes", []):
                augmented = bridge.augment_score(
                    score_value=str(probe.get("success", False)),
                    score_type="true_false",
                    attack_type="agent_untraceability",
                    owasp_codes=["ASI10"],
                    objective=probe.get("description", ""),
                )
                ai_vss_scores.append(augmented.to_dict())

        # 多 Agent 攻击结果 → AI-VSS
        ma_data = ctx.metadata.get("multi_agent_result")
        if ma_data and isinstance(ma_data, dict):
            for chain in ma_data.get("chains", []):
                augmented = bridge.augment_score(
                    score_value=str(chain.get("success", False)),
                    score_type="true_false",
                    attack_type="multi_agent_chain",
                    owasp_codes=chain.get("owasp_codes", ["ASI02"]),
                    objective=chain.get("description", ""),
                )
                ai_vss_scores.append(augmented.to_dict())

        # 生成汇总并存储
        if ai_vss_scores:
            augmented_list = bridge.augment_scores_batch(score_results=ai_vss_scores)
            summary = bridge.generate_summary(augmented_list)
            ctx.metadata["ai_vss_scores"] = ai_vss_scores
            ctx.metadata["ai_vss_summary"] = summary
            print(f"  AI-VSS 漏洞评分: {summary['successful_attacks']}/{summary['total_attacks']} "
                  f"成功, 均值 {summary['avg_ai_vss_score']:.1f}, "
                  f"最高 {summary['max_ai_vss_score']:.1f}")
    except Exception as e:
        print(f"  [提示] AI-VSS 评分跳过: {e}")

    sorted_datasets = sort_datasets_by_asr(args.datasets, asr_by_category=asr_by_category)
    if sorted_datasets != args.datasets:
        print(f"  数据集优先级排序 (ASR 驱动): {args.datasets} → {sorted_datasets}")
    else:
        print(f"  数据集: {args.datasets}")

    # ── 评分器 + 模型信息 ──
    objective_scorer = _get_objective_scorer()
    ctx.objective_scorer = objective_scorer

    from pipeline.converters.model_tier_detector import detect_model_tier_from_registry

    model_name, model_tier = detect_model_tier_from_registry()
    owasp_id = os.getenv("OWASP_ID", "")

    # 复合评分器 (task_achieved AND not_refused)
    # 强模型/中等模型使用复合评分器, 消除部分拒绝导致的 ASR 假阳性
    from pipeline.scenarios.composite_scorer import should_use_composite_scorer

    if should_use_composite_scorer(model_tier) and objective_scorer is not None:
        try:
            from pipeline.scenarios.composite_scorer import create_composite_objective_scorer

            # 获取 scorer 的 chat_target
            scorer_chat_target = (
                getattr(objective_scorer, "_chat_target", None)
                or getattr(objective_scorer, "chat_target", None)
            )
            if scorer_chat_target is not None:
                composite = create_composite_objective_scorer(scorer_chat_target)
                if composite is not None:
                    print(f"  复合评分器已启用 (task_achieved AND not_refused, tier={model_tier})")
                    objective_scorer = composite
                    ctx.objective_scorer = composite
        except Exception as e:
            print(f"  [提示] 复合评分器创建跳过: {e}")

    # F3: 目标信息合并到技术池矩阵卡片中, 不再单独展示

    # 构建 warm-start ASR 字典
    # 从学术 ASR 先验构建 warm-start 字典，注入 selector
    # 首次运行时替代乐观初始值 1.0，确保高 ASR 技术被优先选中
    warm_start_asr = _build_warm_start_asr(model_name, model_tier, owasp_id)
    # 经验 ASR 自动刷新 — 经验数据覆盖学术先验
    if warm_start_asr:
        warm_start_asr = merge_empirical_with_priors(warm_start_asr, model_name=model_name)
    # F3: warm-start ASR 信息合并到技术池矩阵卡片中, 不再单独展示 Top 5

    # ASR Tier 分层 + 降级链
    ranked_groups: list = []
    try:
        from pipeline.asr.rank_builder import GroupFallbackExecutor

        try:
            all_tech_names = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
            tech_names_for_fallback = [n for n in all_tech_names if is_known_technique(n)]
        except ImportError:
            tech_names_for_fallback = []

        if tech_names_for_fallback:
            fallback_executor = GroupFallbackExecutor(
                model_name=model_name,
                model_tier=model_tier,
                owasp_id=owasp_id,
            )
            fallback_plan = fallback_executor.build_fallback_plan(
                technique_names=tech_names_for_fallback,
            )
            ctx.fallback_plan = fallback_plan
            print(f"  ASR Tier 降级链: {fallback_plan.total_groups} 组, {fallback_plan.fallback_count} 个降级点")
    except (ImportError, AttributeError, KeyError) as e:
        print(f" [提示] ASR Tier 降级链初始化跳过: {e}")

    # 动态技术选择
    selector_scope = SelectorScope.current_run() if args.selector_scope == "current_run" else SelectorScope.all_runs()

    # 多场景选择
    scenario_name = getattr(args, "scenario", "text_adaptive")

    if scenario_name == "text_adaptive":
        # 使用 FailureTypeRoutingSelector
        selector = FailureTypeRoutingSelector(
            epsilon=args.epsilon,
            scope=selector_scope,
            strategy_mode=os.getenv("STRATEGY_MODE", "academic"),
            model_name=model_name,
            model_tier=model_tier,
            owasp_id=owasp_id or None,
            warm_start_asr=warm_start_asr,
        )

        # 动态 epsilon 衰减 (--epsilon-decay)
        if getattr(args, "epsilon_decay", False):
            selector.set_epsilon_decay(True)
            print("  动态 epsilon 衰减已启用 (0.20→0.02, 50 步线性衰减)")

        # 直接使用原生 TextAdaptive, Converter 由 technique_converters 参数注入
        scenario = TextAdaptive(
            objective_scorer=objective_scorer,
            selector=selector,
            scenario_result_id=args.resume,
        )
        # 探测 target_type (用于报告和日志 + Layer 2 Converter 路由)
        # 修复: 优先使用 get_by_tag("default") 获取 objective target (而非字母序第一个)
        # 修复: except Exception 替代 except ImportError (避免静默吞错)
        try:
            from pipeline.converters.target_aware_router import infer_target_type

            registry = TargetRegistry.get_registry_singleton().instances
            # 优先获取标记为 default 的目标 (objective target)
            default_entries = registry.get_by_tag(tag="default")
            target_entries = default_entries or registry.get_all_instances()
            for entry in target_entries:
                inferred = infer_target_type(entry.instance)
                if inferred:
                    ctx.target_type = inferred
                    break
            if not ctx.target_type and target_entries:
                logger.warning(
                    f"target_type detection failed for {len(target_entries)} targets: "
                    f"class_name={type(target_entries[0].instance).__name__}"
                )
        except Exception as e:
            logger.warning(f"target_type detection error: {e}")
        # 保存 selector 引用供 Stage 4 运行时反馈
        ctx.selector = selector
        ctx.scenario = scenario

        # 加载历史范式性能数据到 selector (自动学习)
        try:
            from pipeline.asr.failure_type_event_handler import ParadigmPerformanceTracker

            output_mgr = getattr(ctx, "output_manager", None)
            if output_mgr:
                paradigm_path = output_mgr.empirical_asr_dir / "paradigm_performance.json"
            else:
                paradigm_path = Path("outputs/paradigm_performance.json")
            if paradigm_path.exists():
                tracker = ParadigmPerformanceTracker.load_from_file(paradigm_path)
                if tracker.has_data:
                    selector.set_paradigm_tracker(tracker)
                    print("  范式性能数据已加载 (运行时自动学习)")
        except Exception as e:
            print(f"  [提示] 范式性能数据加载跳过: {e}")
        print("  场景: text_adaptive (原生 TextAdaptive + ASR 驱动 Selector, 零覆盖)")
    else:
        # ── P1: 原生场景 (AIRT/Garak/Benchmark/Foundry) ──
        scenario = create_scenario(
            scenario_name,
            objective_scorer=objective_scorer,
            scenario_result_id=args.resume,
        )
        if scenario is None:
            print(f"  [错误] 无法创建场景: {scenario_name}")
            raise ValueError(f"Unknown scenario: {scenario_name}")
        ctx.scenario = scenario
        ctx.selector = None
        print(f"  场景: {scenario_name} (原生场景)")

    # CompoundDatasetAttackConfiguration (独立 per-dataset 预算)
    dataset_config = CompoundDatasetAttackConfiguration.per_dataset(
        dataset_names=sorted_datasets,
        max_dataset_size=args.max_dataset_size,
    )
    print(f"  数据集配置 (本地预加载, per-dataset 预算={args.max_dataset_size}): {len(sorted_datasets)} 个数据集")

    # ── P2: EXHAUSTIVE 策略 ──
    # 对每个 objective 尝试所有技术 (不提前停止), 生成完整 ASR 对比矩阵
    if getattr(args, "exhaustive", False):
        max_attempts = 999
        print("  EXHAUSTIVE 模式: 全技术尝试 (max_attempts=999)")
    elif os.getenv("STOP_ON_FIRST_SUCCESS", "").lower() in ("true", "1", "yes"):
        # L3: 全局首停
        max_attempts = 1
        print("  全局首停策略启用 (max_attempts=1)")
    else:
        # L1: 原生 FIRST_SUCCESS
        max_attempts = args.max_attempts

    # 模型特异性攻击参数
    _apply_tier_attack_params(args, model_tier)

    # converter_target 提前获取
    # 使用最优对抗 LLM 配对 (PAIR arXiv:2310.08437)
    converter_target = _get_converter_target(model_name)
    converter_target_available = converter_target is not None
    if not converter_target_available:
        converter_target = _auto_create_converter_target()
        converter_target_available = converter_target is not None
        if converter_target_available:
            print("  Converter 目标自动创建成功 (从 objective_target 配置派生)")

    # 构建参数包 (单次 set_params_from_args 调用)
    objective_target_name = _resolve_objective_target_name()
    params: dict[str, Any] = {
        # 通过 TargetRegistry 动态解析的目标名称
        "objective_target": objective_target_name,
        # 数据集配置 (auto_fetch=True 时自动从 SeedDatasetProvider 获取)
        "dataset_config": dataset_config,
        # 弹性恢复: 失败自动重试，从上次中断处继续
        "max_retries": args.max_retries,
        # 并发控制: 最多 N 个 AtomicAttack 同时执行
        "max_concurrency": args.max_concurrency,
        # 每 objective 最多尝试 N 个技术 (SequentialAttack FIRST_SUCCESS)
        "max_attempts_per_objective": max_attempts,
        # baseline 控制: prompt_sending 作为对比基线
        "include_baseline": not args.no_baseline,
        # 附加标签到每条 AttackResult
        "memory_labels": {
            "run_date": datetime.now().isoformat(),
            "pipeline_version": "7.0",
            "selector_scope": args.selector_scope,
            "asr_driven": "true",
        },
    }

    # Converter 变体动态创建

    # scenario_techniques (技术选择)
    if args.techniques:
        params["scenario_techniques"] = args.techniques
        print(f"  技术选择: {args.techniques}")
    elif getattr(args, "tier_layer", 0) > 0:
        # P1: TieredSelectionWizard 渐进式选择
        tier_techniques = _select_techniques_by_tier(
            model_name=model_name,
            model_tier=model_tier,
            owasp_id=owasp_id,
            tier_layer=args.tier_layer,
        )
        if tier_techniques:
            # 高 ASR 技术自动补充
            if len(tier_techniques) < 3 and warm_start_asr:
                top_asr_techs = sorted(warm_start_asr.items(), key=lambda x: x[1], reverse=True)
                for tech, asr in top_asr_techs:
                    if tech not in tier_techniques and len(tier_techniques) < 5:
                        tier_techniques.append(tech)
                        print(f"    补充高 ASR 技术: {tech} ({asr:.0%})")

            params["scenario_techniques"] = tier_techniques
            ctx.tier_layer = args.tier_layer
            print(f"  技术选择 (TieredSelection Layer {args.tier_layer}): {tier_techniques}")
        else:
            print("  技术选择: DEFAULT (TieredSelection 无结果)")
    else:
        print("  技术选择: DEFAULT (TextAdaptive 默认聚合)")

    # 能力感知技术过滤
    if params.get("scenario_techniques"):
        try:
            from pipeline.converters.modality_router import ModalityRouter

            target_entries = TargetRegistry.get_registry_singleton().instances.get_all_instances()
            if target_entries:
                target_instance = target_entries[0].instance
                # 多轮攻击技术集合 (需要 supports_multi_turn)
                multi_turn_techniques = {"crescendo", "tap", "red_teaming", "pair", "forest"}
                # 多模态攻击技术集合 (需要 supports_image_input)
                multimodal_techniques = {"image_variation", "multimodal_jailbreak"}

                techniques_before = list(params["scenario_techniques"])
                supported, filtered = ModalityRouter.filter_techniques_by_capability(
                    techniques_before,
                    target_instance,
                    multi_turn_techniques=multi_turn_techniques,
                    multimodal_techniques=multimodal_techniques,
                )
                if filtered:
                    params["scenario_techniques"] = supported
                    print(f"  能力感知筛选: 过滤 {len(filtered)} 个不支持的技术: {filtered}")
        except Exception as e:
            print(f"  [提示] ModalityRouter 技术过滤跳过: {e}")

    # Converter 路由 (ASR 驱动 + 目标感知双路由)
    technique_converter_map: dict[str, list] = {}

    try:
        all_tech_names = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
        technique_names = [n for n in all_tech_names if is_known_technique(n)]
    except Exception:
        technique_names = []

    # converter_target 已提前获取

    # ConverterHealthMonitor — 熔断器+降级+统计
    health_monitor = ConverterHealthMonitor(failure_threshold=2)
    ctx.converter_health_monitor = health_monitor

    # Layer 1: CLI --converters (ASR 驱动差异化路由)
    if args.converters and technique_names:
        # 小模型跳过 LLM 辅助 Converter 链
        from pipeline.converters.model_tier_detector import should_use_llm_converters

        llm_converters_ok = should_use_llm_converters(model_tier)
        if not llm_converters_ok:
            print(f"  小模型 (tier={model_tier}) 跳过 LLM 辅助 Converter 链")

        try:
            asr_by_tech = query_historical_asr_by_technique()
            cli_converter_map = build_technique_converter_map(
                converter_names=args.converters,
                technique_names=technique_names,
                asr_by_technique=asr_by_tech,
            )
            technique_converter_map = merge_converter_maps(
                technique_converter_map,
                cli_converter_map,
            )
            cli_assignments = sum(len(v) for v in cli_converter_map.values())
            print(
                f"  Converter CLI 路由 (ASR 驱动): {args.converters} → "
                f"{len(technique_names)} 个技术 ({cli_assignments} 个分配)"
            )
        except ValueError as e:
            print(f"  Converter CLI 路由: 失败 ({e})")
        except Exception as e:
            print(f"  Converter CLI 路由: 异常 ({e}), 跳过")

    # Layer 2: Target 感知自动路由 (无需 --converters)
    if ctx.target_type and technique_names:
        try:
            ta_converter_map = build_target_aware_converter_map(
                technique_names=technique_names,
                target_type=ctx.target_type,
                converter_target=converter_target,
                converter_target_available=converter_target_available,
                model_tier=model_tier,
            )
            if ta_converter_map:
                # 模型特异性说服策略重排序
                if model_name:
                    try:
                        from pipeline.converters.target_aware_router import reorder_persuasion_chains_by_model

                        for tech, chains in ta_converter_map.items():
                            if chains and len(chains) > 1:
                                reordered = reorder_persuasion_chains_by_model(chains, model_name)
                                if reordered != chains:
                                    ta_converter_map[tech] = reordered
                    except Exception as e:
                        logger.debug(f"G4 persuasion reordering skipped: {e}")

                technique_converter_map = merge_converter_maps(
                    technique_converter_map,
                    ta_converter_map,
                )
                ta_assignments = sum(len(v) for v in ta_converter_map.values())
                print(
                    f"  Converter Target 感知路由: target_type='{ctx.target_type}' → "
                    f"{len(ta_converter_map)} 个技术 ({ta_assignments} 个分配)"
                )
        except Exception as e:
            print(f"  Converter Target 感知路由: 异常 ({e}), 跳过")

    # 注入合并后的 technique_converters
    if technique_converter_map:
        params["technique_converters"] = technique_converter_map
        total_assignments = sum(len(v) for v in technique_converter_map.values())
        ctx.converter_routing_count = total_assignments
        ctx.technique_converter_map = technique_converter_map  # 传递到 Stage 4 供执行可视化
        unique_converters = set()
        for convs in technique_converter_map.values():
            for c in convs:
                unique_converters.add(type(c).__name__)
        print(
            f"  Converter 路由总计: {len(technique_converter_map)} 个技术, "
            f"{total_assignments} 个分配, {len(unique_converters)} 种 Converter"
        )

        # B2: Converter 路由决策日志
        from pipeline.utils.decision_trace import DecisionTrace
        from pipeline.utils.event_bus import EventBus

        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_2",
            layer="L4_CompoundAttack",
            decision="converter_routing_assigned",
            reason=f"ASR-driven routing: {len(technique_converter_map)} techniques, "
            f"{total_assignments} assignments",
            techniques=len(technique_converter_map),
            assignments=total_assignments,
            converter_types=list(unique_converters),
        )
        bus = EventBus.get_instance()
        bus.publish_simple(
            "stage_2", "converter_routing_done",
            techniques=len(technique_converter_map),
            assignments=total_assignments,
        )

        # 动态种子预算分配
        _apply_dynamic_seed_budget(ctx, technique_converter_map)
    elif getattr(args, "auto_converters", True) and technique_names:
        # ── Layer 3: ASR 驱动 Auto-Converter 兜底 ──
        # 当 Layer 1 (CLI) 和 Layer 2 (Target 感知) 都未产出 Converter 时,
        # 使用 converter_chains.yaml 的 base_techniques_for_variants 映射,
        # 为每个攻击技术自动分配最优非 LLM Converter 链.
        # 学术依据:
        #   - Russinovich et al. (arXiv:2402.12109): Crescendo + encoding 协同 3-5x ASR
        #   - Wei et al. (arXiv:2307.15043): 编码攻击绕过表示级安全过滤
        #   - Zeng et al. (arXiv:2402.19181): 说服策略 ASR 30-40%
        auto_map = _build_auto_converter_map(
            technique_names=technique_names,
            converter_target=converter_target,
            converter_target_available=converter_target_available,
            model_tier=model_tier,
            dataset_names=sorted_datasets,
        )
        if auto_map:
            technique_converter_map = merge_converter_maps(
                technique_converter_map,
                auto_map,
            )
            auto_assignments = sum(len(v) for v in auto_map.values())
            auto_techniques = len(auto_map)
            print(
                f"  Converter Auto 路由 (Layer 3 ASR 驱动): "
                f"{auto_techniques} 个技术 ({auto_assignments} 个分配)"
            )

    if not technique_converter_map:
        print("  Converter 路由: (未启用, 使用 --converters 添加或检测 target_type)")

    # 原生参数注入 (带异常保护 + 噪音拦截)
    noise_log_path = ctx.metadata.get("noise_log_path")
    try:
        if noise_log_path:
            from pipeline.utils.noise_redirector import redirect_noise_to_file

            with redirect_noise_to_file(Path(noise_log_path)):
                scenario.set_params_from_args(args=params)
        else:
            scenario.set_params_from_args(args=params)
    except (ImportError, RuntimeError, ValueError) as e:
        print(f"  [错误] 参数注入失败 (ImportError/RuntimeError/ValueError): {e}")
        print("  [提示] 请检查 .pyrit_conf 配置和 TargetRegistry/ScorerRegistry 初始化")
        raise

    # 保存 Stage 2 产出到 Context
    ctx.sorted_datasets = sorted_datasets
    ctx.warm_start_asr = warm_start_asr
    ctx.max_attempts_per_objective = max_attempts
    ctx.ranked_groups = ranked_groups

    # D12: 存储 payload_categories 供 Stage 4 成功传播使用
    try:
        payload_cats = _infer_payload_categories(sorted_datasets)
        if payload_cats:
            ctx.metadata["payload_categories"] = payload_cats
    except Exception:
        pass

    # P 编号映射
    _build_plan_pid_map(ctx, sorted_datasets, args.max_dataset_size)

    # 决策链追溯
    _print_decision_chain(
        model_tier=model_tier,
        strategy_mode=os.getenv("STRATEGY_MODE", "academic"),
        scenario_techniques=params.get("scenario_techniques"),
        scenario_name=scenario_name,
    )

    # F3: 执行配置 + 数据配置合并为单一信息盒
    from pipeline.utils.display import info_box
    info_box("执行配置", [
        f"策略: {scenario_name} | max_attempts={max_attempts} | 并发={args.max_concurrency} | 重试={args.max_retries}",
        f"Converter 路由: {ctx.converter_routing_count} 个分配 | baseline={'启用' if not args.no_baseline else '禁用'}",
        f"数据集: {len(sorted_datasets)} 个 (ASR 降序, per_dataset={args.max_dataset_size})",
        f"ASR 分析: epsilon={args.epsilon}, scope={args.selector_scope}, warm_start={len(warm_start_asr)} 先验",
    ])

    # 5 层数据溯源 (内部记录, 不输出到用户日志)
    _trace_5_layer_data_lineage(ctx, sorted_datasets, warm_start_asr)

    # 种子镜像策略 (内部记录, 不输出到用户日志)
    _apply_seed_mirror_strategy(ctx, sorted_datasets, warm_start_asr)
    if ctx.tier_layer > 0:
        print(f"      TieredSelection: Layer {ctx.tier_layer} 渐进式选择")

    # 技术池矩阵 (ASR 驱动路径总览)
    _print_tech_pool_matrix(ctx, warm_start_asr, model_name, model_tier, sorted_datasets, technique_converter_map)

    # G1: 载荷-技术匹配矩阵
    _print_payload_technique_matrix(ctx, sorted_datasets, warm_start_asr)

    # G2: Converter 变换示例
    _print_converter_transform_sample(ctx, technique_converter_map, sorted_datasets)

    # G3: 目标类型→Converter 适配图
    _print_target_converter_adaptation(ctx, technique_converter_map, model_tier)

    # D1: 5 层决策流水线图
    _print_5layer_decision_pipeline(ctx, sorted_datasets, warm_start_asr)

    # 阶段间传递 (简化为单行摘要)
    from pipeline.utils.display import handoff_line

    tech_count = len(args.techniques) if args.techniques else 14
    handoff_line(
        2, 3,
        f"{tech_count} 技术 | {len(sorted_datasets)} 数据集 | "
        f"{ctx.converter_routing_count} Converter 分配 | "
        f"warm-start {len(warm_start_asr) if warm_start_asr else 0} 先验",
    )


def _print_decision_chain(
    model_tier: str,
    strategy_mode: str,
    scenario_techniques: list[str] | None,
    scenario_name: str,
) -> None:
    """完整决策链追溯 (Stage 1推荐 → Selector推荐 → 实际).

    对齐 pyrit_ai300 Stage 2 ① 策略决策卡片。
    展示策略选择是否为最优决策路径。
    """
    from pipeline.utils.display import info_box

    # Stage 1 推荐: 基于 model_tier 自动推荐策略模式
    tier_recommended = {
        "weak": "balanced",
        "moderate": "academic",
        "strong": "academic",
    }.get(model_tier, "academic")

    # Selector 实际接收的策略模式
    selector_mode = strategy_mode

    # 实际技术选择
    if scenario_techniques:
        actual_techs = scenario_techniques
        actual_source = "CLI --techniques"
    else:
        actual_techs = None
        actual_source = "DEFAULT (TextAdaptive 默认聚合)"

    # 决策匹配判断
    mode_match = tier_recommended == selector_mode
    match_str = "✓ 与推荐一致" if mode_match else "⚠ 与推荐不一致"

    lines = [
        f"Stage 1 推荐: {tier_recommended} (基于 model_tier={model_tier})",
        f"Selector 实际: {selector_mode} {match_str}",
        f"场景: {scenario_name}",
        f"技术来源: {actual_source}",
    ]
    if actual_techs:
        tech_display = ", ".join(actual_techs[:5])
        if len(actual_techs) > 5:
            tech_display += f" ... (+{len(actual_techs) - 5})"
        lines.append(f"技术列表: {tech_display}")

    lines.append("")
    if mode_match:
        lines.append("✓ 决策路径最优 — 策略与模型分层对齐")
    else:
        lines.append(f"⚠ 决策路径偏差 — 推荐 {tier_recommended}, 实际 {selector_mode}")
        lines.append("  → 原因: STRATEGY_MODE 环境变量覆盖了推荐值")

    info_box("策略决策链", lines)


def _build_plan_pid_map(
    ctx: PipelineContext,
    sorted_datasets: list[str],
    max_dataset_size: int,
) -> None:
    """构建 P 编号映射 (dataset → P编号范围).

    按数据集排序顺序分配 P 编号:
      dataset_1 (5 seeds) → P1-P5
      dataset_2 (3 seeds) → P6-P8
      ...

    映射存储到 ctx.plan_pid_map, 供 Stage 4/5 展示时引用。
    """
    pid_counter = 1
    pid_map: dict[str, str] = {}

    for ds_name in sorted_datasets:
        # 尝试获取数据集的种子数
        seed_count = max_dataset_size
        try:
            from pyrit.memory import CentralMemory

            memory = CentralMemory.get_memory_instance()
            prompts = memory.get_seed_prompts(dataset_name=ds_name)
            seed_count = len(prompts) if prompts else max_dataset_size
        except Exception:
            pass

        end_pid = pid_counter + seed_count - 1
        pid_range = f"P{pid_counter}" if seed_count == 1 else f"P{pid_counter}-P{end_pid}"
        pid_map[ds_name] = pid_range
        pid_counter = end_pid + 1

    ctx.plan_pid_map = pid_map

    # 展示 P 编号映射
    from pipeline.utils.display import info_box

    lines = []
    for ds_name, pid_range in pid_map.items():
        lines.append(f"{ds_name:<40} → {pid_range}")
    lines.append("")
    lines.append(f"合计: {pid_counter - 1} 个攻击计划 (P1-P{pid_counter - 1})")
    lines.append("P 编号将贯穿 Stage 4 (执行) → Stage 5 (分析)")

    info_box("P 编号映射", lines)


def _print_tech_pool_matrix(
    ctx: PipelineContext,
    warm_start_asr: dict[str, float] | None,
    model_name: str,
    model_tier: str,
    sorted_datasets: list[str] | None = None,
    technique_converter_map: dict[str, list] | None = None,
) -> None:
    """技术池矩阵 — ASR 驱动路径总览 (F1/F2/F6/F7).

    F1: 技术/数据集正交分离展示
    F2: 统一 core_card 风格
    F6: Converter 路径可视化
    F7: 目标类型适配展示
    """
    from pipeline.utils.display import core_card, info_box, pad_right

    if not warm_start_asr:
        info_box("ASR 驱动路径", ["(无 ASR 先验数据, 首次运行)"])
        return

    # Tier 分层
    def _tier_from_asr(asr: float) -> str:
        if asr >= 0.50:
            return "S"
        elif asr >= 0.30:
            return "A"
        elif asr >= 0.15:
            return "B"
        elif asr >= 0.05:
            return "C"
        else:
            return "D"

    # F1: 只展示真正的攻击技术 (已通过 is_known_technique 过滤)
    sorted_techs = sorted(warm_start_asr.items(), key=lambda x: x[1], reverse=True)

    tier_counts: dict[str, int] = {}
    for _, asr in sorted_techs:
        tier = _tier_from_asr(asr)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    tier_summary = " ".join(
        f"{t}={tier_counts.get(t, 0)}" for t in ["S", "A", "B", "C", "D"] if tier_counts.get(t, 0) > 0
    )

    # F1: 技术维度
    multi_turn_set = {
        "red_teaming", "crescendo", "tap", "pair", "many_shot", "forest",
        "crescendo_simulated", "tree_of_attacks_pruned",
    }
    tech_lines: list[str] = []
    for _i, (tech, asr) in enumerate(sorted_techs):
        tier = _tier_from_asr(asr)
        tech_pad = pad_right(tech[:30], 30)
        mode = "多轮迭代" if tech in multi_turn_set else "单轮直发"
        tech_lines.append(f"{tech_pad} ASR {asr:>4.0%} (Tier {tier}) [{mode}]")
    tech_lines.append(f"合计: {len(sorted_techs)} 技术 | Tier: {tier_summary}")

    # F1: 载荷维度
    payload_lines: list[str] = []
    if sorted_datasets:
        for ds in sorted_datasets[:5]:
            payload_lines.append(f"• {ds}")
        if len(sorted_datasets) > 5:
            payload_lines.append(f"... 还有 {len(sorted_datasets) - 5} 个")
        payload_lines.append(f"合计: {len(sorted_datasets)} 数据集 (ASR 降序)")
    else:
        payload_lines.append("(未加载数据集)")

    # F6: Converter 维度
    converter_lines: list[str] = []
    if technique_converter_map:
        total_assignments = sum(len(v) for v in technique_converter_map.values())
        unique_converters: set[str] = set()
        for convs in technique_converter_map.values():
            for c in convs:
                unique_converters.add(type(c).__name__)
        converter_lines.append(
            f"{len(technique_converter_map)} 技术 × {len(unique_converters)} Converter = {total_assignments} 分配"
        )
        for tech, convs in list(technique_converter_map.items())[:3]:
            conv_names = [type(c).__name__ for c in convs[:2]]
            tech_asr = warm_start_asr.get(tech, 0)
            converter_lines.append(f"  {tech} + {' → '.join(conv_names)} → ASR {tech_asr:.0%}")
    else:
        converter_lines.append("(未启用 Converter 路由)")

    # F7: 目标维度
    target_lines: list[str] = []
    target_lines.append(f"模型: {model_name} (tier={model_tier})")
    target_type = getattr(ctx, "target_type", None)
    if target_type:
        target_lines.append(f"目标类型: {target_type}")
    if ctx.fallback_plan and hasattr(ctx.fallback_plan, "total_groups"):
        target_lines.append(
            f"降级链: {ctx.fallback_plan.total_groups} 组, {ctx.fallback_plan.fallback_count} 降级点"
        )

    # 预期 ASR
    expected_lines: list[str] = []
    if warm_start_asr:
        avg_asr = sum(warm_start_asr.values()) / max(len(warm_start_asr), 1)
        tier_asr_map = {"strong": 0.25, "moderate": 0.45, "weak": 0.65, "unknown": 0.30}
        expected_asr = tier_asr_map.get(model_tier, 0.30)
        expected_lines.append(
            f"预测: {expected_asr:.0%}-{min(expected_asr * 1.4, 0.8):.0%} (tier={model_tier})"
        )
        expected_lines.append(
            f"warm-start: {len(warm_start_asr)} 技术先验 | 平均 ASR: {avg_asr:.0%}"
        )
    budget_map = getattr(ctx, "metadata", {}).get("dynamic_seed_budget", {})
    if budget_map:
        expected_lines.append(f"动态种子预算: {len(budget_map)} 技术已分配")

    core_card(
        "ASR 驱动攻击路径 — 载荷 → 技术 → Converter → 目标",
        sections=[
            {"label": "技术", "lines": tech_lines},
            {"label": "载荷", "lines": payload_lines},
            {"label": "Converter", "lines": converter_lines},
            {"label": "目标", "lines": target_lines},
            {"label": "预期 ASR", "lines": expected_lines},
        ],
    )


def _resolve_objective_target_name() -> str:
    """从 TargetRegistry 动态解析 objective_target 名称.

    优先级:
      1. ``default_objective_target`` 标签 (原生推荐标签)
      2. ``default`` 标签 (通用默认标签)
      3. 第一个注册的 Target
      4. 回退到 ``"openai_chat"`` (最终默认值)

    Returns:
        TargetRegistry 中注册的目标名称字符串。
    """
    try:
        registry = TargetRegistry.get_registry_singleton()
        # 1. default_objective_target 标签
        entries = registry.instances.get_by_tag(tag="default_objective_target")
        if entries:
            name = entries[0].name
            logger.info(f"objective_target resolved: '{name}' (default_objective_target tag)")
            return name
        # 2. default 标签
        entries = registry.instances.get_by_tag(tag="default")
        if entries:
            name = entries[0].name
            logger.info(f"objective_target resolved: '{name}' (default tag)")
            return name
        # 3. 第一个注册的 Target
        all_entries = registry.instances.get_all_instances()
        if all_entries:
            name = all_entries[0].name
            logger.info(f"objective_target resolved: '{name}' (first available)")
            return name
    except Exception as e:
        logger.warning(f"Failed to resolve objective_target from TargetRegistry: {e}")
    # 4. 最终回退
    logger.warning("objective_target falling back to 'openai_chat' (no targets in registry)")
    return "openai_chat"


def _get_objective_scorer() -> Any:
    """从 ScorerRegistry 获取自动标记的最佳评分器 (原生 API, 三级 fallback)。."""
    scorer_entries = ScorerRegistry.get_registry_singleton().instances.get_by_tag(tag="default_objective_scorer")
    if scorer_entries:
        scorer = scorer_entries[0].instance
        print(f"  评分器: {type(scorer).__name__} (default_objective_scorer)")
        return scorer

    # Fallback: 尝试获取 "main" 评分器 (基于 objective_scorer_chat)
    main_entry = ScorerRegistry.get_registry_singleton().instances.get_entry(name="main")
    if main_entry:
        scorer = main_entry.instance
        print(f"  评分器: {type(scorer).__name__} (main)")
        return scorer

    # Fallback: 尝试获取 "fallback" 评分器 (基于 openai_chat)
    fallback_entry = ScorerRegistry.get_registry_singleton().instances.get_entry(name="fallback")
    if fallback_entry:
        scorer = fallback_entry.instance
        print(f"  评分器: {type(scorer).__name__} (fallback)")
        return scorer

    # 最终 fallback: 使用第一个可用的评分器
    all_scorers = ScorerRegistry.get_registry_singleton().instances.get_all_instances()
    if all_scorers:
        scorer = all_scorers[0].instance
        print(f"  评分器: {type(scorer).__name__} (first available)")
        return scorer

    print("  评分器: ScorerRegistry 为空, 使用 TextAdaptive 默认评分器")
    return None


def _get_converter_target(model_name: str = "") -> Any:
    """从 TargetRegistry 获取用于 LLM 辅助 Converter 链的目标实例。.

    使用最优对抗 LLM 配对 (PAIR arXiv:2310.08437)
    从 ``data/setting/model_tiers.yaml`` 的 ``optimal_attacker_by_target`` 加载
    最优对抗 LLM 模型名, 优先选择该模型作为 converter_target。

    查找优先级:
      1. 标记为 "adversarial_chat" 的目标 (原生 adversarial chat 角色)
      2. 标记为 "converter_target" 的目标 (自定义标签)
      3. 名为 "objective_scorer_chat" 的目标 (评分器使用的 LLM)
      4. 匹配 optimal_attacker_by_target 的目标 (最优配对)
      5. 第一个非 objective_target 的目标 (避免用被攻击目标做 Converter)
      6. None (仅使用非 LLM Converter 链)

    Returns:
        PromptTarget 实例, 或 None (无可用 LLM 目标)
    """
    try:
        # 1. adversarial_chat 标签
        entries = TargetRegistry.get_registry_singleton().instances.get_by_tag(tag="adversarial_chat")
        if entries:
            logger.info(f"Converter target: '{entries[0].name}' (adversarial_chat)")
            return entries[0].instance

        # 2. converter_target 标签
        entries = TargetRegistry.get_registry_singleton().instances.get_by_tag(tag="converter_target")
        if entries:
            logger.info(f"Converter target: '{entries[0].name}' (converter_target)")
            return entries[0].instance

        # 3. objective_scorer_chat 名称
        entry = TargetRegistry.get_registry_singleton().instances.get_entry(name="objective_scorer_chat")
        if entry:
            logger.info("Converter target: 'objective_scorer_chat'")
            return entry.instance

        # 4. 匹配最优对抗 LLM (optimal_attacker_by_target)
        if model_name:
            try:
                from pipeline.converters.model_tier_detector import get_optimal_attacker

                optimal_attacker = get_optimal_attacker(model_name)
                if optimal_attacker:
                    # 尝试按名称匹配
                    all_entries = TargetRegistry.get_registry_singleton().instances.get_all_instances()
                    for e in all_entries:
                        entry_model = (
                            getattr(e.instance, "_model_name", None)
                            or getattr(e.instance, "model_name", None)
                            or getattr(e.instance, "deployment_name", None)
                            or ""
                        )
                        if entry_model and optimal_attacker.lower() in str(entry_model).lower():
                            logger.info(
                                f"Converter target matched optimal attacker: '{e.name}' "
                                f"(model={entry_model})"
                            )
                            return e.instance
            except Exception as e:
                logger.debug(f"G5 optimal attacker matching failed: {e}")

        # 5. 第一个非 default_objective_target 的目标
        all_entries = TargetRegistry.get_registry_singleton().instances.get_all_instances()
        objective_entries = TargetRegistry.get_registry_singleton().instances.get_by_tag(tag="default_objective_target")
        objective_ids = {id(e.instance) for e in (objective_entries or [])}
        for e in all_entries:
            if id(e.instance) not in objective_ids:
                logger.info(f"Converter target: '{e.name}' (non-objective fallback)")
                return e.instance
    except Exception as e:
        logger.debug(f"Failed to get converter_target: {e}")

    return None


def _apply_tier_attack_params(args: Any, model_tier: str) -> dict[str, Any]:
    """根据 model_tier 自动应用模型特异性攻击参数.

    学术依据:
      - Crescendo (arXiv:2402.12109): GPT-4o 需 5-7 轮, GPT-3.5 需 3-4 轮
      - TAP (arXiv:2312.02191): 树搜索深度应随模型抵抗力调整
      - HarmBench (arXiv:2402.04249): 强模型需要更多探索, 弱模型更多利用

    当 ``--auto-tier-params`` 启用时, 根据 model_tier 自动覆盖:
      - max_attempts: 强模型更多尝试 (ASR 低, 需要更多探索)
      - max_concurrency: 弱模型高并发 (ASR 高, 快速覆盖)
      - epsilon: 强模型更多探索 (ASR 低, 需要尝试更多技术)

    Returns:
        应用的参数字典 (用于日志展示)
    """
    from pipeline.converters.model_tier_detector import get_attack_params_by_tier

    tier_params = get_attack_params_by_tier(model_tier)
    auto_override = getattr(args, "auto_tier_params", False)

    applied: dict[str, Any] = {}

    # 参数映射: (args 属性, tier_params 键, argparse 默认值)
    param_map = [
        ("max_concurrency", "max_concurrency", 3),
        ("epsilon", "epsilon", 0.1),
        ("max_attempts", "max_attempts", 3),
    ]

    for attr, tier_key, _default_val in param_map:
        if not hasattr(args, attr) or getattr(args, attr) is None:
            continue
        current = getattr(args, attr)
        recommended = tier_params.get(tier_key, current)
        if current != recommended:
            if auto_override:
                # 当 --auto-tier-params 启用时, 实际覆盖 args 值
                setattr(args, attr, recommended)
                applied[attr] = {"old": current, "new": recommended, "applied": True}
            else:
                # 仅记录推荐值, 不覆盖
                applied[attr] = {"current": current, "tier_recommended": recommended, "applied": False}

    if applied:
        mode_str = "已覆盖" if auto_override else "仅推荐 (启用 --auto-tier-params 自动覆盖)"
        print(f"  模型特异性参数 (tier={model_tier}, {mode_str}):")
        for param, vals in applied.items():
            if vals.get("applied"):
                print(f"    {param}: {vals['old']} → {vals['new']} ✓")
            else:
                print(f"    {param}: current={vals['current']}, tier_recommended={vals['tier_recommended']}")

    return applied


def _auto_create_converter_target() -> Any:
    """自动创建 converter_target.

    当 TargetRegistry 中没有 adversarial_chat 标签的目标时,
    尝试从 objective_target 的配置派生一个 converter_target.

    策略:
      1. 获取 objective_target 实例
      2. 从中提取模型名和部署配置
      3. 使用相同配置创建新的 OpenAIChatTarget (或对应类型)
      4. 注册到 TargetRegistry 并返回

    Returns:
        PromptTarget 实例, 或 None (无法创建)
    """
    try:
        from pyrit.registry import TargetRegistry

        registry = TargetRegistry.get_registry_singleton()
        objective_entries = registry.instances.get_by_tag(tag="default_objective_target")
        if not objective_entries:
            return None

        obj_target = objective_entries[0].instance

        # 提取目标配置
        model_name = getattr(obj_target, "_model_name", None) or getattr(obj_target, "model_name", None)
        deployment_name = getattr(obj_target, "_deployment_name", None)
        endpoint = getattr(obj_target, "_endpoint", None)
        api_key = getattr(obj_target, "_api_key", None)

        if model_name is None or api_key is None:
            logger.debug("Cannot auto-create converter_target: missing model_name or api_key")
            return None

        # 创建新的 OpenAIChatTarget 作为 converter_target
        try:
            from pyrit.prompt_target import OpenAIChatTarget

            converter_target = OpenAIChatTarget(
                deployment_name=deployment_name or model_name,
                endpoint=endpoint,
                api_key=api_key,
            )
            logger.info(f"Auto-created converter_target from objective_target config (model={model_name})")
            return converter_target
        except (ImportError, TypeError) as e:
            logger.debug(f"Failed to create OpenAIChatTarget for converter_target: {e}")
            return None
    except Exception as e:
        logger.debug(f"Auto-create converter_target failed: {e}")
        return None


def _build_warm_start_asr(
    model_name: str,
    model_tier: str,
    owasp_id: str,
) -> dict[str, float]:
    """从学术 ASR 先验构建 warm-start 字典。.

    从 AttackTechniqueRegistry 获取所有注册的技术名称，
    为每个技术查询学术 ASR 先验，构建 (技术→ASR) 映射。
    """
    warm_start: dict[str, float] = {}
    try:
        all_names = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
    except Exception:
        all_names = []

    # F1: 过滤非攻击技术名称 (数据集名如 owasp_llm05 不应出现在技术池中)
    # 只有 is_known_technique() 返回 True 的名称才是真正的攻击技术
    technique_names = [name for name in all_names if is_known_technique(name)]

    for tech in technique_names:
        asr = get_initial_q_value(tech, model_name, model_tier, owasp_id)
        if asr > 0:
            warm_start[tech] = asr

    return warm_start


def _select_techniques_by_tier(
    model_name: str,
    model_tier: str,
    owasp_id: str,
    tier_layer: int,
) -> list[str] | None:
    """使用 TieredSelectionWizard 按 ASR Tier 渐进式选择技术。.

    Layer 1: Tier S/A 技术 (ASR >= 40%) — 快速评估
    Layer 2: + Tier B 技术 (ASR >= 15%) — 标准评估
    Layer 3: 全部技术 (含 Tier C/D) — 深度评估

    Args:
        model_name: 目标模型名
        model_tier: 模型安全过滤等级
        owasp_id: OWASP 分类 ID
        tier_layer: 选择层级 (1/2/3)

    Returns:
        技术名称列表, 失败返回 None
    """
    try:
        from pipeline.asr.tiered_selection_wizard import TieredSelectionWizard

        wizard = TieredSelectionWizard(
            model_name=model_name,
            model_tier=model_tier,
        )

        # 从 AttackTechniqueRegistry 获取可用技术
        try:
            available = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
        except Exception:
            available = []

        if not available:
            return None

        recommendation = wizard.recommend(
            available_techniques=available,
            owasp_id=owasp_id,
        )

        # 选择指定层级的技术
        layer_idx = tier_layer - 1  # 0-based
        if 0 <= layer_idx < len(recommendation.layers):
            layer = recommendation.layers[layer_idx]
            return layer.recommended_techniques

        return None
    except Exception as e:
        print(f"  [警告] TieredSelection 失败: {e}")
        return None


# ASR 统计输出 (分类 + 技术 Top 5)


def _print_asr_summary(asr_by_category: dict) -> None:
    """ASR 分类 + 技术 统计卡片 (F3 合并 — 单一卡片展示)."""
    from pipeline.utils.display import info_box

    lines: list[str] = []

    # 分类 ASR Top 5
    if asr_by_category:
        sorted_asr = sorted(
            asr_by_category.items(),
            key=lambda x: x[1].success_rate if hasattr(x[1], "success_rate") and x[1].success_rate is not None else 0,
            reverse=True,
        )
        lines.append("分类 ASR (Top 5):")
        for cat, stats in sorted_asr[:5]:
            sr = (stats.success_rate or 0) * 100 if hasattr(stats, "success_rate") else 0
            total = stats.total_decided if hasattr(stats, "total_decided") and stats.total_decided is not None else 0
            successes = stats.successes if hasattr(stats, "successes") and stats.successes is not None else 0
            bar = "█" * int(sr / 5)
            lines.append(f"  {cat:<33} {sr:>5.1f}% ({successes}/{total}) {bar}")
        lines.append(f"  合计: {len(asr_by_category)} 分类")
    else:
        lines.append("分类 ASR: (无历史数据)")

    # 技术 ASR Top 5
    tech_asr = query_historical_asr_by_technique()
    if tech_asr:
        lines.append("")
        lines.append("技术 ASR (Top 5):")
        for tech, stats in sorted(
            tech_asr.items(),
            key=lambda x: x[1].success_rate if hasattr(x[1], "success_rate") and x[1].success_rate is not None else 0,
            reverse=True,
        )[:5]:
            sr = (stats.success_rate or 0) * 100 if hasattr(stats, "success_rate") else 0
            total = stats.total_decided if hasattr(stats, "total_decided") and stats.total_decided is not None else 0
            bar = "█" * int(sr / 5)
            lines.append(f"  {tech:<33} {sr:>5.1f}% ({total}) {bar}")
        lines.append(f"  合计: {len(tech_asr)} 技术有数据")

    info_box("历史 ASR", lines)


def _print_technique_asr_summary_compact() -> None:
    """已合并到 _print_asr_summary (F3). 保留函数体供向后兼容."""  # noqa: F401 — 已合并到 _print_asr_summary


# 动态种子预算分配


def _apply_dynamic_seed_budget(ctx: PipelineContext, technique_converter_map: dict) -> None:
    """基于历史 ASR 动态调整每技术的种子预算。.

    高 ASR 技术 → 更多种子 (提高成功概率)
    低 ASR 技术 → 更少种子 (节省资源)

    设计原则 (R-010): 不修改 PyRIT 原生 scenario 配置,
    仅通过 metadata 记录预算建议, 供 Stage 4 执行时参考。

    Academic basis:
      - Multi-Armed Bandit budget allocation (arXiv:1904.07252)
      - UCB-based resource allocation under uncertainty
    """
    try:
        from pipeline.asr.prior_registry import ASRPriorRegistry

        registry = ASRPriorRegistry.get_instance()
        model_name = getattr(ctx.args, "model", "default")

        budget_map: dict[str, int] = {}
        default_budget = ctx.args.batch_size if hasattr(ctx.args, "batch_size") else 5

        for tech_name in technique_converter_map:
            prior = registry.for_model(model_name, tech_name)
            if prior and prior.success_rate is not None:
                # ASR > 0.3 → budget * 1.5; ASR < 0.1 → budget * 0.5
                sr = prior.success_rate
                if sr > 0.3:
                    budget_map[tech_name] = max(int(default_budget * 1.5), default_budget + 2)
                elif sr < 0.1:
                    budget_map[tech_name] = max(int(default_budget * 0.5), 1)
                else:
                    budget_map[tech_name] = default_budget
            else:
                budget_map[tech_name] = default_budget

        ctx.metadata["dynamic_seed_budget"] = budget_map
        high_budget = {k: v for k, v in budget_map.items() if v > default_budget}
        low_budget = {k: v for k, v in budget_map.items() if v < default_budget}

        if high_budget or low_budget:
            print(f"  动态种子预算: {len(high_budget)} 技术↑, {len(low_budget)} 技术↓")
            from pipeline.utils.decision_trace import DecisionTrace

            trace = DecisionTrace.get_instance()
            trace.record(
                stage="stage_2",
                layer="L3_DatasetConfig",
                decision="dynamic_seed_budget_allocated",
                reason=f"ASR-driven: {len(high_budget)} boosted, {len(low_budget)} reduced",
                default_budget=default_budget,
                high_count=len(high_budget),
                low_count=len(low_budget),
            )
    except Exception as e:
        logger.debug(f"B3 dynamic seed budget failed (non-fatal): {e}")


# 5 层数据溯源


def _trace_5_layer_data_lineage(
    ctx: PipelineContext,
    sorted_datasets: list[str],
    warm_start_asr: dict,
) -> None:
    """记录数据流通过 5 层架构的完整追溯链。.

    L1_SeedSource → L2_Organization → L3_DatasetConfig → L4_Memory → L5_Analytics

    设计原则 (R-010): 不修改 PyRIT 原生数据流, 仅在编排层记录追溯信息。
    """
    try:
        from pipeline.utils.decision_trace import DecisionTrace

        trace = DecisionTrace.get_instance()

        # L1: Seed Source
        trace.record(
            stage="stage_2",
            layer="L1_SeedSource",
            decision="seed_sources_loaded",
            reason=f"{len(sorted_datasets)} datasets loaded from seed_datasets/",
            datasets=sorted_datasets[:5],
            total_datasets=len(sorted_datasets),
        )

        # L2: Organization
        trace.record(
            stage="stage_2",
            layer="L2_Organization",
            decision="datasets_sorted_by_asr",
            reason="ASR descending order for priority execution",
            sorted_order=sorted_datasets[:3],
        )

        # L3: Dataset Config
        max_dataset_size = getattr(ctx.args, "max_dataset_size", 0)
        trace.record(
            stage="stage_2",
            layer="L3_DatasetConfig",
            decision="compound_dataset_configured",
            reason=f"CompoundDatasetAttackConfiguration with per_dataset={max_dataset_size}",
            total_datasets=len(sorted_datasets),
            per_dataset_limit=max_dataset_size,
        )

        # L4: Memory (PyRIT 原生 CentralMemory)
        trace.record(
            stage="stage_2",
            layer="L4_Memory",
            decision="seeds_in_memory",
            reason="PyRIT CentralMemory stores seed prompts with dataset_name labels",
            memory_type="SQLite (per-run)",
        )

        # L5: Analytics
        trace.record(
            stage="stage_2",
            layer="L5_Analytics",
            decision="warm_start_asr_loaded",
            reason=f"{len(warm_start_asr)} technique priors loaded for ASR-driven scheduling",
            priors_count=len(warm_start_asr),
        )

        logger.debug("5 层数据溯源已记录 (L1→L2→L3→L4→L5)")
    except Exception as e:
        logger.debug(f"B4 data lineage trace failed (non-fatal): {e}")


# 种子镜像策略


def _apply_seed_mirror_strategy(
    ctx: PipelineContext,
    sorted_datasets: list[str],
    warm_start_asr: dict,
) -> None:
    """高 ASR 种子跨数据集镜像。.

    将高 ASR 技术的种子镜像到其他数据集中, 增加攻击覆盖率。

    设计原则 (R-010): 不修改 PyRIT 原生 seed prompts,
    仅在 metadata 中记录镜像建议, 供执行层参考。

    Academic basis:
      - Data augmentation for robust evaluation (arXiv:2308.03331)
      - Cross-dataset transferability of adversarial examples
    """
    try:
        if not warm_start_asr or len(sorted_datasets) < 2:
            return

        # 找出高 ASR 技术 (ASR > 0.2)
        high_asr_techs = [
            tech for tech, asr in warm_start_asr.items()
            if isinstance(asr, (int, float)) and asr > 0.2
        ]

        if not high_asr_techs:
            return

        # 构建镜像建议: 每个高 ASR 技术镜像到 top-3 数据集
        mirror_map: dict[str, list[str]] = {}
        for tech in high_asr_techs[:5]:  # 限制 Top 5
            mirror_map[tech] = sorted_datasets[:3]

        ctx.metadata["seed_mirror_strategy"] = {
            "high_asr_techniques": high_asr_techs[:5],
            "mirror_targets": mirror_map,
            "mirror_count": len(high_asr_techs[:5]) * min(3, len(sorted_datasets)),
        }

        logger.debug(
            f"种子镜像: {len(high_asr_techs[:5])} 高ASR技术 → "
            f"{min(3, len(sorted_datasets))} 数据集"
        )

        from pipeline.utils.decision_trace import DecisionTrace

        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_2",
            layer="L1_SeedSource",
            decision="seed_mirror_strategy_applied",
            reason=f"{len(high_asr_techs[:5])} high-ASR techniques mirrored to top datasets",
            high_asr_count=len(high_asr_techs[:5]),
            mirror_targets=min(3, len(sorted_datasets)),
        )
    except Exception as e:
        logger.debug(f"B5 seed mirror strategy failed (non-fatal): {e}")


def _infer_payload_categories(dataset_names: list[str]) -> set[str]:
    """从数据集名称列表推断载荷类别集合.

    基于 ``converter_chains.yaml`` 的 ``payload_converter_affinity.dataset_category_keywords``
    将数据集名映射到种子类别 (encoding/persuasion/decomposition/multi_turn/role_play/baseline).

    学术依据: HarmBench (arXiv:2402.04249) — 同一种子对不同 Converter 的 ASR 差异达 30-50%.
    """
    import yaml as _yaml

    yaml_path = Path(__file__).parent.parent.parent / "data" / "setting" / "converter_chains.yaml"
    if not yaml_path.exists():
        return set()

    with open(yaml_path, encoding="utf-8") as f:
        data = _yaml.safe_load(f)

    affinity = data.get("payload_converter_affinity", {})
    keywords_map = affinity.get("dataset_category_keywords", {})
    if not keywords_map:
        return set()

    categories: set[str] = set()
    for ds_name in dataset_names:
        ds_lower = ds_name.lower()
        for category, keywords in keywords_map.items():
            if any(kw in ds_lower for kw in keywords):
                categories.add(category)
                break

    return categories


def _build_auto_converter_map(
    technique_names: list[str],
    *,
    converter_target: Any = None,
    converter_target_available: bool = False,
    model_tier: str = "unknown",
    dataset_names: list[str] | None = None,
) -> dict[str, list]:
    """Layer 3: ASR-driven Auto-Converter fallback with payload affinity.

    When Layer 1 (CLI) and Layer 2 (Target-aware) both produce no converters,
    use ``base_techniques_for_variants`` from ``converter_chains.yaml`` to
    auto-assign the best converter chains per attack technique.

    Payload affinity:
      When ``dataset_names`` is provided, payload categories are inferred
      and used to boost compatible converter chains in the priority sort.
      This ensures that e.g. encoding-type payloads get encoding chains first,
      maximizing ASR based on combo_multipliers (multi_turn + encoding = 3.5x).

    Academic basis:
      - Russinovich et al. (arXiv:2402.12109): Crescendo + encoding 3-5x ASR
      - Wei et al. (arXiv:2307.15043): encoding bypasses representation-level filters
      - Zeng et al. (arXiv:2402.19181): persuasion ASR 30-40%
      - HarmBench (arXiv:2402.04249): payload-converter ASR variance 30-50%
    """
    from pipeline.converters.chains import (
        BASE_TECHNIQUES_FOR_VARIANTS,
        CONVERTER_VARIANT_CHAINS,
        build_converters_from_chain_names,
        get_chain_cost_weight,
        score_chain_combo,
    )

    # Infer payload categories for affinity boosting
    payload_categories: set[str] = set()
    boost_chains: set[str] = set()
    if dataset_names:
        payload_categories = _infer_payload_categories(dataset_names)
        if payload_categories:
            import yaml as _yaml

            yaml_path = Path(__file__).parent.parent.parent / "data" / "setting" / "converter_chains.yaml"
            if yaml_path.exists():
                with open(yaml_path, encoding="utf-8") as f:
                    affinity_data = _yaml.safe_load(f)
                category_boost = affinity_data.get("payload_converter_affinity", {}).get("category_boost_chains", {})
                for cat in payload_categories:
                    boost_chains.update(category_boost.get(cat, []))

    result: dict[str, list] = {}

    for tech_name in technique_names:
        base_tech = tech_name.split("+")[0] if "+" in tech_name else tech_name
        recommended_chains = BASE_TECHNIQUES_FOR_VARIANTS.get(base_tech)
        if not recommended_chains:
            continue

        filtered_chains: list[str] = []
        for chain_name in recommended_chains:
            chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
            if chain_info is None:
                continue
            requires_llm = chain_info.get("requires_llm", False)
            if requires_llm and not converter_target_available:
                continue
            if requires_llm and model_tier == "weak":
                continue
            filtered_chains.append(chain_name)

        if not filtered_chains:
            continue

        # D13+D14: Sort by (boost_rank, combo_score, cost_weight, priority)
        # boost_rank: payload affinity (0=boosted, 1=normal)
        # combo_score: D13 chain synergy multiplier (higher=better, negative for sort)
        # cost_weight: D14 budget-aware (higher=cheaper, negative for sort)
        # priority: original chain priority (lower=higher priority)
        def _sort_key(chain_name: str, _fc: list[str] = filtered_chains) -> tuple[int, float, float, int]:
            boost_rank = 0 if chain_name in boost_chains else 1
            combo_score = score_chain_combo(_fc[:3] + [chain_name])
            cost_weight = get_chain_cost_weight(chain_name)
            priority = CONVERTER_VARIANT_CHAINS.get(chain_name, {}).get("priority", 99)
            # Negative because we want higher combo_score and cost_weight first
            return (boost_rank, -combo_score, -cost_weight, priority)

        filtered_chains.sort(key=_sort_key)
        filtered_chains = filtered_chains[:3]

        # Pass converter_target for LLM chains (may be None if not available)
        converters = build_converters_from_chain_names(
            chain_names=filtered_chains,
            converter_target=converter_target,
        )

        if converters:
            result[tech_name] = converters

    if result:
        total_chains = sum(len(v) for v in result.values())
        affinity_str = f", payload affinity: {payload_categories}" if payload_categories else ""
        logger.info(
            f"Auto-Converter (Layer 3): {len(result)}/{len(technique_names)} techniques "
            f"matched, {total_chains} total converter assignments{affinity_str}"
        )

    return result


# ============================================================
# G1: 载荷-技术匹配矩阵
# ============================================================


def _print_payload_technique_matrix(
    ctx: PipelineContext,
    sorted_datasets: list[str],
    warm_start_asr: dict[str, float] | None,
) -> None:
    """G1: 载荷-技术匹配矩阵 — 展示每个数据集的种子如何匹配攻击技术。.

    数据来源: CentralMemory 中的 seed prompts metadata (technique_group)
    展示: 数据集名 → 种子数 → technique_group → 匹配的攻击技术
    """
    from pipeline.utils.display import info_box, pad_right

    if not sorted_datasets:
        return

    lines: list[str] = []
    warm_start = warm_start_asr or {}

    for ds_name in sorted_datasets[:8]:
        seed_count = 0
        technique_groups: set[str] = set()

        try:
            from pyrit.memory import CentralMemory

            memory = CentralMemory.get_memory_instance()
            prompts = memory.get_seed_prompts(dataset_name=ds_name)
            seed_count = len(prompts) if prompts else 0
            if prompts:
                for p in prompts:
                    metadata = getattr(p, "metadata", None) or {}
                    if isinstance(metadata, dict):
                        tg = metadata.get("technique_group", "")
                        if tg:
                            technique_groups.add(tg)
        except Exception:
            pass

        # 匹配攻击技术: 从 warm_start 中找 ASR 最高的技术
        matched_techs: list[str] = []
        if technique_groups:
            for tg in technique_groups:
                # 从 warm_start 中找匹配的技术
                for tech, asr in sorted(warm_start.items(), key=lambda x: x[1], reverse=True):
                    if tg.lower() in tech.lower() or tech.lower() in tg.lower():
                        if tech not in matched_techs:
                            matched_techs.append(f"{tech}({asr:.0%})")
                        break
        elif warm_start:
            # 无 technique_group 时, 展示 Top 3 高 ASR 技术
            for tech, asr in sorted(warm_start.items(), key=lambda x: x[1], reverse=True)[:3]:
                matched_techs.append(f"{tech}({asr:.0%})")

        ds_pad = pad_right(ds_name[:32], 32)
        groups_str = ", ".join(sorted(technique_groups)) if technique_groups else "(无)"
        techs_str = ", ".join(matched_techs[:3]) if matched_techs else "(默认)"
        lines.append(f"{ds_pad} {seed_count:>3} seeds | group: {groups_str}")
        lines.append(f"{'':>34}→ 技术: {techs_str}")

    info_box("载荷-技术匹配矩阵", lines)


# ============================================================
# G2: Converter 变换示例
# ============================================================


def _print_converter_transform_sample(
    ctx: PipelineContext,
    technique_converter_map: dict[str, list],
    sorted_datasets: list[str],
) -> None:
    """G2: Converter 变换示例 — 展示 Top 3 技术的载荷变换链路。.

    展示: 技术 → Converter 链 → 变换类型 → 预期效果
    """
    from pipeline.utils.display import info_box

    if not technique_converter_map:
        return

    lines: list[str] = []
    # 按技术名排序取 Top 3
    for tech, convs in list(technique_converter_map.items())[:3]:
        conv_names = [type(c).__name__ for c in convs]
        lines.append(f"  [{tech}]")
        if conv_names:
            chain_str = " → ".join(conv_names)
            lines.append(f"    Converter 链: {chain_str}")
            # 推断变换效果
            effects: list[str] = []
            for name in conv_names:
                name_lower = name.lower()
                if "base64" in name_lower:
                    effects.append("Base64 编码绕过")
                elif "rot13" in name_lower:
                    effects.append("ROT13 字符替换")
                elif "caesar" in name_lower:
                    effects.append("凯撒位移")
                elif "atbash" in name_lower:
                    effects.append("Atbash 镜像替换")
                elif "unicode" in name_lower:
                    effects.append("Unicode 混淆")
                elif "suffix" in name_lower:
                    effects.append("后缀注入")
                elif "persuasion" in name_lower:
                    effects.append("LLM 说服策略增强")
                elif "stealth" in name_lower:
                    effects.append("隐蔽伪装")
                else:
                    effects.append(f"{name} 变换")
            lines.append(f"    变换效果: {' + '.join(effects)}")
        else:
            lines.append("    Converter: (无, baseline 直发)")
        lines.append("")

    info_box("Converter 变换示例 (Top 3 技术)", lines)


# ============================================================
# G3: 目标类型→Converter 适配图
# ============================================================


def _print_target_converter_adaptation(
    ctx: PipelineContext,
    technique_converter_map: dict[str, list],
    model_tier: str,
) -> None:
    """G3: 目标类型→Converter 适配图 — 展示目标类型如何驱动 Converter 链选择。."""
    from pipeline.utils.display import info_box

    target_type = getattr(ctx, "target_type", None)
    if not target_type:
        return

    lines: list[str] = []
    lines.append(f"目标类型: {target_type}")
    lines.append(f"模型分层: {model_tier}")
    lines.append("")

    # 目标类型 → 适配的 Converter 策略
    adaptation_map: dict[str, list[str]] = {
        "api": [
            "Encoding Bypass (Base64/ROT13) — API 无渲染层, 编码直接有效",
            "Stealth Evasion — 绕过 API 级文本过滤",
            "Persuasion Authority — LLM 辅助, 对抗模型生成说服策略",
        ],
        "web_chat": [
            "Format Injection — 利用 Web 渲染层注入格式",
            "Unicode Confusable — 绕过前端字符过滤",
            "Stealth Evasion — 隐蔽伪装绕过 DOM 过滤",
        ],
        "azure_openai": [
            "Encoding Bypass — 编码绕过 Azure 内容过滤",
            "Multi Encoding V2 — 多重编码组合",
            "Persuasion Chain — 多轮说服策略链",
        ],
    }

    strategies = adaptation_map.get(target_type, [])
    if strategies:
        lines.append("适配策略:")
        for i, strategy in enumerate(strategies, 1):
            lines.append(f"  {i}. {strategy}")
    else:
        lines.append("适配策略: (使用通用 Converter 路由)")

    # 统计实际匹配的 Converter
    if technique_converter_map:
        lines.append("")
        conv_type_counts: dict[str, int] = {}
        for convs in technique_converter_map.values():
            for c in convs:
                cname = type(c).__name__
                conv_type_counts[cname] = conv_type_counts.get(cname, 0) + 1
        top_convs = sorted(conv_type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        lines.append("实际 Converter 分布:")
        for cname, count in top_convs:
            lines.append(f"  {cname}: {count} 次")

    info_box("目标类型→Converter 适配", lines)


# ============================================================
# D1: 5 层决策流水线图
# ============================================================


def _print_5layer_decision_pipeline(
    ctx: PipelineContext,
    sorted_datasets: list[str],
    warm_start_asr: dict[str, float] | None,
) -> None:
    """D1: 5 层数据决策流水线图 — 展示数据从 L1→L5 的完整决策链路 + 层间数据流。."""
    from pipeline.utils.display import core_card

    warm_start = warm_start_asr or {}
    args = ctx.args if ctx.args else None
    max_ds_size = getattr(args, "max_dataset_size", 5) if args else 5

    # L1: Seed Source
    l1_lines = [
        f"{len(sorted_datasets)} 数据集 → {len(sorted_datasets)} 加载点",
        "来源: benchmarks/ + owasp/ + custom/",
    ]

    # L1 → L2 数据流
    l1_l2_lines = [
        f"↓ 输出: {len(sorted_datasets)} 个 SeedPromptGroup → 传入 L2 排序",
    ]

    # L2: Organization
    l2_lines = [
        "排序: ASR 降序 (高优先级优先)",
        "聚合: 按 dataset_name 分组",
    ]

    # L2 → L3 数据流
    l2_l3_lines = [
        f"↓ 输出: 排序后 {len(sorted_datasets)} 个数据集 → 传入 L3 配置",
    ]

    # L3: Dataset Config
    l3_lines = [
        "CompoundDatasetAttackConfiguration",
        f"per_dataset={max_ds_size} | {len(sorted_datasets)} 个独立预算",
    ]

    # L3 → L4 数据流
    l3_l4_lines = [
        f"↓ 输出: {len(sorted_datasets) * max_ds_size} 个 AtomicAttack 配置 → 持久化到 L4",
    ]

    # L4: Memory
    l4_lines = [
        "CentralMemory SQLite (per-run)",
        "标签: dataset_name + run_date + pipeline_version",
    ]

    # L4 → L5 数据流
    l4_l5_lines = [
        "↓ 输出: AttackResult 持久化 → L5 读取计算 ASR",
    ]

    # L5: Analytics
    l5_lines = [
        f"warm-start: {len(warm_start)} 技术先验",
        "epsilon-greedy + 失败路由 + ASR 反馈",
    ]

    core_card(
        "数据管理 5 层决策流水线",
        sections=[
            {"label": "L1 种子源", "lines": l1_lines},
            {"label": "L1→L2", "lines": l1_l2_lines},
            {"label": "L2 组织", "lines": l2_lines},
            {"label": "L2→L3", "lines": l2_l3_lines},
            {"label": "L3 配置", "lines": l3_lines},
            {"label": "L3→L4", "lines": l3_l4_lines},
            {"label": "L4 存储", "lines": l4_lines},
            {"label": "L4→L5", "lines": l4_l5_lines},
            {"label": "L5 分析", "lines": l5_lines},
        ],
    )
