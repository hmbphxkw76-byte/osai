"""
Stage 6/8: Executor 执行层
=========================

原生 AdaptiveScenario 批量执行。

显示架构（v6.0 统一卡片式 + 载荷主轴）:
  ① 执行配置 + 攻击计划摘要       — 全局统计
  ② 攻击载荷 × Converter 组合矩阵 — 按技术分组统一卡片（载荷 + Converter + 执行流程）
  ③ 执行清单 (★ 风格)           — 逐载荷执行计划确认
  ④ [OK] 开始执行...
  ⑤ 执行前准备卡片              — 从 scenario 诊断属性读取
  ⑥ 执行结果概要               — 执行后统计
  ⑦ 逐载荷执行结果 (★ 风格)     — 每个载荷的成功/失败+对话摘要
  ⑧ Per-Group Breakdown        — 执行后按组统计（格式对齐②）
"""

import os
from typing import Any

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header

# ── 统一卡片宽度（双线框） ──
_W = 68


def _trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号"""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


def _resolve_converter_chains_for_technique(
    tech: str,
    plans: list[Any],
    target_type: str,
    router_chains: list[str] | None,
) -> list[dict[str, Any]]:
    """
    三级回退获取技术的 Converter 链列表。

    优先级:
      1. 载荷自带 pi.converter_chains (最精确)
      2. BASE_TECHNIQUES_FOR_VARIANTS[tech] (静态映射)
      3. select_converter_chains_for_target(target_type) (动态路由)

    每条链返回: {name, desc, llm, priority}
    """
    try:
        from src.scenarios.technique_factories import (
            BASE_TECHNIQUES_FOR_VARIANTS,
            CONVERTER_VARIANT_CHAINS,
        )
    except Exception:
        return []

    # Step 1: 从载荷自带 converter_chains 提取
    payload_chains: list[str] = []
    for plan in plans:
        pi = getattr(plan, "prompt_item", None)
        if pi and getattr(pi, "converter_chains", None):
            for cn in pi.converter_chains:
                if cn not in payload_chains:
                    payload_chains.append(cn)

    # Step 2: 静态映射
    static_chains = list(BASE_TECHNIQUES_FOR_VARIANTS.get(tech, []))

    # Step 3: 动态路由链（如果 target_type 可用）
    dynamic_chains = list(router_chains) if router_chains else []

    # 合并去重: 载荷自带 > 静态映射 > 动态路由
    all_chain_names: list[str] = []
    seen = set()
    for cn in payload_chains + static_chains + dynamic_chains:
        if cn not in seen:
            all_chain_names.append(cn)
            seen.add(cn)

    # 解析每条链的元数据
    chains_info = []
    for cn in all_chain_names:
        ci = CONVERTER_VARIANT_CHAINS.get(cn, {})
        chains_info.append({
            "name": cn,
            "desc": ci.get("description", ""),
            "llm": ci.get("requires_llm", False),
            "priority": ci.get("priority", 99),
        })
    chains_info.sort(key=lambda x: x["priority"])
    return chains_info


def _display_unified_attack_matrix(
    attack_plans: list[Any],
    *,
    strategy_info: dict[str, Any],
    target_type: str = "",
    converter_chains_from_router: list[str] | None = None,
    owasp_set: dict[str, int] | None = None,
    mode_count: dict[str, int] | None = None,
    tech_set: dict[str, int] | None = None,
) -> None:
    """
    统一攻击载荷 × Converter 组合矩阵展示

    合并 DATA PAYLOAD x ATTACK TECHNIQUE 和 display_converter_variants
    为按技术分组的统一卡片，每张卡片包含：
    1. 技术头（名称/描述/模式/ASR/Tier）
    2. 载荷列表（OWASP/Source/Mode/Target/对话轮次/顺序步骤）
    3. Converter 链（优先级/LLM标记/描述）
    4. 执行流程说明
    """
    from src.scenarios.technique_factories import AI300_TECHNIQUE_METADATA

    # ── 技术模式中文名映射 ──
    _MODE_CN = {
        "multi_turn": "多轮迭代",
        "single_turn": "单轮直发",
        "sequential": "顺序组合",
        "converter_enhanced": "Converter增强",
    }

    # ── 技术 ASR 查询 (惰性导入, 避免循环依赖) ──
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr
        from src.scenarios.asr_strategy_display import _get_tier
    except Exception:
        get_normalized_asr = None  # type: ignore
        _get_tier = None  # type: ignore

    model_name = strategy_info.get("model_name", "")

    # ── 按技术分组攻击计划 ──
    payload_groups: dict[str, list[Any]] = {}
    for plan in attack_plans:
        tech = getattr(plan, "attack_technique", "unknown")
        payload_groups.setdefault(tech, []).append(plan)

    # ── 统计 Converter 变体数 ──
    total_variants = 0
    total_non_llm = 0
    total_llm = 0

    # 为主标题预计算
    for tech in payload_groups:
        chains = _resolve_converter_chains_for_technique(
            tech, payload_groups[tech], target_type, converter_chains_from_router,
        )
        for ci in chains:
            total_variants += 1
            if ci["llm"]:
                total_llm += 1
            else:
                total_non_llm += 1

    # ── 主标题: 双线装饰框 + ★ 强调 ──
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  攻击载荷 × Converter 组合矩阵  ★")
    print()
    print("    每个目标按优先级依次尝试 · 首次成功即停止 (FIRST_SUCCESS)")
    print()
    print("  ╚" + "═" * _W + "╝")

    # ── 按载荷数降序排列技术 ──
    for tech, plans in sorted(payload_groups.items(), key=lambda x: -len(x[1])):
        meta = AI300_TECHNIQUE_METADATA.get(tech, {})
        tech_desc = meta.get("description", tech)
        tags = meta.get("tags", [])
        raw_mode = "multi_turn" if "multi_turn" in tags else "single_turn"
        # 检查是否 sequential
        if "sequential" in tags:
            raw_mode = "sequential"
        mode_cn = _MODE_CN.get(raw_mode, raw_mode)

        # 轮次信息
        first_pi = getattr(plans[0], "prompt_item", None)
        plan_turns = getattr(plans[0], "max_turns", 1) if plans else 1
        mode_detail = mode_cn
        if plan_turns > 1 and raw_mode == "multi_turn":
            mode_detail = f"{mode_cn} ({plan_turns} 轮)"
        elif first_pi and getattr(first_pi, "sequential_steps", None):
            mode_detail = f"{mode_cn} ({len(first_pi.sequential_steps)} 步)"

        # ASR 信息
        asr_str = ""
        if get_normalized_asr and _get_tier:
            try:
                asr = get_normalized_asr(tech, model_name)
                tier = _get_tier(asr)
                asr_str = f"  |  学术 ASR: {asr:.0%} (Tier {tier})"
            except Exception:
                pass

        # ── 技术卡片: 双线边框 + ◆ 强调标题 ──
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {tech} · {tech_desc}")
        print(f"  ┃    模式: {mode_detail}{asr_str}")
        print("  ┃")

        # ── 载荷列表 ──
        print(f"  ┃    ┌─ 载荷 ({len(plans)} 个) ─{'─' * max(0, _W - 24)}┐")

        # OWASP 分布（全组共享）
        owasp_dist: dict[str, int] = {}
        for p in plans:
            oid = getattr(p, "owasp_id", None) or "N/A"
            owasp_dist[oid] = owasp_dist.get(oid, 0) + 1
        owasp_str = ", ".join(f"{k}({v})" for k, v in sorted(owasp_dist.items()))

        # Source
        first_meta = getattr(first_pi, "metadata", {}) or {} if first_pi else {}
        source_id = ""
        if first_pi:
            source_id = (
                getattr(first_pi, "source_id", "")
                or first_meta.get("source_id", "")
            )
        src_short = source_id.replace("owasp_", "").replace("_", " ") if source_id else "(unknown)"

        # 全局载荷编号偏移：在 attack_plans 中的位置
        global_plan_idx = 0
        for pg_plans in payload_groups.values():
            for p in pg_plans:
                if p in attack_plans:
                    pass
        # 构建全局载荷编号映射
        plan_to_pid = {}
        for g_idx, p in enumerate(attack_plans):
            plan_to_pid[id(p)] = f"P{g_idx + 1}"

        max_payloads_display = 4
        for idx, plan in enumerate(plans[:max_payloads_display]):
            pi = plan.prompt_item
            plan_mode = getattr(pi, "attack_mode", None)
            plan_mode_str = plan_mode.value if plan_mode else "unknown"
            obj = getattr(pi, "objective", "")
            obj_short = _trunc(obj, 55)

            # severity
            meta_pi = getattr(pi, "metadata", {}) or {}
            severity = meta_pi.get("severity", "")

            # 载荷编号 (P1, P2, ...)
            pid = plan_to_pid.get(id(plan), f"P{idx + 1}")

            # 载荷头
            if idx == 0:
                sev_str = f"  ({severity})" if severity else ""
                print(f"  ┃    │ {pid}{sev_str}")
                print(f"  ┃    │   OWASP  : {owasp_str}")
                print(f"  ┃    │   Source : {src_short}")
            else:
                # 后续载荷：OWASP/Source 与第一个相同则省略
                sev_str = f"  ({severity})" if severity else ""
                print(f"  ┃    │ {pid}{sev_str}")

            # 模式（每个载荷可能不同）
            plan_turns_local = getattr(plan, "max_turns", 1)
            local_mode = plan_mode_str + (f" ({plan_turns_local} turns)" if plan_turns_local > 1 else "")
            print(f"  ┃    │   Mode   : {local_mode}")
            print(f"  ┃    │   Target : \"{obj_short}\"")

            # 多轮: 展示对话轮次
            if plan_mode_str == "multi_turn" and getattr(pi, "multi_turn_steps", None):
                print("  ┃    │   Turns  :")
                for t_idx, step in enumerate(pi.multi_turn_steps[:3]):
                    print(f"  ┃    │     Turn {t_idx + 1}: \"{_trunc(step, 50)}\"")
                remaining = len(pi.multi_turn_steps) - 3
                if remaining > 0:
                    print(f"  ┃    │     ... ({remaining} more turns)")

            # 顺序: 展示步骤
            elif plan_mode_str == "sequential" and getattr(pi, "sequential_steps", None):
                print("  ┃    │   Steps  :")
                for s_idx, step in enumerate(pi.sequential_steps[:3]):
                    conv = f" + {step.converter_chain}" if step.converter_chain else ""
                    print(f"  ┃    │     Step {s_idx + 1}: {step.attack_technique}{conv}")
                    print(f"  ┃    │       -> \"{_trunc(step.objective, 48)}\"")
                remaining = len(pi.sequential_steps) - 3
                if remaining > 0:
                    print(f"  ┃    │     ... ({remaining} more steps)")

            # 载荷自带 Converter 链
            pi_chains = getattr(pi, "converter_chains", None)
            if pi_chains:
                print(f"  ┃    │   Conv   : {', '.join(pi_chains[:3])}")

            if idx < min(len(plans), max_payloads_display) - 1:
                print("  ┃    │")

        if len(plans) > max_payloads_display:
            print(f"  ┃    │   ... {len(plans) - max_payloads_display} more payloads")

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # ── Converter 增强 ──
        chains_info = _resolve_converter_chains_for_technique(
            tech, plans, target_type, converter_chains_from_router,
        )

        if chains_info:
            print(f"  ┃    ┌─ Converter 增强 ({len(chains_info)} 条) ─{'─' * max(0, _W - 32)}┐")
            for ci in chains_info:
                llm_tag = "[LLM]  " if ci["llm"] else "[非LLM]"
                print(f"  ┃    │ P{ci['priority']}  {llm_tag}  {ci['name']}")
                if ci["desc"]:
                    print(f"  ┃    │       └─ {ci['desc']}")
            print(f"  ┃    └{'─' * max(0, _W - 3)}┘")
        else:
            print("  ┃    (无 Converter 增强 — 基线技术)")

        # ── 执行流程 ──
        print("  ┃")
        if raw_mode == "multi_turn":
            print(f"  ┃    执行流程: {tech} 逐轮升级 → 末轮注入 Converter → 首次成功即停止")
        elif raw_mode == "sequential":
            print("  ┃    执行流程: 顺序执行各步 → 每步独立评分 → 全部成功则整体成功")
        else:
            print(f"  ┃    执行流程: {tech} + Converter 变换 → 按优先级依次尝试 → 首次成功即停止")
        print("  ┗" + "━" * _W)

    # ── 底部汇总 ──
    _plan_count = len(attack_plans)
    _total_tech = len(payload_groups)
    _owasp_count = len(owasp_set) if owasp_set else 0

    print()
    print("  " + "═" * _W)
    print(f"  ■ 汇总: {_plan_count} 个载荷 | {_total_tech} 种技术 | "
          f"{_owasp_count} 类 OWASP")
    if mode_count:
        _mode_str = " | ".join(f"{_MODE_CN.get(k, k)}: {v}" for k, v in mode_count.items() if v > 0)
        print(f"  ■ 模式: {_mode_str}")
    print(f"  ■ Converter 变体: {total_variants} 个组合 "
          f"(非 LLM: {total_non_llm} | LLM: {total_llm})")
    print("  ■ 策略: 自适应选择 → 失败类型路由 → 首次成功停止")
    print("  ■ 机制: PyRIT 原生 extra_request_converters 渐进式追加")
    print("  " + "═" * _W)
    print()


def _display_execution_checklist(
    attack_plans: list[Any],
    *,
    strategy_info: dict[str, Any],
    target_type: str = "",
    converter_chains_from_router: list[str] | None = None,
) -> None:
    """
    执行清单（★ 风格）— 逐载荷执行计划确认

    在 ★ 组合矩阵 ★ 之后、[OK] 开始执行 之前展示。
    每个载荷一行，附带 Converter 尝试链（↳ 表示渐进式追加）。
    """
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr
        from src.scenarios.asr_strategy_display import _get_tier
    except Exception:
        get_normalized_asr = None  # type: ignore
        _get_tier = None  # type: ignore

    model_name = strategy_info.get("model_name", "")
    strategy_mode = strategy_info.get("strategy_mode", "academic")

    # 主标题
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    n_plans = len(attack_plans)
    # 统计技术数
    tech_set = set()
    for p in attack_plans:
        t = getattr(p, "attack_technique", "")
        if t:
            tech_set.add(t)
    print(f"       ★  执行清单 ({n_plans} 载荷 × {len(tech_set)} 技术 = {n_plans} 原子攻击)  ★")
    print()
    print("  ╚" + "═" * _W + "╝")

    print(f"  ┌─ 按执行顺序 ─{'─' * max(1, _W - 22)}┐")

    for idx, plan in enumerate(attack_plans):
        pid = f"P{idx + 1}"
        tech = getattr(plan, "attack_technique", "unknown")
        owasp = getattr(plan, "owasp_id", "") or ""
        pi = getattr(plan, "prompt_item", None)
        obj = _trunc(getattr(pi, "objective", ""), 50) if pi else ""

        # ASR
        asr_str = ""
        if get_normalized_asr and _get_tier:
            try:
                asr = get_normalized_asr(tech, model_name)
                tier = _get_tier(asr)
                asr_str = f"  Tier {tier}  ASR {asr:.0%}"
            except Exception:
                pass

        print(f"  │ #{idx + 1}  {pid} [{owasp}] {tech}{asr_str}")
        print(f"  │      \"{obj}\"")

        # Converter 尝试链
        chains = _resolve_converter_chains_for_technique(
            tech, [plan], target_type, converter_chains_from_router,
        )
        if chains:
            chain_names = [c["name"] for c in chains[:4]]
            chain_str = " → ".join(chain_names)
            if len(chains) > 4:
                chain_str += f" ... (+{len(chains) - 4})"
            print(f"  │      ↳ {chain_str}")
        else:
            print(f"  │      ↳ (无 Converter — 基线技术)")

    print(f"  │")
    print(f"  │ 策略: {strategy_mode} (Tier S → A → B → C → D)")
    print(f"  │ 停止: FIRST_SUCCESS (首次成功即停止尝试剩余 Converter)")
    print(f"  └{'─' * _W}┘")
    print()


def _display_per_payload_results(
    attack_plans: list[Any],
    native_result: Any,
) -> None:
    """
    逐载荷执行结果（★ 风格）— 每个载荷的成功/失败 + 对话摘要

    在执行结果概要之后、Per-Group Breakdown 之前展示。
    """
    if native_result is None:
        return
    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    # 从 scenario_output 导入提取辅助函数
    from src.scenarios.scenario_output import _extract_result_info, _OWASP_NAMES

    # 主标题
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  逐载荷执行结果  ★")
    print()
    print("  ╚" + "═" * _W + "╝")

    # 展平所有结果
    all_results: list[Any] = []
    for group_name, results in display_groups.items():
        for r in results:
            if r is not None:
                all_results.append(r)

    payload_idx = 0
    for r in all_results:
        payload_idx += 1
        pid = f"P{payload_idx}"

        # 提取信息
        techniques: set[str] = set()
        converters: set[str] = set()
        owasp_ids: set[str] = set()
        _extract_result_info(r, techniques=techniques, converters=converters, owasp_ids=owasp_ids)

        # 结果
        outcome = getattr(r, "outcome", None)
        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
        is_success = outcome_str == "SUCCESS"

        status_icon = "✅ 成功" if is_success else "❌ 失败"
        tech_display = ", ".join(sorted(techniques)) if techniques else "(unknown)"

        # 对话摘要
        conversation = getattr(r, "conversation", None) or getattr(r, "request_pieces", None)
        user_msg = ""
        asst_msg = ""
        if conversation:
            try:
                # 尝试从 conversation 提取消息
                if hasattr(conversation, "__iter__"):
                    for piece in conversation:
                        role = getattr(piece, "role", "") or ""
                        val = getattr(piece, "value", "") or getattr(piece, "text", "")
                        if not val:
                            continue
                        if role.lower() in ("user", "assistant"):
                            val_short = _trunc(val, 80)
                            if role.lower() == "user" and not user_msg:
                                user_msg = val_short
                            elif role.lower() == "assistant" and not asst_msg:
                                asst_msg = val_short
            except Exception:
                pass

        # OWASP
        owasp_id_str = ", ".join(sorted(owasp_ids)) if owasp_ids else ""
        owasp_name = ""
        if owasp_id_str:
            oid = owasp_id_str.split(", ")[0].strip()
            owasp_name = _OWASP_NAMES.get(oid, "")

        # SequentialAttackResult: 检查子结果的成功 Converter
        child_converters: list[str] = []
        child_results = getattr(r, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            child_identifier = None
            if hasattr(child, "get_attack_strategy_identifier"):
                child_identifier = child.get_attack_strategy_identifier()
            if child_identifier is not None:
                from src.scenarios.scenario_output import _extract_converters_from_identifier
                child_conv_names = _extract_converters_from_identifier(child_identifier)
                child_converters.extend(child_conv_names)
            child_outcome = getattr(child, "outcome", None)
            if child_outcome is not None:
                child_outcome_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                if child_outcome_str == "SUCCESS":
                    child_name = getattr(child_identifier, "unique_name", "") if child_identifier else ""
                    if child_name:
                        tech_display = child_name.split("::")[0] if "::" in child_name else child_name

        # 卡片
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {pid} [{owasp_id_str}] {tech_display}  {status_icon}")
        print(f"  ┃    ┌─ 结果 ─{'─' * max(0, _W - 16)}┐")

        if owasp_name:
            print(f"  ┃    │ OWASP: {owasp_id_str} ({owasp_name})")

        if converters:
            conv_str = ", ".join(sorted(converters))
            print(f"  ┃    │ Converter: {conv_str}")
        elif child_converters:
            conv_str = ", ".join(sorted(set(child_converters)))
            print(f"  ┃    │ Converter: {conv_str}")
        else:
            print(f"  ┃    │ Converter: (基线无变换)")

        # 评分
        score = getattr(r, "score", None)
        if score is not None:
            score_val = getattr(score, "score_value", "")
            score_rationale = _trunc(getattr(score, "score_rationale", ""), 50)
            print(f"  ┃    │ 评分: {outcome_str} ({score_val})")
            if score_rationale:
                print(f"  ┃    │       {score_rationale}")
        else:
            print(f"  ┃    │ 评分: {outcome_str}")

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # 对话摘要（仅成功时展示）
        if is_success and (user_msg or asst_msg):
            print(f"  ┃    ┌─ 攻击对话 ─{'─' * max(0, _W - 20)}┐")
            if user_msg:
                print(f"  ┃    │ [USER] {user_msg}")
            if converters or child_converters:
                conv_short = ", ".join(sorted(converters or set(child_converters)))
                print(f"  ┃    │        ↳ [{conv_short}]")
            if asst_msg:
                print(f"  ┃    │ [ASST] {asst_msg}")
            print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # 失败: 展示尝试过的 Converter
        if not is_success:
            if child_results:
                print(f"  ┃    ┌─ 尝试记录 ({len(child_results)} 次) ─{'─' * max(0, _W - 34)}┐")
                for ci, child in enumerate(child_results[:5]):
                    child_outcome = getattr(child, "outcome", None)
                    child_status = "✗"
                    if child_outcome is not None:
                        child_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                        if child_str == "SUCCESS":
                            child_status = "✓"
                    child_identifier = None
                    if hasattr(child, "get_attack_strategy_identifier"):
                        child_identifier = child.get_attack_strategy_identifier()
                    child_name = getattr(child_identifier, "unique_name", "") if child_identifier else ""
                    child_tech = child_name.split("::")[0] if "::" in child_name else child_name
                    print(f"  ┃    │ {ci + 1}. {child_status} {child_tech}")
                if len(child_results) > 5:
                    print(f"  ┃    │   ... {len(child_results) - 5} more")
                print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        print("  ┗" + "━" * _W)

    print()


async def run(ctx: PipelineContext) -> bool:
    """执行攻击阶段。返回 False 表示执行失败不可恢复。"""
    stage_header(6, "Executor 执行层", "原生 AdaptiveScenario 批量执行")

    # ── ① 执行配置 ──
    ctx.max_concurrency = ctx.config_loader.get_pipeline_max_concurrency()
    ctx.per_attack_timeout = ctx.config_loader.get_pipeline_per_attack_timeout()
    ctx.timeout_overrides = ctx.config_loader.get_pipeline_timeout_overrides()
    ctx.adaptive_max_concurrency = int(os.getenv("ADAPTIVE_MAX_CONCURRENCY", "4"))

    config_lines = [f"最大并发: {ctx.max_concurrency}"]
    if ctx.timeout_overrides:
        override_str = ", ".join(f"{k}={v}s" for k, v in ctx.timeout_overrides.items())
        config_lines.append(f"差异化超时: {override_str}  (默认: {ctx.per_attack_timeout}s)")
    else:
        config_lines.append(f"单次超时: {ctx.per_attack_timeout}s")
    config_lines.append(f"原生并发: {ctx.adaptive_max_concurrency} (API 级限速: {ctx.api_max_concurrent})")
    config_lines.append("执行模式: 原生 AdaptiveScenario (L5 统一路径, Converter 变体)")
    info_box("执行配置", config_lines)

    # ── ① 攻击计划摘要 ──
    _exec_model = ctx.strategy_info.get("model_name", ctx.target_model)
    _exec_mode = ctx.strategy_info.get("strategy_mode", "academic")
    _plan_count = len(ctx.attack_plans)

    # 提取攻击计划摘要信息
    _tech_set = {}
    _owasp_set = {}
    _mode_count = {"multi_turn": 0, "single_turn": 0, "sequential": 0}
    for plan in ctx.attack_plans:
        tech = getattr(plan, "attack_technique", "unknown")
        _tech_set[tech] = _tech_set.get(tech, 0) + 1
        owasp = getattr(plan, "owasp_id", None) or "N/A"
        _owasp_set[owasp] = _owasp_set.get(owasp, 0) + 1
        mode = getattr(plan.prompt_item, "attack_mode", None)
        mode_str = mode.value if mode else "unknown"
        if mode_str in _mode_count:
            _mode_count[mode_str] += 1

    plan_lines = [
        f"目标模型: {_exec_model}  |  策略: {_exec_mode}",
        f"攻击计划: {_plan_count} 个 "
        f"(多轮: {_mode_count['multi_turn']} | 单轮: {_mode_count['single_turn']} "
        f"| 顺序: {_mode_count['sequential']})",
        f"攻击技术 ({len(_tech_set)} 种): " + ", ".join(
            f"{t}({c})" for t, c in sorted(_tech_set.items(), key=lambda x: -x[1])
        ),
        f"OWASP 覆盖 ({len(_owasp_set)} 类): " + ", ".join(
            f"{o}({c})" for o, c in sorted(_owasp_set.items(), key=lambda x: -x[1])
        ),
    ]
    info_box("攻击计划摘要", plan_lines)

    # ── ② 统一攻击载荷 × Converter 组合矩阵 ──
    _display_unified_attack_matrix(
        ctx.attack_plans,
        strategy_info=ctx.strategy_info,
        target_type=ctx.target_type,
        converter_chains_from_router=ctx.converter_chains,
        owasp_set=_owasp_set,
        mode_count=_mode_count,
        tech_set=_tech_set,
    )

    # ── ③ 执行清单（★ 风格） ──
    _display_execution_checklist(
        ctx.attack_plans,
        strategy_info=ctx.strategy_info,
        target_type=ctx.target_type,
        converter_chains_from_router=ctx.converter_chains,
    )

    # ── ④ 开始执行 ──
    print(f"  [OK] 开始执行 {_plan_count} 个攻击计划...\n")

    from src.scenarios.adaptive_runner import run_adaptive_scenario_async

    ctx.adaptive_result = await run_adaptive_scenario_async(
        objective_target=ctx.objective_target,
        judge_target=ctx.judge_target,
        attack_plans=ctx.attack_plans,
        owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
        exam_id=ctx.exam_id,
        max_attempts_per_objective=3,
        per_attack_timeout=ctx.per_attack_timeout,
        max_retries=ctx.scenario_max_retries,
        verbose=ctx.verbose,
        converter_target=ctx.converter_target,
        target_type=ctx.target_type,
        max_concurrency=ctx.adaptive_max_concurrency,
        strategy_mode=ctx.strategy_info.get("strategy_mode", "academic"),
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        model_tier=ctx.strategy_info.get("model_tier", ctx.model_tier),
    )
    ctx.batch_result = ctx.adaptive_result.batch_result

    # ── ⑥ 执行结果概要 ──
    result_lines = [
        f"总计划: {ctx.batch_result.total_plans}",
        f"已执行: {ctx.batch_result.executed} | 成功: {ctx.batch_result.succeeded} | "
        f"失败: {ctx.batch_result.failed} | 错误: {ctx.batch_result.errored}",
        f"成功率: {ctx.batch_result.success_rate * 100:.1f}%",
        f"执行时间: {ctx.adaptive_result.execution_time:.1f}s",
        f"Converter 变体使用: {ctx.adaptive_result.converter_variants_used} 次",
    ]
    if ctx.batch_result.upgrade_attempts > 0:
        result_lines.append(
            f"升级重试: {ctx.batch_result.upgrade_attempts} 次, "
            f"成功 {ctx.batch_result.upgrade_success} 次"
        )
    if ctx.adaptive_result.failure_type_distribution:
        result_lines.append(f"失败类型分布: {ctx.adaptive_result.failure_type_distribution}")
        if ctx.adaptive_result.most_common_failure_type:
            result_lines.append(f"最常见失败类型: {ctx.adaptive_result.most_common_failure_type}")
    info_box("执行结果", result_lines)

    # ── ⑦ 逐载荷执行结果（★ 风格） ──
    if ctx.adaptive_result.native_result is not None:
        try:
            _display_per_payload_results(
                ctx.attack_plans,
                ctx.adaptive_result.native_result,
            )
        except Exception as e:
            print(f"  [!] 逐载荷结果输出失败: {e}")

    # ── ⑧ Per-Group Breakdown（格式对齐②） ──
    if ctx.adaptive_result.native_result is not None:
        try:
            from src.scenarios.scenario_output import display_enhanced_group_breakdown
            display_enhanced_group_breakdown(
                ctx.adaptive_result.native_result,
                owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
            )
        except Exception as e:
            print(f"  [!] Per-Group Breakdown 输出失败: {e}")

    # L5: 执行后清理
    try:
        from src.executor import reset_executor
        reset_executor()
    except Exception:
        pass

    # 错误详情
    if ctx.batch_result.errors:
        print(f"\n  [!] 错误详情 ({len(ctx.batch_result.errors)} 个):")
        for err in ctx.batch_result.errors[:5]:
            print(f"    - {err.get('plan_id', 'N/A')}: {err.get('error', 'N/A')}")
        if len(ctx.batch_result.errors) > 5:
            print(f"    ... 还有 {len(ctx.batch_result.errors) - 5} 个错误")

    return True
