"""
Stage 5/7: Executor 执行层
=========================

原生 AdaptiveScenario 批量执行。

显示架构 (v8.0 统一优化 — 载荷×Converter 组合矩阵 + 执行策略 + 结果摘要):
  ① 执行配置 + 攻击计划摘要       — 全局统计
  ② 执行策略                     — 技术排序 + 失败路由 + 停止策略
  ③ ★ 载荷 × Converter 变体交叉组合 ★  — 全局概览 + ×并排 + 公式 + 执行流程箭头 + 详情
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
from src.reporting.converter_log import format_technique_display

# ── 统一卡片宽度（双线框） ──
_W = 68


def _trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号"""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


def _cjk_width(s: str) -> int:
    """近似计算字符串显示宽度（CJK 字符算 2 列）"""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def _pad_right(s: str, width: int) -> str:
    """将字符串填充到指定显示宽度"""
    w = _cjk_width(s)
    return s + " " * max(0, width - w)


def _sort_tech_by_asr(tech_counts: dict[str, int], model_name: str) -> list[tuple[str, int]]:
    """按 ASR 降序排序技术（高 ASR 优先），ASR 相同时按计划数降序"""
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr
        return sorted(
            tech_counts.items(),
            key=lambda x: (-get_normalized_asr(x[0], model_name), -x[1]),
        )
    except Exception:
        return sorted(tech_counts.items(), key=lambda x: -x[1])


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
    载荷 × Converter 变体交叉组合矩阵展示 (v2.0)

    展示结构:
      1. 标题
      2. 全局概览 (所有技术的 载荷×变体=尝试 汇总)
      3. 每个技术卡片:
         a. 技术头 (名称/描述/模式/ASR/Tier)
         b. × 并排布局 (载荷概要 | Converter 概要)
         c. 公式行 (N × M = K)
         d. 执行流程箭头 (每行 = 一个载荷的完整尝试链)
         e. 载荷详情
         f. Converter 详情
      4. 底部汇总
    """
    from src.scenarios.technique_factories import AI300_TECHNIQUE_METADATA

    _MODE_CN = {
        "multi_turn": "多轮迭代",
        "single_turn": "单轮直发",
        "sequential": "顺序组合",
        "converter_enhanced": "Converter增强",
    }

    _CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩"

    # ── 技术 ASR 查询 (惰性导入) ──
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

    # ── 为每个技术解析 Converter 链 ──
    tech_chains: dict[str, list[dict[str, Any]]] = {}
    for tech in payload_groups:
        tech_chains[tech] = _resolve_converter_chains_for_technique(
            tech, payload_groups[tech], target_type, converter_chains_from_router,
        )

    # ── 统计 Converter 变体数 ──
    total_variants = 0
    total_non_llm = 0
    total_llm = 0
    for chains in tech_chains.values():
        for ci in chains:
            total_variants += 1
            if ci["llm"]:
                total_llm += 1
            else:
                total_non_llm += 1

    # ── ASR 降序排序 ──
    def _asr_sort_for_display(tech_name: str) -> float:
        if get_normalized_asr:
            try:
                return -get_normalized_asr(tech_name, model_name)
            except Exception:
                pass
        return 0.0

    sorted_techs = sorted(payload_groups.keys(), key=_asr_sort_for_display)

    # ════════════════════════════════════════════════════════════════
    # 1. 标题
    # ════════════════════════════════════════════════════════════════
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  载荷 × Converter 变体交叉组合  ★")
    print()
    print("    每个载荷独立尝试所有变体 → 首次成功即停止 → 不再尝试后续变体")
    print()
    print("  ╚" + "═" * _W + "╝")

    # ════════════════════════════════════════════════════════════════
    # 2. 全局概览
    # ════════════════════════════════════════════════════════════════
    print()
    print(f"  ┌─ 全局概览 {'─' * max(1, _W - 22)}┐")
    print("  │")
    total_payloads = 0
    total_attempts = 0
    for i, tech in enumerate(sorted_techs):
        n_pl = len(payload_groups[tech])
        n_var = len(tech_chains[tech]) + 1
        n_att = n_pl * n_var
        total_payloads += n_pl
        total_attempts += n_att
        tech_pad = _pad_right(tech[:20], 20)
        print(f"  │  技术 {i + 1}: {tech_pad}  "
              f"{n_pl:>2} 载荷 × {n_var:>2} 变体 = {n_att:>3} 尝试")
    print(f"  │  {'─' * max(1, _W - 6)}")
    print(f"  │  合计: {total_payloads} 载荷 × (变体不同) = {total_attempts} 尝试上限")
    print("  │  实际远少于此 (FIRST_SUCCESS + L2/L3 停止策略)")
    print(f"  └{'─' * _W}┘")

    # ════════════════════════════════════════════════════════════════
    # 3. 每个技术卡片
    # ════════════════════════════════════════════════════════════════

    # ── 并排布局尺寸 ──
    _LEFT_W = 24
    _RIGHT_W = 38

    # 全局载荷编号映射 (P1, P2, ... 贯穿全阶段)
    plan_to_pid: dict[int, str] = {}
    for g_idx, p in enumerate(attack_plans):
        plan_to_pid[id(p)] = f"P{g_idx + 1}"

    for tech in sorted_techs:
        plans = payload_groups[tech]
        chains = tech_chains[tech]
        n_variants = len(chains) + 1  # +1 for baseline

        meta = AI300_TECHNIQUE_METADATA.get(tech, {})
        tech_desc = meta.get("description", tech)
        tags = meta.get("tags", [])
        raw_mode = "multi_turn" if "multi_turn" in tags else "single_turn"
        if "sequential" in tags:
            raw_mode = "sequential"
        mode_cn = _MODE_CN.get(raw_mode, raw_mode)

        first_pi = getattr(plans[0], "prompt_item", None)
        plan_turns = getattr(plans[0], "max_turns", 1) if plans else 1
        mode_detail = mode_cn
        if plan_turns > 1 and raw_mode == "multi_turn":
            mode_detail = f"{mode_cn} ({plan_turns} 轮)"
        elif first_pi and getattr(first_pi, "sequential_steps", None):
            mode_detail = f"{mode_cn} ({len(first_pi.sequential_steps)} 步)"

        asr_str = ""
        if get_normalized_asr and _get_tier:
            try:
                asr = get_normalized_asr(tech, model_name)
                tier = _get_tier(asr)
                asr_str = f"  |  学术 ASR: {asr:.0%} (Tier {tier})"
            except Exception:
                pass

        tech_display = format_technique_display(tech)

        # ── 3a. 技术头 ──
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {tech_display} · {tech_desc}")
        print(f"  ┃    模式: {mode_detail}{asr_str}")
        print("  ┃")

        # ── 3b. × 并排布局 ──
        # 构建载荷概要 (左栏)
        payload_lines: list[str] = []
        for idx, plan in enumerate(plans[:4]):
            pi = plan.prompt_item
            obj = _trunc(getattr(pi, "objective", ""), _LEFT_W - 5)
            marker = _CIRCLED[idx] if idx < len(_CIRCLED) else f"{idx + 1}."
            payload_lines.append(f" {marker} {obj}")
        if len(plans) > 4:
            payload_lines.append(f" ... ({len(plans) - 4} more)")
        payload_lines.append(f" {len(plans)} 个载荷")

        # 构建 Converter 概要 (右栏)
        converter_lines: list[str] = [" 基线 (无变换)"]
        shown_chains = min(len(chains), 8)
        for ci in chains[:shown_chains]:
            llm_tag = "[非LLM]" if not ci["llm"] else "[LLM]  "
            name = ci["name"]
            max_name = _RIGHT_W - 16
            if _cjk_width(name) > max_name:
                name = name[:max_name - 3] + "..."
            converter_lines.append(
                f" 优先{ci['priority']}  {_pad_right(name, max_name)} {llm_tag}"
            )
        if len(chains) > shown_chains:
            converter_lines.append(f" ... ({len(chains) - shown_chains} more)")
        converter_lines.append(
            f" {n_variants} 个变体 (1基线+{len(chains)} Conv)"
        )

        # 填充到相同行数
        max_lines = max(len(payload_lines), len(converter_lines))
        while len(payload_lines) < max_lines:
            payload_lines.append("")
        while len(converter_lines) < max_lines:
            converter_lines.append("")

        # 打印并排框
        left_hdr = f"载荷 ({len(plans)})"
        left_dashes = max(0, _LEFT_W - 3 - _cjk_width(left_hdr))
        left_top = f"┌─ {left_hdr} {'─' * left_dashes}┐"

        right_hdr = f"Converter 变体池 ({n_variants})"
        right_dashes = max(0, _RIGHT_W - 3 - _cjk_width(right_hdr))
        right_top = f"┌─ {right_hdr} {'─' * right_dashes}┐"

        print(f"  ┃    {left_top}  ×  {right_top}")

        for i in range(max_lines):
            left_content = _pad_right(payload_lines[i], _LEFT_W)
            right_content = _pad_right(converter_lines[i], _RIGHT_W)
            print(f"  ┃    │{left_content}│     │{right_content}│")

        left_bot = "└" + "─" * _LEFT_W + "┘"
        right_bot = "└" + "─" * _RIGHT_W + "┘"
        print(f"  ┃    {left_bot}     {right_bot}")

        # ── 3c. 公式行 ──
        print("  ┃")
        n_attempts = len(plans) * n_variants
        print(f"  ┃    交叉组合: {len(plans)} × {n_variants} = {n_attempts} "
              f"尝试上限 (FIRST_SUCCESS)")
        print("  ┃")

        # ── 3d. 执行流程箭头 ──
        flow_hdr = "执行流程 (每行 = 一个载荷的完整尝试链)"
        flow_dashes = max(0, _W - 6 - _cjk_width(flow_hdr) - 2)
        print(f"  ┃    ┌─ {flow_hdr} {'─' * flow_dashes}┐")

        flow_parts = ["[基线]"]
        for ci in chains[:5]:
            short = ci["name"][:8]
            flow_parts.append(f"[{short}]")
        if len(chains) > 5:
            flow_parts.append("...")
        flow_parts.append("✅停")
        flow_line = " → ".join(flow_parts)

        for idx in range(min(len(plans), 4)):
            marker = _CIRCLED[idx] if idx < len(_CIRCLED) else f"{idx + 1}."
            print(f"  ┃    │ {marker} → {flow_line}")
        if len(plans) > 4:
            print(f"  ┃    │ ... ({len(plans) - 4} more)")
        print("  ┃    │")
        print(f"  ┃    │ 每行独立 · 变体顺序相同 "
              f"(优先1→2→3→4) · 最多 {n_variants} 步/行")
        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # ── 3e. 载荷详情 ──
        print(f"  ┃    ┌─ 载荷详情 {'─' * max(1, _W - 20)}┐")

        owasp_dist: dict[str, int] = {}
        for p in plans:
            oid = getattr(p, "owasp_id", None) or "N/A"
            owasp_dist[oid] = owasp_dist.get(oid, 0) + 1
        owasp_str = ", ".join(
            f"{k}({v})" for k, v in sorted(owasp_dist.items())
        )

        first_meta = (
            getattr(first_pi, "metadata", {}) or {} if first_pi else {}
        )
        source_id = ""
        if first_pi:
            source_id = (
                getattr(first_pi, "source_id", "")
                or first_meta.get("source_id", "")
            )
        src_short = (
            source_id.replace("owasp_", "").replace("_", " ")
            if source_id
            else "(unknown)"
        )

        max_detail = 4
        for idx, plan in enumerate(plans[:max_detail]):
            pi = plan.prompt_item
            plan_mode = getattr(pi, "attack_mode", None)
            plan_mode_str = plan_mode.value if plan_mode else "unknown"
            obj = getattr(pi, "objective", "")
            obj_short = _trunc(obj, 50)
            meta_pi = getattr(pi, "metadata", {}) or {}
            severity = meta_pi.get("severity", "")
            pid = plan_to_pid.get(id(plan), f"P{idx + 1}")
            marker = (
                _CIRCLED[idx] if idx < len(_CIRCLED) else f"{idx + 1}."
            )

            sev_str = f"  ({severity})" if severity else ""
            if idx == 0:
                print(f"  ┃    │ {marker}{sev_str}  [{pid}]  OWASP: {owasp_str}")
                print(f"  ┃    │   Source: {src_short}  |  Mode: {plan_mode_str}")
            else:
                print(f"  ┃    │ {marker}{sev_str}  [{pid}]  Mode: {plan_mode_str}")
            print(f"  ┃    │   Target: \"{obj_short}\"")

            if (
                plan_mode_str == "multi_turn"
                and getattr(pi, "multi_turn_steps", None)
            ):
                for t_idx, step in enumerate(pi.multi_turn_steps[:2]):
                    print(f"  ┃    │     Turn {t_idx + 1}: \"{_trunc(step, 45)}\"")
                remaining = len(pi.multi_turn_steps) - 2
                if remaining > 0:
                    print(f"  ┃    │     ... ({remaining} more turns)")
            elif (
                plan_mode_str == "sequential"
                and getattr(pi, "sequential_steps", None)
            ):
                for s_idx, step in enumerate(pi.sequential_steps[:2]):
                    conv = (
                        f" + {step.converter_chain}"
                        if step.converter_chain
                        else ""
                    )
                    print(f"  ┃    │     Step {s_idx + 1}: "
                          f"{step.attack_technique}{conv}")
                remaining = len(pi.sequential_steps) - 2
                if remaining > 0:
                    print(f"  ┃    │     ... ({remaining} more steps)")

            if idx < min(len(plans), max_detail) - 1:
                print("  ┃    │")

        if len(plans) > max_detail:
            print(f"  ┃    │ ... ({len(plans) - max_detail} more)")
        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # ── 3f. Converter 详情 ──
        print(f"  ┃    ┌─ Converter 详情 {'─' * max(1, _W - 24)}┐")
        print("  ┃    │ 基线        原文直发，无变换")
        for ci in chains:
            llm_tag = "[非LLM]" if not ci["llm"] else "[LLM]  "
            print(f"  ┃    │ 优先{ci['priority']} {llm_tag}  {ci['name']}")
            if ci["desc"]:
                print(f"  ┃    │   └─ {ci['desc']}")
        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # ── 执行流程说明 ──
        print("  ┃")
        if raw_mode == "multi_turn":
            print(f"  ┃    执行流程: {tech} 逐轮升级 → "
                  f"末轮注入 Converter → 首次成功即停止")
        elif raw_mode == "sequential":
            print("  ┃    执行流程: 顺序执行各步 → "
                  "每步独立评分 → 全部成功则整体成功")
        else:
            print(f"  ┃    执行流程: {tech} + Converter 变换 → "
                  f"按优先级依次尝试 → 首次成功即停止")
        print("  ┗" + "━" * _W)

    # ════════════════════════════════════════════════════════════════
    # 4. 底部汇总
    # ════════════════════════════════════════════════════════════════
    _plan_count = len(attack_plans)
    _total_tech = len(payload_groups)
    _owasp_count = len(owasp_set) if owasp_set else 0
    _strategy_mode = strategy_info.get("strategy_mode", "academic")

    print()
    print("  " + "═" * _W)
    print(f"  ■ 汇总: {_plan_count} 个载荷 | {_total_tech} 种技术 | "
          f"{_owasp_count} 类 OWASP")
    if mode_count:
        _mode_str = " | ".join(
            f"{_MODE_CN.get(k, k)}: {v}"
            for k, v in mode_count.items()
            if v > 0
        )
        print(f"  ■ 模式: {_mode_str}")
    print(f"  ■ Converter 变体: {total_variants} 个组合 "
          f"(非 LLM: {total_non_llm} | LLM: {total_llm})")
    print(f"  ■ 策略: {_strategy_mode} (Tier S → A → B → C → D)")
    print("  ■ 停止: FIRST_SUCCESS (首次成功即停止尝试剩余 Converter)")
    print("  ■ 机制: PyRIT 原生 extra_request_converters 渐进式追加")
    print(f"  ■ 载荷编号: P1-P{_plan_count} (基线) → "
          f"执行后含 Converter 变体扩展")
    print("  " + "═" * _W)
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
            print("  ┃    │ Converter: (基线无变换)")

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


def _display_execution_strategy(ctx: PipelineContext) -> None:
    """
    执行策略 — 合并技术排序 + 失败路由 + 停止策略
    """
    from src.payloads.technique_name_mapper import get_normalized_asr
    from src.scenarios.asr_strategy_display import _get_tier

    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    strategy_mode = ctx.strategy_info.get("strategy_mode", "academic")

    tech_list = []
    seen = set()
    for plan in ctx.attack_plans:
        tech = getattr(plan, "attack_technique", "")
        if tech and tech not in seen:
            seen.add(tech)
            asr = get_normalized_asr(tech, model_name)
            tech_list.append((tech, asr, _get_tier(asr)))

    if tech_list:
        tech_list.sort(key=lambda x: -x[1])

    _TIER_LABELS = {"S": "极高", "A": "高", "B": "中", "C": "低", "D": "极低"}

    strategy_lines = [f"技术排序: {strategy_mode} 模式 (Tier S → A → B → C → D)"]

    if tech_list:
        for i, (tech, asr, tier) in enumerate(tech_list[:10]):
            bar_len = int(asr * 10)
            bar = "█" * bar_len + "░" * (10 - bar_len)
            _label = _TIER_LABELS.get(tier, "")
            strategy_lines.append(f"  {i+1}. [{tier} {_label}] {tech:28s} {bar}")
    else:
        strategy_lines.append("  (无技术)")

    strategy_lines.append("")
    strategy_lines.append("失败路由 (参考策略):")
    strategy_lines.append("  model_refusal     → 策略升级 (Tier S/A 优先)")
    strategy_lines.append("  timeout           → 降级单轮 (prompt_sending)")
    strategy_lines.append("  scorer_error      → 换技术 (跳过当前)")
    strategy_lines.append("  objective_failed  → 强技术+Converter 变体")

    strategy_lines.append("")
    strategy_lines.append("停止策略: FIRST_SUCCESS (首次成功即停止尝试剩余 Converter)")
    # L2/L3 停止策略
    _owasp_threshold = ctx.config_loader.get_owasp_success_threshold()
    _stop_on_first = ctx.config_loader.get_stop_on_first_success()
    if _stop_on_first:
        strategy_lines.append("  L3: 全局首成功即停 (已启用)")
    elif _owasp_threshold > 0:
        strategy_lines.append(f"  L2: OWASP 分类阈值 {_owasp_threshold:.0%} (运行时)")

    info_box("执行策略", strategy_lines)


async def run(ctx: PipelineContext) -> bool:
    """执行攻击阶段（含执行策略展示）。返回 False 表示执行失败不可恢复。"""
    stage_header(5, "Executor 执行层", "原生 AdaptiveScenario 批量执行")

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
            f"{t}({c})" for t, c in _sort_tech_by_asr(_tech_set, _exec_model)
        ),
        f"OWASP 覆盖 ({len(_owasp_set)} 类): " + ", ".join(
            f"{o}({c})" for o, c in sorted(_owasp_set.items(), key=lambda x: -x[1])
        ),
    ]
    info_box("攻击计划摘要", plan_lines)

    # ── ② 执行策略 ──
    _display_execution_strategy(ctx)

    # ── ③ 统一攻击载荷 × Converter 组合矩阵 ──
    _display_unified_attack_matrix(
        ctx.attack_plans,
        strategy_info=ctx.strategy_info,
        target_type=ctx.target_type,
        converter_chains_from_router=ctx.converter_chains,
        owasp_set=_owasp_set,
        mode_count=_mode_count,
        tech_set=_tech_set,
    )

    # ── ③ 开始执行 ──
    print(f"  [OK] 开始执行 {_plan_count} 个攻击计划...\n")

    from src.scenarios.adaptive_runner import run_adaptive_scenario_async

    # P1-1: max_attempts_per_objective — env > pipeline.yaml > default(5)
    _max_attempts = int(os.getenv("MAX_ATTEMPTS_PER_OBJECTIVE", "") or ctx.config_loader.get_pipeline_defaults().get("max_attempts_per_objective", 5))
    # P0-1: L2/L3 停止策略参数从 pipeline.yaml 读取
    _owasp_threshold = ctx.config_loader.get_owasp_success_threshold()
    _stop_on_first = ctx.config_loader.get_stop_on_first_success()

    ctx.adaptive_result = await run_adaptive_scenario_async(
        objective_target=ctx.objective_target,
        judge_target=ctx.judge_target,
        attack_plans=ctx.attack_plans,
        owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
        exam_id=ctx.exam_id,
        max_attempts_per_objective=_max_attempts,
        per_attack_timeout=ctx.per_attack_timeout,
        max_retries=ctx.scenario_max_retries,
        verbose=ctx.verbose,
        converter_target=ctx.converter_target,
        target_type=ctx.target_type,
        max_concurrency=ctx.adaptive_max_concurrency,
        strategy_mode=ctx.strategy_info.get("strategy_mode", "academic"),
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        model_tier=ctx.strategy_info.get("model_tier", ctx.model_tier),
        owasp_success_threshold=_owasp_threshold,
        stop_on_first_success=_stop_on_first,
    )
    ctx.batch_result = ctx.adaptive_result.batch_result

    # ── 从执行结果构建停止策略统计 (供 Stage 6 展示) ──
    _populate_stop_context(ctx)

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


def _populate_stop_context(ctx: PipelineContext) -> None:
    """
    从执行结果构建停止策略统计 (供 Stage 6 展示)

    Pipeline 数据流修复: RuntimeStopEventHandler 设计为运行时事件处理器,
    但 AdaptiveScenario 内部执行时无法直接注入。本函数在执行完成后,
    从 batch_result + native_result 后处理构建 StopStrategyContext,
    使 Stage 6 的 _display_stop_stats() 能展示有意义的停止策略统计。

    L2/L3 停止的实际执行由 adaptive_runner 的预过滤完成,
    本函数仅用于展示层面的统计汇总。
    """
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    try:
        from src.scenarios.runtime_stop_handler import StopStrategyContext

        stop_ctx = StopStrategyContext()
        native_result = ctx.adaptive_result.native_result

        if not hasattr(native_result, "get_display_groups"):
            return

        display_groups = native_result.get_display_groups()
        for _group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue

                # 从 memory_labels 提取 OWASP ID
                owasp_id = "UNKNOWN"
                labels = getattr(r, "memory_labels", {}) or {}
                if isinstance(labels, dict):
                    owasp_id = labels.get("owasp_id", "UNKNOWN")
                else:
                    # PyRIT MemoryLabels 对象
                    try:
                        owasp_id = labels.get("owasp_id", "UNKNOWN")
                    except Exception:
                        pass

                stop_ctx.record_attempt(owasp_id)

                outcome = getattr(r, "outcome", None)
                outcome_str = (
                    str(outcome.value).upper()
                    if hasattr(outcome, "value")
                    else str(outcome).upper()
                )
                if outcome_str == "SUCCESS":
                    stop_ctx.record_success(owasp_id)

        ctx.stop_context = stop_ctx
    except Exception:
        pass
