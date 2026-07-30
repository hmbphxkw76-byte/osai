"""
Stage 2/7: Strategy 策略层
=========================

策略选择 + ASR引导策略分析 + ASR经验加载。

显示架构 (v8.0 优化 — 载荷驱动 + 高 ASR 导向):
  ① 策略决策                     — 合并旧 ASR策略分析 + 攻击策略分析
  ② ★ 技术池矩阵 — 高 ASR 优先 ★  — 按技术卡片，ASR降序，经验反馈融入
  ③ ★ 传递到 Target 接入 ★      — 最终结果摘要（决定后续攻击成功率）

设计原则:
  - 以技术池为驱动：以策略选择的技术为展示核心单元
  - 高 ASR 导向：每个技术卡片标注 ASR + Tier，按 ASR 降序排列
  - 参照 executor 卡片风格：┏━ 粗线框 + ◆ 技术头 + ┌─ 子区域 + ①②③ 编号
  - 传递结果突出展示：策略模式 + 技术池 + warm_start 决定后续攻击成功率
"""

from typing import Any

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.core.models import AuthResult, AuthStatus, AuthType
from src.analysis import select_strategy
from src.analysis.strategy_selector import StrategySelector

# ── 统一卡片宽度（双线框，与 executor/Stage 4 一致） ──
_W = 68

_TIER_LABELS = {"S": "极高", "A": "高", "B": "中", "C": "低", "D": "极低"}

_TIER_DESCRIPTIONS = {
    "S": "多轮迭代攻击 (极高)",
    "A": "树搜索/迭代/模拟对话 (高)",
    "B": "说服/角色扮演/包装 (中)",
    "C": "编码变换/基线 (低, 兜底)",
    "D": "极低 (兜底尝试 — ASR 非零即值得尝试)",
}

_MODE_CN = {
    "multi_turn": "多轮迭代",
    "single_turn": "单轮直发",
    "sequential": "顺序组合",
    "converter_enhanced": "Converter增强",
}

_TIER_INFERENCE = {
    "strong": "强过滤模型 → 策略攻击为主, 编码低效",
    "moderate": "中等过滤 → 策略+编码交替",
    "weak": "弱过滤 → 编码攻击也可生效",
    "unknown": "未知 → 默认强过滤策略",
}


# ============================================================
# 辅助函数
# ============================================================


def _cjk_width(s: str) -> int:
    """近似计算字符串显示宽度（CJK 字符算 2 列）"""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def _pad_right(s: str, width: int) -> str:
    """将字符串填充到指定显示宽度"""
    w = _cjk_width(s)
    return s + " " * max(0, width - w)


def _get_tech_asr(
    tech: str,
    model_name: str,
    warm_start: dict[str, float] | None = None,
) -> tuple[float, str]:
    """获取技术的 ASR 和 Tier (warm_start 优先, 回退学术先验)"""
    try:
        from src.payloads.technique_name_mapper import (
            get_normalized_asr,
            normalize_technique_name,
        )
        from src.payloads.asr_prior_registry import tier_from_asr

        normalized = normalize_technique_name(tech)
        if warm_start and normalized in warm_start:
            asr = warm_start[normalized]
        else:
            asr = get_normalized_asr(tech, model_name)
        tier = tier_from_asr(asr)
        return asr, tier
    except Exception:
        return 0.0, "D"


def _format_tech_display(tech: str) -> str:
    """格式化技术名显示（snake_case + PascalCase 双命名）"""
    try:
        from src.reporting.converter_log import format_technique_display
        return format_technique_display(tech)
    except Exception:
        return tech


def _is_multi_turn_tech(tech: str) -> bool:
    """判断技术是否为多轮技术"""
    multi_turn_set = {
        "red_teaming", "crescendo", "tap", "pair",
        "tree_of_attacks_pruned", "many_shot",
    }
    return tech in multi_turn_set


# ============================================================
# ① 策略决策
# ============================================================


def _display_strategy_decision(ctx: PipelineContext) -> None:
    """① 策略决策 — 合并旧 ASR策略分析 + 攻击策略分析"""

    strategy_mode = ctx.strategy_info.get("strategy_mode", "academic")
    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    model_tier = ctx.strategy_info.get("model_tier", ctx.model_tier)

    mode_desc = {
        "academic": "学术先验驱动 (策略优先, 高 ASR 技术优先尝试)",
        "exam": "考试模式 (编码优先, 快速验证基础安全)",
        "balanced": "均衡模式 (策略+编码交替)",
    }
    tier_desc = _TIER_INFERENCE.get(model_tier, model_tier)

    # 探测来源
    probe_source = ""
    probe_detail = getattr(ctx.recon_result, "model_tier_probe_detail", None)
    if probe_detail:
        probe_source = "动态探针 (3-step gradient probe)"
    elif model_tier != "unknown":
        probe_source = "静态模型名推断"

    lines = [
        f"目标模型:   {model_name}",
        f"模型分层:   {model_tier} ({tier_desc})",
    ]
    if probe_source:
        lines.append(f"探测来源:   {probe_source}")
    lines.append("")
    lines.append(f"策略模式:   {strategy_mode}")
    lines.append(f"  → {mode_desc.get(strategy_mode, '未知')}")

    # P3-2: 策略模式决策链 — 完整决策路径 + 矛盾标注
    import os as _os
    _env_mode = _os.getenv("STRATEGY_MODE", "")  # 仅检查 .env 显式覆盖
    _stage1_rec = "exam" if model_tier == "weak" else (
        "balanced" if model_tier == "moderate" else "academic"
    )

    if strategy_mode == ctx.recommended_mode:
        lines.append(
            f"推荐模式:   {ctx.recommended_mode} ✓ 与自动推荐一致 "
            f"(model_tier={model_tier})"
        )
    elif _env_mode:
        lines.append(
            f"推荐模式:   {ctx.recommended_mode} (model_tier={model_tier} → 自动推荐)"
        )
        lines.append(
            f"  ⚠ 环境变量 STRATEGY_MODE={_env_mode} 覆盖自动推荐"
        )
    else:
        # P3-2: 推荐模式与实际模式不一致 (无 env 覆盖)
        lines.append(
            f"推荐模式:   {ctx.recommended_mode} (model_tier={model_tier})"
        )
        lines.append(
            f"  ⚠ 实际使用: {strategy_mode} (默认值, STRATEGY_MODE 未设置)"
        )
        lines.append(
            f"  决策链: Stage 1 推荐 {_stage1_rec} → "
            f"StrategySelector 推荐 {ctx.recommended_mode} → "
            f"实际 {strategy_mode}"
        )
        lines.append(
            f"  建议: 设置 STRATEGY_MODE={ctx.recommended_mode} 以跟随推荐"
        )
    lines.append("")
    lines.append(f"Scenario:   {ctx.strategy_selection.scenario_name}")
    n_tech = len(ctx.strategy_selection.attack_techniques)
    lines.append(f"技术池:     {n_tech} 种 → 按 ASR 降序展示 (见下方矩阵)")

    info_box("策略决策", lines)


# ============================================================
# ② 技术池矩阵 — 高 ASR 优先
# ============================================================


def _display_tech_pool_matrix(ctx: PipelineContext) -> None:
    """② 技术池矩阵 — 按技术卡片，ASR降序，经验反馈融入"""

    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    warm_start = ctx.warm_start_asr or None
    techniques = ctx.strategy_selection.attack_techniques

    if not techniques:
        print("  [!] 无技术池数据")
        return

    # 构建技术信息
    tech_infos: list[dict[str, Any]] = []
    for tech in techniques:
        asr, tier = _get_tech_asr(tech, model_name, warm_start)
        is_multi = _is_multi_turn_tech(tech)

        # 经验数据
        emp_asr = None
        emp_attempts = 0
        if ctx.empirical_asr_data:
            emp_techs = ctx.empirical_asr_data.get("techniques", {})
            from src.payloads.technique_name_mapper import normalize_technique_name
            normalized = normalize_technique_name(tech)
            emp_data = emp_techs.get(normalized) or emp_techs.get(tech)
            if emp_data:
                emp_asr = emp_data.get("empirical_asr", 0.0)
                emp_attempts = emp_data.get("attempts", 0)

        # patched 检测
        is_patched = False
        patched_delta = None
        if ctx.patched_techniques:
            from src.payloads.technique_name_mapper import normalize_technique_name
            normalized = normalize_technique_name(tech)
            for p in ctx.patched_techniques:
                if p.get("technique") == normalized or p.get("technique") == tech:
                    is_patched = True
                    patched_delta = p.get("delta", 0)
                    break

        # 能力匹配
        caps = getattr(ctx.recon_result, "capabilities", None)
        caps_mt = getattr(caps, "supports_multi_turn", False) if caps else False
        caps_sp = getattr(caps, "supports_system_prompt", False) if caps else False

        # 过滤结果
        if is_multi and not caps_mt:
            filtered = "过滤 (目标不支持 multi_turn)"
        elif tech == "skeleton" and not caps_sp:
            filtered = "过滤 (目标不支持 system_prompt)"
        else:
            filtered = "保留"

        tech_infos.append({
            "tech": tech,
            "display": _format_tech_display(tech),
            "asr": asr,
            "tier": tier,
            "is_multi": is_multi,
            "emp_asr": emp_asr,
            "emp_attempts": emp_attempts,
            "is_patched": is_patched,
            "patched_delta": patched_delta,
            "caps_mt": caps_mt,
            "caps_sp": caps_sp,
            "filtered": filtered,
        })

    # 按 ASR 降序排序
    tech_infos.sort(key=lambda x: -x["asr"])

    # Banner
    _asr_label = "经验融合 ASR" if warm_start else "学术 ASR"
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  技术池矩阵 — 高 ASR 优先  ★")
    print()
    print(f"    按 {_asr_label} 降序展示 · 高成功率技术优先执行")
    print()
    print("  ╚" + "═" * _W + "╝")

    # 全局概览
    tier_counts: dict[str, int] = {}
    for ti in tech_infos:
        tier_counts[ti["tier"]] = tier_counts.get(ti["tier"], 0) + 1
    tier_summary = " ".join(
        f"{t}={tier_counts.get(t, 0)}"
        for t in ["S", "A", "B", "C", "D"]
        if tier_counts.get(t, 0) > 0
    )
    n_patched = sum(1 for ti in tech_infos if ti["is_patched"])
    n_filtered = sum(1 for ti in tech_infos if "过滤" in ti["filtered"])

    print()
    print(f"  ┌─ 全局概览 {'─' * max(1, _W - 22)}┐")
    print("  │")
    for i, ti in enumerate(tech_infos):
        tech_pad = _pad_right(ti["tech"][:20], 20)
        patch_mark = " ⚠" if ti["is_patched"] else ""
        filt_mark = " [过滤]" if "过滤" in ti["filtered"] else ""
        print(
            f"  │  技术 {i + 1}: {tech_pad}  "
            f"ASR {ti['asr']:>4.0%} (Tier {ti['tier']})"
            f"{patch_mark}{filt_mark}"
        )
    print(f"  │  {'─' * max(1, _W - 6)}")
    print(f"  │  合计: {len(tech_infos)} 技术 | Tier 分布: {tier_summary}")
    if n_patched:
        print(f"  │  Patched: {n_patched} 个技术 (经验ASR大幅低于学术先验)")
    if n_filtered:
        print(f"  │  过滤: {n_filtered} 个技术 (能力不匹配)")
    print(f"  └{'─' * _W}┘")

    # 每个技术卡片
    for ti in tech_infos:
        display = ti["display"]
        asr = ti["asr"]
        tier = ti["tier"]
        mode_str = "多轮迭代" if ti["is_multi"] else "单轮直发"

        # ── 卡片头 ──
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {display}")
        patch_str = "  [PATCHED] ⚠" if ti["is_patched"] else ""
        filt_str = (
            f"  [{ti['filtered']}]" if "过滤" in ti["filtered"] else ""
        )
        print(
            f"  ┃    ASR: {asr:.0%} (Tier {tier} "
            f"{_TIER_LABELS.get(tier, '')})  |  模式: {mode_str}"
            f"{patch_str}{filt_str}"
        )
        print(f"  ┃    {_TIER_DESCRIPTIONS.get(tier, '')}")
        print("  ┃")

        # ── ASR 来源 ──
        asr_hdr = "ASR 来源"
        asr_dashes = max(1, _W - 6 - _cjk_width(asr_hdr) - 2)
        print(f"  ┃    ┌─ {asr_hdr} {'─' * asr_dashes}┐")

        # 学术先验
        try:
            from src.payloads.technique_name_mapper import (
                get_normalized_asr,
                normalize_technique_name,
            )
            normalized = normalize_technique_name(ti["tech"])
            academic_asr = get_normalized_asr(ti["tech"], model_name)
        except Exception:
            academic_asr = asr
            normalized = ti["tech"]

        print(f"  ┃    │ 学术先验: {academic_asr:.0%}")

        # 经验数据
        if ti["emp_asr"] is not None and ti["emp_attempts"] > 0:
            delta = ti["emp_asr"] - academic_asr
            delta_str = f"Δ {delta:+.0%}"
            if delta < -0.1:
                delta_str += " ↓"
            elif delta > 0.1:
                delta_str += " ↑"
            print(
                f"  ┃    │ 经验数据: {ti['emp_asr']:.0%} "
                f"({ti['emp_attempts']} 次尝试, {delta_str})"
            )
        else:
            print("  ┃    │ 经验数据: 无 (首次运行)")

        # patched 详情
        if ti["is_patched"] and ti["patched_delta"] is not None:
            print(
                f"  ┃    │ Patched: 学术 {academic_asr:.0%} → 实测 "
                f"{ti['emp_asr'] or 0:.0%} "
                f"(Δ {ti['patched_delta']:+.0%}), 建议降低优先级"
            )

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # ── 能力匹配 ──
        cap_hdr = "能力匹配"
        cap_dashes = max(1, _W - 6 - _cjk_width(cap_hdr) - 2)
        print(f"  ┃    ┌─ {cap_hdr} {'─' * cap_dashes}┐")

        mt_str = "✓" if ti["caps_mt"] else "✗"
        sp_str = "✓" if ti["caps_sp"] else "✗"
        need_mt = "需要" if ti["is_multi"] else "不需要"
        need_sp = "需要" if ti["tech"] == "skeleton" else "不需要"

        print(
            f"  ┃    │ MULTI_TURN: {mt_str} (技术{need_mt})  "
            f"|  SYSTEM_PROMPT: {sp_str} (技术{need_sp})"
        )

        if "过滤" in ti["filtered"]:
            print(f"  ┃    │ 结果: ✗ {ti['filtered']}")
        else:
            print("  ┃    │ 结果: ✓ 保留 (能力匹配)")

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        print("  ┗" + "━" * _W)


# ============================================================
# ③ 传递到 Target 接入 — 突出展示
# ============================================================


def _display_handoff(ctx: PipelineContext) -> None:
    """③ 传递到 Target 接入 — 最终结果摘要（★ 突出展示 ★）"""

    strategy_mode = ctx.strategy_info.get("strategy_mode", "academic")
    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    techniques = ctx.strategy_selection.attack_techniques

    # Tier 分布统计
    tier_counts: dict[str, int] = {}
    for tech in techniques:
        asr, tier = _get_tech_asr(
            tech, model_name, ctx.warm_start_asr or None
        )
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    tier_summary = " ".join(
        f"{t}={tier_counts.get(t, 0)}"
        for t in ["S", "A", "B", "C", "D"]
        if tier_counts.get(t, 0) > 0
    )

    n_patched = len(ctx.patched_techniques) if ctx.patched_techniques else 0

    # warm_start 信息
    if ctx.empirical_asr_data:
        run_count = ctx.empirical_asr_data.get("run_count", 0)
        from src.scenarios.empirical_asr_store import _get_empirical_weight
        weight = _get_empirical_weight(run_count)
        warm_str = f"warm_start 已加载 ({run_count} 次经验, 权重={weight:.0%})"
    else:
        warm_str = "无 (首次运行, 使用纯学术先验)"

    # Banner
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  传递到 Target 接入 — 决定后续攻击成功率  ★")
    print()
    print("  ╚" + "═" * _W + "╝")

    lines = [
        f"★ 策略模式: {strategy_mode} → 影响 Tier 执行顺序",
        f"★ 技术池: {len(techniques)} 种 ({tier_summary}) → 能力感知筛选后保留",
        f"★ 融合 ASR: {warm_str}",
    ]
    if n_patched:
        lines.append(
            f"★ Patched: {n_patched} 个技术标记 → 降低优先级"
        )
    owasp_str = (
        ", ".join(ctx.owasp_ids) if ctx.owasp_ids else "全部 OWASP"
    )
    lines.append(f"★ 预期载荷: {owasp_str} → 载荷预映射")

    info_box("传递到 Target 接入 (Stage 3)", lines)


# ============================================================
# 主流程
# ============================================================


async def run(ctx: PipelineContext) -> None:
    """执行分析阶段"""
    stage_header(2, "Strategy 策略层", "策略选择 + ASR经验加载")

    # ── 策略选择 (纯逻辑) ──
    ctx.auth_result = AuthResult(
        target_url=ctx.target_url,
        auth_type=AuthType.NONE,
        status=AuthStatus.SUCCESS,
        auth_headers={"Content-Type": "application/json"},
    )

    ctx.strategy_selection = select_strategy(ctx.auth_result, ctx.recon_result)
    ctx.recommended_mode = StrategySelector.recommend_strategy_mode(ctx.recon_result)

    # P0-B: 统一模型名来源 — 先构建 strategy_info, 再用其加载经验 ASR
    from src.scenarios.asr_strategy_display import _get_strategy_mode, _get_model_name

    strategy_mode = _get_strategy_mode()
    model_name = _get_model_name(ctx.target_model)

    # 优先使用探测式分层，回退静态推断
    if ctx.recon_result is not None and getattr(
        ctx.recon_result, "model_tier", "unknown"
    ) != "unknown":
        model_tier = ctx.recon_result.model_tier
    else:
        from src.scenarios.asr_strategy_display import _infer_model_tier
        model_tier = _infer_model_tier(model_name)

    ctx.strategy_info = {
        "strategy_mode": strategy_mode,
        "model_name": model_name,
        "model_tier": model_tier,
    }

    # ── L5 ASR 反馈回路 Tier 2: 加载经验 ASR (warm-start) ──
    # P0-B: 使用 strategy_info["model_name"] 而非 ctx.target_model
    from src.scenarios.empirical_asr_store import (
        load_empirical_asr,
        compute_effective_asr,
        detect_patched_techniques,
    )
    ctx.empirical_asr_data = load_empirical_asr(model_name)

    # 计算融合 ASR (学术 × 经验)
    if ctx.empirical_asr_data:
        from src.payloads.technique_name_mapper import get_normalized_asr
        from src.payloads.asr_prior_registry import get_all_priors
        academic_map = {
            tech_name: get_normalized_asr(
                tech_name, ctx.target_model
            )
            for tech_name in get_all_priors()
        }
        ctx.warm_start_asr = {
            tech: compute_effective_asr(
                tech, model_name, acad, ctx.empirical_asr_data
            )
            for tech, acad in academic_map.items()
        }
        # 检测 patched 技术
        ctx.patched_techniques = detect_patched_techniques(
            academic_map, ctx.empirical_asr_data,
        )
        # 生成策略建议 (存入 ctx，不再独立展示 box)
        from src.scenarios.empirical_asr_store import (
            generate_strategy_recommendation,
        )
        ctx.strategy_recommendations = generate_strategy_recommendation(
            model_name,
            ctx.empirical_asr_data,
            academic_map,
            ctx.patched_techniques,
        )

    # ── ① 策略决策 ──
    _display_strategy_decision(ctx)

    # ── ② 技术池矩阵 ──
    _display_tech_pool_matrix(ctx)

    # ── ③ 传递到 Target 接入 (★ 突出展示 ★) ──
    _display_handoff(ctx)

    # P2-A: 阶段间衔接行
    from pipeline.display import handoff_line
    _n_tech_s2 = len(ctx.strategy_selection.attack_techniques) if ctx.strategy_selection else 0
    _mode_s2 = ctx.strategy_info.get("strategy_mode", "academic")
    _tier_s2 = ctx.strategy_info.get("model_tier", "unknown")
    handoff_line(2, 3, f"策略={_mode_s2} | 模型分层={_tier_s2} | 技术池={_n_tech_s2} 种")
