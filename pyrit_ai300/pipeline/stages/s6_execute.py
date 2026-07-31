"""
Stage 5/7: Executor 执行层
=========================

原生 AdaptiveScenario 批量执行。

显示架构 (v10.0 L5专家级 — 数据驱动+ASR导向+承上启下):
  ① 执行配置 + 攻击计划摘要       — 全局统计
  ② 执行策略                     — 失败路由 + 停止策略 (技术排序移入决策摘要)
  ③ ★ 载荷 × Converter 变体交叉组合 ★  — v4.0 承上启下 (6 区精简)
  ④ [OK] 开始执行...
  ⑤ 执行结果概要               — 统计 + 失败类型
  ⑥ 逐载荷执行结果 (★ 风格)     — 每个载荷成功/失败+对话摘要
  ⑦ Per-Group Breakdown        — 执行后按组统计
"""

import logging
import os
from typing import Any

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header
from src.reporting.converter_log import format_technique_display

logger = logging.getLogger(__name__)

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


def _sort_tech_by_asr(
    tech_counts: dict[str, int],
    model_name: str,
    warm_start: dict[str, float] | None = None,
) -> list[tuple[str, int]]:
    """按 ASR 降序排序技术（高 ASR 优先），ASR 相同时按计划数降序

    P1 修复: 使用 warm_start ASR (与 Stage 2/4 一致), 回退学术先验
    """
    try:
        from src.payloads.technique_name_mapper import (
            get_normalized_asr,
            normalize_technique_name,
        )

        def _asr_key(tech_name: str) -> float:
            if warm_start:
                normalized = normalize_technique_name(tech_name)
                if normalized in warm_start:
                    return -warm_start[normalized]
            return -get_normalized_asr(tech_name, model_name)

        return sorted(tech_counts.items(), key=lambda x: (_asr_key(x[0]), -x[1]))
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

    每条链返回: {name, desc, llm, priority, source}
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
    # 同时记录来源 (P0-1: 链来源标注)
    all_chain_names: list[str] = []
    chain_sources: dict[str, str] = {}
    seen = set()

    for cn in payload_chains:
        if cn not in seen:
            all_chain_names.append(cn)
            chain_sources[cn] = "payload"
            seen.add(cn)
    for cn in static_chains:
        if cn not in seen:
            all_chain_names.append(cn)
            chain_sources[cn] = "static"
            seen.add(cn)
    for cn in dynamic_chains:
        if cn not in seen:
            all_chain_names.append(cn)
            chain_sources[cn] = "router"
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
            "source": chain_sources.get(cn, "unknown"),
        })
    chains_info.sort(key=lambda x: x["priority"])
    return chains_info


def _get_tech_asr_value(
    tech: str,
    model_name: str,
    warm_start: dict[str, float] | None,
    get_normalized_asr: Any,
) -> tuple[float | None, str]:
    """获取技术 ASR 值和标签 (P3-1: 统一标签)

    Returns: (asr_value, asr_tag)
    - 有 warm_start 数据时: (融合值, "融合 ASR")
    - 无 warm_start 时:    (学术值, "学术 ASR")
    """
    _asr_val = None
    _has_warm = False
    if warm_start:
        try:
            from src.payloads.technique_name_mapper import normalize_technique_name
            _norm = normalize_technique_name(tech)
            if _norm in warm_start:
                _asr_val = warm_start[_norm]
                _has_warm = True
        except Exception:
            pass
    if _asr_val is None and get_normalized_asr:
        try:
            _asr_val = get_normalized_asr(tech, model_name)
        except Exception:
            pass
    _asr_tag = "融合 ASR" if _has_warm else "学术 ASR"
    return _asr_val, _asr_tag


def _display_unified_attack_matrix(
    attack_plans: list[Any],
    *,
    strategy_info: dict[str, Any],
    target_type: str = "",
    converter_chains_from_router: list[str] | None = None,
    owasp_set: dict[str, int] | None = None,
    mode_count: dict[str, int] | None = None,
    tech_set: dict[str, int] | None = None,
    warm_start: dict[str, float] | None = None,
    owasp_success_threshold: float = 0.0,
    stop_on_first_success: bool = False,
    stage4_tech_asr: dict[str, float] | None = None,
) -> None:
    """
    载荷 × Converter 变体交叉组合矩阵展示 (v4.0 — L5专家级承上启下)

    展示结构 (6 区):
      1. 承上启下 Banner — 上下文标注 (Stage 2/3/4 → Stage 5) + 链来源分解
      2. 决策摘要 — 关键指标 + 技术映射桥接 + ASR加权预期 + 高ASR预警 + 降级链
      3. 共享 Converter 变体池 — 全局展示一次 + 来源标注 + 跳过标注 + 增益预估
      4. 逐技术卡片 (精简 3 区):
         a. 技术头 (名称/ASR/Tier/公式/承上启下 + OWASP分布)
         b. 载荷详情 (PID/severity/Source/Target — severity一致展示)
         c. 技术专属 Converter 差异
      5. 执行预算桥接 — AtomicAttack vs 变体尝试 + 时间预估
    """
    from src.scenarios.technique_factories import AI300_TECHNIQUE_METADATA

    _MODE_CN = {
        "multi_turn": "多轮迭代",
        "single_turn": "单轮直发",
        "sequential": "顺序组合",
        "converter_enhanced": "Converter增强",
    }

    _CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩"

    _TIER_ICON = {"S": "◆", "A": "◆", "B": "◇", "C": "○", "D": "○"}

    # ── 技术 ASR 查询 (惰性导入) ──
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr
        from src.scenarios.asr_strategy_display import _get_tier
    except Exception:
        get_normalized_asr = None  # type: ignore
        _get_tier = None  # type: ignore

    model_name = strategy_info.get("model_name", "")
    model_tier = strategy_info.get("model_tier", "unknown")

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

    # ── ASR 降序排序 (P1: 使用 warm_start, 与 Stage 2/4 一致) ──
    def _asr_sort_for_display(tech_name: str) -> float:
        _asr_v, _ = _get_tech_asr_value(
            tech_name, model_name, warm_start, get_normalized_asr,
        )
        return -_asr_v if _asr_v is not None else 0.0

    sorted_techs = sorted(payload_groups.keys(), key=_asr_sort_for_display)

    # ── 计算全局统计 ──
    total_payloads = sum(len(payload_groups[t]) for t in sorted_techs)
    total_attempts = sum(
        len(payload_groups[t]) * (len(tech_chains[t]) + 1)
        for t in sorted_techs
    )

    # ── 全局载荷编号映射 (P1, P2, ... 贯穿全阶段) ──
    plan_to_pid: dict[int, str] = {}
    for g_idx, p in enumerate(attack_plans):
        plan_to_pid[id(p)] = f"P{g_idx + 1}"

    # ── 共享 Converter 链集合 (所有技术的并集) ──
    shared_chain_names: set[str] = set()
    for tech in sorted_techs:
        for ci in tech_chains[tech]:
            shared_chain_names.add(ci["name"])
    _shared_chains_ref: list[dict[str, Any]] = []
    if sorted_techs:
        _shared_chains_ref = list(tech_chains[sorted_techs[0]])

    # P0-1: 链来源分解 — 区分路由链 vs 静态映射
    _router_chain_set = set(converter_chains_from_router) if converter_chains_from_router else set()
    _router_chains_in_pool = [c for c in _shared_chains_ref if c["name"] in _router_chain_set]
    _static_chains_in_pool = [c for c in _shared_chains_ref if c["name"] not in _router_chain_set]

    # P0-3: 弱模型时 LLM 链将被跳过
    _skip_llm = model_tier in ("weak", "unknown")
    _llm_chains_in_pool = [c for c in _shared_chains_ref if c["llm"]]
    _non_llm_chains_in_pool = [c for c in _shared_chains_ref if not c["llm"]]
    _effective_chains = _non_llm_chains_in_pool if _skip_llm else _shared_chains_ref
    _n_effective_variants = len(_effective_chains) + 1

    # P0-2: AtomicAttack 估计 (PyRIT 渐进式, 非预生成)
    _est_atomic_attacks = total_payloads + 1

    # P4-1: ASR 加权预期
    _weighted_asr = 0.0
    for tech in sorted_techs:
        _asr_v, _ = _get_tech_asr_value(tech, model_name, warm_start, get_normalized_asr)
        if _asr_v is not None:
            _tech_payloads = len(payload_groups[tech])
            _weighted_asr += _asr_v * (_tech_payloads / total_payloads if total_payloads > 0 else 0)

    # P4-2: 变体增益预估
    _baseline_asr = _weighted_asr
    _p1_gain = _baseline_asr * 4 if _baseline_asr > 0 else 0.08
    _p2_gain = _baseline_asr * 2.5 if _baseline_asr > 0 else 0.05
    _p3_gain = _baseline_asr * 1.5 if _baseline_asr > 0 else 0.03
    _est_final_asr = min(0.95, _baseline_asr + _p1_gain * 0.3 + _p2_gain * 0.2 + _p3_gain * 0.1)

    # P4-3: 时间预估
    _avg_time_per_attack = 45
    _est_time_min = (_est_atomic_attacks * _avg_time_per_attack) / 60
    _est_time_max = (_est_atomic_attacks * _avg_time_per_attack * 2) / 60

    # ════════════════════════════════════════════════════════════════
    # 1. 承上启下 Banner (P1-A + P2-1: 链来源修正)
    # ════════════════════════════════════════════════════════════════
    _n_router_chains = len(converter_chains_from_router) if converter_chains_from_router else 0
    _n_static_chains = len(_static_chains_in_pool)
    _n_total_chains = len(_shared_chains_ref)
    _n_total_var = _n_total_chains + 1

    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  载荷 × Converter 变体交叉组合 — 承上启下  ★")
    print()
    print(f"    承上: Stage 4 → {total_payloads} 个攻击计划 | "
          f"Stage 3 → {_n_router_chains} 路由链")
    if _n_static_chains > 0:
        print(f"          + {_n_static_chains} 静态映射 = {_n_total_chains} 有效链")
    print(f"    启下: → Stage 5 执行依据 "
          f"({_est_atomic_attacks} AtomicAttack, "
          f"{total_attempts} 变体尝试上限)")
    print("    机制: extra_request_converters 渐进式追加 (非预生成)")
    print("    停止: FIRST_SUCCESS + L2/L3 → 实际远少于上限")
    print()
    print("  ╚" + "═" * _W + "╝")

    # ════════════════════════════════════════════════════════════════
    # 2. 决策摘要 (P1-B + P0-2 + P1-1 + P1-2 + P2-2 + P4-1)
    # ════════════════════════════════════════════════════════════════
    _n_high_asr = 0
    _tier_counts: dict[str, int] = {}
    for tech in sorted_techs:
        _asr_v, _ = _get_tech_asr_value(tech, model_name, warm_start, get_normalized_asr)
        _tier_str_local = "?"
        if _asr_v is not None and _get_tier:
            _tier_str_local = _get_tier(_asr_v)
        _tier_counts[_tier_str_local] = _tier_counts.get(_tier_str_local, 0) + 1
        if _tier_str_local in ("S", "A"):
            _n_high_asr += 1

    _est_actual = max(1, int(total_attempts * 0.35))

    print()
    print(f"  ┌─ 决策摘要 (承上启下) {'─' * max(1, _W - 32)}┐")
    print("  │")
    print(f"  │  ★ 总载荷:       {total_payloads} 个 (来自 Stage 4)")
    print(f"  │  ★ AtomicAttack:  {_est_atomic_attacks} 个 (PyRIT 注册: "
          f"1 baseline + {total_payloads} 载荷)")
    print(f"  │  ★ 变体尝试上限: {total_attempts} 次 "
          f"({total_payloads} × {_n_total_var}, 运行时渐进)")
    _eff_line = (f"  │  ★ 有效变体:     {_n_effective_variants} 个 "
                 f"(非LLM={len(_non_llm_chains_in_pool)+1}")
    if _skip_llm and _llm_chains_in_pool:
        _eff_line += f", 跳过LLM={len(_llm_chains_in_pool)})"
    else:
        _eff_line += ")"
    print(_eff_line)
    print(f"  │  ★ 高ASR技术:    {_n_high_asr} 种 Tier S/A (优先执行)")
    print(f"  │  ★ 预期实际:     ~{_est_actual} 次 "
          f"(FIRST_SUCCESS + L2/L3 停止)")

    # P4-1: ASR 加权预期
    print("  │")
    if _weighted_asr > 0:
        print(f"  │  ★ 加权预期 ASR: ~{_weighted_asr:.0%} "
              f"(Σ 技术ASR × 载荷占比)")
        if _est_final_asr > _weighted_asr:
            print(f"  │  ★ 变体增益后:  ~{_est_final_asr:.0%} "
                  f"(基线 {_weighted_asr:.0%} + Converter 增益)")

    # P1-1: 高 ASR 为零预警
    if _n_high_asr == 0 and total_payloads > 0:
        print("  │")
        print("  │  ⚠ 预警: 无 Tier S/A 技术 — 预期整体 ASR 极低")
        _tier_str_summary = " ".join(
            f"{t}={_tier_counts.get(t, 0)}"
            for t in ["S", "A", "B", "C", "D"]
            if _tier_counts.get(t, 0) > 0
        )
        print(f"  │    Tier 分布: {_tier_str_summary}")
        print("  │    建议: 1) 检查 Stage 4 技术映射")
        print("  │          2) 增加高 ASR 数据集 (airt.jailbreak)")
        print("  │          3) 启用 LLM 辅助链 (需强 Converter Target)")

    # P1-2: 技术映射桥接 (Stage 4 → 5)
    if stage4_tech_asr:
        _exec_techs = set(sorted_techs)
        _s4_only = set(stage4_tech_asr.keys()) - _exec_techs
        if _s4_only or _exec_techs != set(stage4_tech_asr.keys()):
            print("  │")
            print("  │  技术映射 (Stage 4 种子 → Stage 5 执行):")
            for s4_tech, s4_asr in sorted(stage4_tech_asr.items(), key=lambda x: -x[1]):
                _arrow = "→" if s4_tech not in _exec_techs else "="
                _exec_tech = sorted_techs[0] if sorted_techs else "?"
                _exec_asr_val, _ = _get_tech_asr_value(
                    _exec_tech, model_name, warm_start, get_normalized_asr,
                )
                _exec_asr_str = f"{_exec_asr_val:.0%}" if _exec_asr_val is not None else "?"
                if _arrow == "→":
                    print(f"  │    {s4_tech} ({s4_asr:.0%}) "
                          f"{_arrow} {_exec_tech} ({_exec_asr_str})  "
                          f"⚠ 降级")
                else:
                    print(f"  │    {s4_tech} ({s4_asr:.0%}) "
                          f"{_arrow} 直接执行")

    # P2-2: 降级链呼应
    print("  │")
    _degrade_parts = []
    for _t in ["S", "A", "B", "C", "D"]:
        _cnt = _tier_counts.get(_t, 0)
        if _cnt > 0:
            _degrade_parts.append(f"{_t}={_cnt}组")
    print(f"  │  降级链: {' → '.join(_degrade_parts)}")
    if _n_high_asr == 0:
        _lowest_tier = min(_tier_counts.keys()) if _tier_counts else "D"
        print(f"  │  ⚠ 无高 Tier 可降级 — 已在最低层 (Tier {_lowest_tier})")

    # 技术执行顺序 (P1-B, P3-1: 统一标签)
    print("  │")
    print("  │  执行顺序 (ASR 降序):")

    for i, tech in enumerate(sorted_techs):
        n_pl = len(payload_groups[tech])
        n_var = len(tech_chains[tech]) + 1
        n_att = n_pl * n_var

        _asr_v, _asr_tag = _get_tech_asr_value(
            tech, model_name, warm_start, get_normalized_asr,
        )
        _tier_str = "?"
        if _asr_v is not None and _get_tier:
            _tier_str = _get_tier(_asr_v)

        _asr_pct = f"{_asr_v:.0%}" if _asr_v is not None else "N/A"
        _icon = _TIER_ICON.get(_tier_str, "○")
        _priority_tag = ""
        if _tier_str in ("S", "A"):
            _priority_tag = "  ← 优先执行"
        elif _tier_str == "D":
            _priority_tag = "  ← 兜底"

        _seq_marker = _CIRCLED[i] if i < len(_CIRCLED) else str(i + 1) + "."
        tech_pad = _pad_right(tech[:22], 22)
        print(f"  │  {_icon} {_seq_marker} "
              f"[{_tier_str}] {tech_pad} "
              f"{_asr_pct:>4s}  {n_pl}×{n_var}={n_att}{_priority_tag}")

    print(f"  └{'─' * _W}┘")

    # ════════════════════════════════════════════════════════════════
    # 3. 共享 Converter 变体池 (P0-A + P0-1 + P0-3 + P3-4 + P4-2)
    # ════════════════════════════════════════════════════════════════
    if _shared_chains_ref:
        _n_non_llm = len(_non_llm_chains_in_pool)
        _n_llm = len(_llm_chains_in_pool)
        _n_total_conv = len(_shared_chains_ref)

        _prio_dist: dict[int, int] = {}
        for c in _shared_chains_ref:
            _prio_dist[c["priority"]] = _prio_dist.get(c["priority"], 0) + 1
        _prio_str = " → ".join(
            f"P{p}({_prio_dist[p]})" for p in sorted(_prio_dist)
        )

        print()
        print(f"  ┌─ 共享 Converter 变体池 (展示一次) "
              f"{'─' * max(1, _W - 38)}┐")
        print("  │")
        print(f"  │  总计: {_n_total_var} 个变体 "
              f"(1 基线 + {_n_total_conv} Converter 链)")

        # P0-1: 来源分解
        print("  │  来源分解:")
        print(f"  │    Stage 3 路由:  {len(_router_chains_in_pool)} 条 "
              f"(非LLM={sum(1 for c in _router_chains_in_pool if not c['llm'])}, "
              f"LLM={sum(1 for c in _router_chains_in_pool if c['llm'])})")
        if _static_chains_in_pool:
            _static_names = ", ".join(c["name"] for c in _static_chains_in_pool[:5])
            if len(_static_chains_in_pool) > 5:
                _static_names += f" ... ({len(_static_chains_in_pool)-5} more)"
            print(f"  │    静态映射追加: {len(_static_chains_in_pool)} 条 "
                  f"({_static_names})")

        # P0-3: 有效链计数 + 跳过标注
        if _skip_llm and _n_llm > 0:
            print(f"  │  有效: {_n_effective_variants} 个 "
                  f"(1 基线 + {_n_non_llm} 非LLM) | "
                  f"跳过: {_n_llm} LLM链 (弱模型)")
        else:
            print(f"  │  有效: {_n_total_var} 个 (全部保留)")

        print(f"  │  优先级分布: {_prio_str}")
        print("  │  尝试顺序: 基线 → P1链 → P2链 → P3链 → ... → "
              "✅首次成功即停止")

        # P4-2: 变体增益预估
        print("  │")
        print("  │  ASR 增益预估:")
        print(f"  │    基线:      {_baseline_asr:.0%} (无变换)")
        _p1_chains = [c for c in _effective_chains if c["priority"] == 1]
        _p2_chains = [c for c in _effective_chains if c["priority"] == 2]
        _p3_chains = [c for c in _effective_chains if c["priority"] == 3]
        if _p1_chains:
            print(f"  │    +P1链:    ~{_p1_gain:.0%} "
                  f"(编码绕过, {len(_p1_chains)}条非LLM)")
        if _p2_chains:
            print(f"  │    +P2链:    ~{_p2_gain:.0%} "
                  f"(编码+噪声, {len(_p2_chains)}条)")
        if _p3_chains:
            print(f"  │    +P3链:    ~{_p3_gain:.0%} "
                  f"(辅助变换, {len(_p3_chains)}条)")
        print(f"  │    最终预期: ~{_est_final_asr:.0%} "
              f"(首次成功即停)")

        # 链详情 (P0-3: 标注跳过)
        print("  │")
        print(f"  │  ┌─ 链详情 {'─' * max(1, _W - 22)}┐")
        print("  │  │ 基线        原文直发，无变换")
        for ci in _shared_chains_ref:
            llm_tag = "[非LLM]" if not ci["llm"] else "[LLM]  "
            _skip_tag = ""
            if _skip_llm and ci["llm"]:
                _skip_tag = "  [跳过]"
            _src_tag = ""
            if ci.get("source") == "static":
                _src_tag = "  [静态]"
            print(f"  │  │ 优先{ci['priority']} {llm_tag}  {ci['name']}"
                  f"{_src_tag}{_skip_tag}")
            if ci["desc"]:
                print(f"  │  │   └─ {ci['desc']}")
        print(f"  │  └{'─' * max(0, _W - 5)}┘")
        print(f"  └{'─' * _W}┘")

    # ════════════════════════════════════════════════════════════════
    # 4. 逐技术卡片 (P0-B + P2-B + P3-3) — 精简 3 区
    # ════════════════════════════════════════════════════════════════
    for tech_idx, tech in enumerate(sorted_techs):
        plans = payload_groups[tech]
        chains = tech_chains[tech]
        n_variants = len(chains) + 1

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

        # P3-1: 统一 ASR 标签
        _asr_val, _asr_tag = _get_tech_asr_value(
            tech, model_name, warm_start, get_normalized_asr,
        )
        _tier_str = "?"
        if _asr_val is not None and _get_tier:
            _tier_str = _get_tier(_asr_val)

        asr_pct = f"{_asr_val:.0%}" if _asr_val is not None else "N/A"
        tech_display = format_technique_display(tech)
        _icon = _TIER_ICON.get(_tier_str, "○")
        _priority_num = _CIRCLED[tech_idx] if tech_idx < len(_CIRCLED) else str(tech_idx + 1) + "."

        # P3-3: OWASP 分布提前计算 (移到技术头)
        owasp_dist: dict[str, int] = {}
        for p in plans:
            oid = getattr(p, "owasp_id", None) or "N/A"
            owasp_dist[oid] = owasp_dist.get(oid, 0) + 1
        owasp_str = ", ".join(
            f"{k}({v})" for k, v in sorted(owasp_dist.items())
        )

        # ── Zone 1: 技术头 (精简, 含公式+承上启下+OWASP) ──
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  {_icon} {_priority_num} {tech_display} · {tech_desc}")
        n_attempts = len(plans) * n_variants
        print(f"  ┃    [{_tier_str}] {_asr_tag}: {asr_pct} | {mode_detail} | "
              f"{len(plans)} 载荷 × {n_variants} 变体 = {n_attempts} 尝试")
        print(f"  ┃    OWASP: {owasp_str} | ← 承上: Stage 4 | 启下: AtomicAttack")

        # ── Zone 2: 载荷详情 (P3-3: severity 一致展示) ──
        print("  ┃")
        print(f"  ┃    ┌─ 载荷详情 {'─' * max(1, _W - 20)}┐")

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
            severity = meta_pi.get("severity", "N/A")
            pid = plan_to_pid.get(id(plan), f"P{idx + 1}")
            marker = (
                _CIRCLED[idx] if idx < len(_CIRCLED) else f"{idx + 1}."
            )

            sev_str = f"  ({severity})" if severity else "  (N/A)"
            if idx == 0:
                print(f"  ┃    │ {marker}{sev_str}  [{pid}]  "
                      f"Mode: {plan_mode_str}")
                print(f"  ┃    │   Source: {src_short}")
            else:
                print(f"  ┃    │ {marker}{sev_str}  [{pid}]  "
                      f"Mode: {plan_mode_str}")
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

        # ── Zone 3: 技术专属 Converter 差异 (P2-B + P3-4) ──
        _tech_chain_names = {ci["name"] for ci in chains}
        _extra_chains = _tech_chain_names - shared_chain_names
        _missing_chains = shared_chain_names - _tech_chain_names

        diff_hdr = "技术专属 Converter (与共享池差异)"
        diff_dashes = max(0, _W - 6 - _cjk_width(diff_hdr) - 2)
        print(f"  ┃    ┌─ {diff_hdr} {'─' * diff_dashes}┐")

        if not _extra_chains and not _missing_chains:
            print(f"  ┃    │ 共享池: {_n_total_var} 变体 "
                  f"(见上方共享区块)")
            print("  ┃    │ 本技术: 与共享池一致, 无差异")
        else:
            print(f"  ┃    │ 共享池: {_n_total_var} 变体 "
                  f"(见上方共享区块)")
            if _extra_chains:
                print(f"  ┃    │ 本技术额外: +{len(_extra_chains)} 条")
                for ec in sorted(_extra_chains)[:5]:
                    ci_next = next(
                        (c for c in chains if c["name"] == ec), None
                    )
                    if ci_next:
                        llm_tag = "[非LLM]" if not ci_next["llm"] else "[LLM]"
                        print(f"  ┃    │   + 优先{ci_next['priority']} "
                              f"{llm_tag} {ec}")
            if _missing_chains:
                print(f"  ┃    │ 本技术跳过: -{len(_missing_chains)} 条")
                for mc in sorted(_missing_chains)[:5]:
                    print(f"  ┃    │   - {mc}")

        if raw_mode == "multi_turn":
            print(f"  ┃    │ 执行: {tech} 逐轮升级 → "
                  f"末轮注入 Converter → 首次成功即停止")
        elif raw_mode == "sequential":
            print("  ┃    │ 执行: 顺序各步 → 独立评分 → "
                  "全部成功则整体成功")
        else:
            print(f"  ┃    │ 执行: {tech} + Converter → "
                  f"按优先级依次尝试 → 首次成功即停止")

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")
        print("  ┗" + "━" * _W)

    # ════════════════════════════════════════════════════════════════
    # 5. 执行预算桥接 (P2-A + P0-2 + P2-3 + P4-3)
    # ════════════════════════════════════════════════════════════════
    _l2_str = (
        f"L2 OWASP 阈值 {owasp_success_threshold:.0%}"
        if owasp_success_threshold > 0
        else "L2 未启用"
    )
    _l3_str = "L3 全局首成功 (已启用)" if stop_on_first_success else "L3 未启用"

    print()
    print(f"  ┌─ 执行预算 → 启下 PyRIT 解析 {'─' * max(1, _W - 36)}┐")
    print("  │")
    print(f"  │  AtomicAttack:  {_est_atomic_attacks} 个 "
          f"(进度条 total ← PyRIT 注册)")
    print(f"  │  变体尝试上限: {total_attempts} 次 "
          f"({total_payloads} × {_n_total_var}, 运行时渐进)")
    print("  │  PyRIT 机制:   extra_request_converters 渐进式追加")
    print("  │                (非预生成所有组合)")
    print("  │  实际执行:     FIRST_SUCCESS → "
          "首次成功即跳过剩余变体")
    print(f"  │  停止策略:     {_l2_str} | {_l3_str}")
    print("  │")
    print(f"  │  时间预估:     ~{_est_time_min:.0f}-{_est_time_max:.0f} 分钟 "
          f"({_est_atomic_attacks} AtomicAttack × "
          f"{_avg_time_per_attack}-{_avg_time_per_attack*2}s/attack)")
    print("  │")
    print("  │  → 下一步: scenario.initialize_async() 解析为")
    print("  │    AtomicAttack 列表 → tqdm 进度条 total")
    print(f"  └{'─' * _W}┘")


def _display_per_payload_results(
    attack_plans: list[Any],
    native_result: Any,
    *,
    warm_start: dict[str, float] | None = None,
    model_name: str = "",
) -> None:
    """
    ASR 排序结果速览 — 成功/失败各一行，按技术 ASR 降序排列

    v11.0 优化原则: ASR 驱动 · 成功为王 · 去重精简
    - 成功结果: ✅ 标记 + 先验→实测 ASR 对比 + Converter 列
    - 失败结果: ❌ 标记 + 先验 ASR + Converter 列 (一行，不展开)
    - 排序: 按技术 ASR 先验降序，同 ASR 内成功在前
    - 成功详情留到 Stage 6 深度展示
    """
    if native_result is None:
        return
    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    from src.scenarios.scenario_output import _extract_result_info, _extract_converters_from_identifier

    # ASR 查询函数
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr, normalize_technique_name
    except Exception:
        get_normalized_asr = None  # type: ignore
        normalize_technique_name = None  # type: ignore

    def _get_asr(tech_name: str) -> float | None:
        if not tech_name or not get_normalized_asr:
            return None
        try:
            if warm_start and normalize_technique_name:
                _norm = normalize_technique_name(tech_name)
                if _norm in warm_start:
                    return warm_start[_norm]
            return get_normalized_asr(tech_name, model_name)
        except Exception:
            return None

    # 展平所有结果，收集每条的关键信息
    rows: list[dict[str, Any]] = []
    payload_idx = 0
    for group_name, results in display_groups.items():
        for r in results:
            if r is None:
                continue
            payload_idx += 1
            pid = f"P{payload_idx}"

            techniques: set[str] = set()
            converters: set[str] = set()
            owasp_ids: set[str] = set()
            _extract_result_info(r, techniques=techniques, converters=converters, owasp_ids=owasp_ids)

            outcome = getattr(r, "outcome", None)
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
            is_success = outcome_str == "SUCCESS"

            tech_display = ", ".join(sorted(techniques)) if techniques else "(unknown)"

            # SequentialAttackResult: 从子结果提取成功技术名 + Converter
            child_converters: list[str] = []
            child_results = getattr(r, "child_attack_results", None) or []
            for child in child_results:
                if child is None:
                    continue
                child_identifier = None
                if hasattr(child, "get_attack_strategy_identifier"):
                    child_identifier = child.get_attack_strategy_identifier()
                if child_identifier is not None:
                    child_conv_names = _extract_converters_from_identifier(child_identifier)
                    child_converters.extend(child_conv_names)
                    child_outcome = getattr(child, "outcome", None)
                    if child_outcome is not None:
                        child_outcome_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                        if child_outcome_str == "SUCCESS":
                            child_name = getattr(child_identifier, "unique_name", "") if child_identifier else ""
                            if child_name:
                                tech_display = child_name.split("::")[0] if "::" in child_name else child_name

            all_converters = sorted(converters | set(child_converters)) if (converters or child_converters) else []

            # 获取 ASR
            asr_val = _get_asr(tech_display.split(", ")[0] if ", " in tech_display else tech_display)

            rows.append({
                "pid": pid,
                "tech": tech_display,
                "is_success": is_success,
                "converters": all_converters,
                "asr_val": asr_val,
                "owasp": ", ".join(sorted(owasp_ids)) if owasp_ids else "",
            })

    if not rows:
        return

    # 按 ASR 降序排列，同 ASR 内成功在前
    def _sort_key(row: dict[str, Any]) -> tuple[float, int]:
        asr = row.get("asr_val")
        asr_neg = -asr if asr is not None else 0.0
        success_first = 0 if row["is_success"] else 1
        return (asr_neg, success_first)

    rows.sort(key=_sort_key)

    # 拆分成功/失败
    success_rows = [r for r in rows if r["is_success"]]
    failure_rows = [r for r in rows if not r["is_success"]]

    # 计算每技术的实测 ASR (用于成功行展示)
    tech_success: dict[str, int] = {}
    tech_total: dict[str, int] = {}
    for row in rows:
        tech = row["tech"]
        tech_total[tech] = tech_total.get(tech, 0) + 1
        if row["is_success"]:
            tech_success[tech] = tech_success.get(tech, 0) + 1

    # 主标题
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  攻击结果速览 (ASR 降序)  ★")
    print()
    print(f"    按技术 ASR 先验降序 · 成功标 ✅ · 失败标 ❌ · 共 {len(rows)} 个")
    print()
    print("  ╚" + "═" * _W + "╝")

    # 成功区
    if success_rows:
        print()
        print(f"  ┌─ 成功 ({len(success_rows)} 个) "
              f"{'─' * max(1, _W - 18 - len(str(len(success_rows))) * 2)}┐")
        for row in success_rows:
            asr_str = f"{row['asr_val']:.0%}" if row['asr_val'] is not None else "N/A"
            tech = row["tech"]
            _t_total = tech_total.get(tech, 0)
            _t_succ = tech_success.get(tech, 0)
            emp_asr = _t_succ / _t_total if _t_total > 0 else 0
            emp_str = f"{emp_asr:.0%}"
            conv_str = ", ".join(row["converters"]) if row["converters"] else "(基线)"
            pid_pad = _pad_right(row["pid"], 4)
            tech_pad = _pad_right(tech[:28], 28)
            print(f"  │  ◆ {pid_pad} ✅ {tech_pad} "
                  f"ASR {asr_str} → {emp_str}  {conv_str}")
        print(f"  └{'─' * _W}┘")

    # 失败区
    if failure_rows:
        print()
        print(f"  ┌─ 失败 ({len(failure_rows)} 个) "
              f"{'─' * max(1, _W - 18 - len(str(len(failure_rows))) * 2)}┐")
        for row in failure_rows:
            asr_str = f"{row['asr_val']:.0%}" if row['asr_val'] is not None else "N/A"
            conv_str = ", ".join(row["converters"]) if row["converters"] else "(基线)"
            pid_pad = _pad_right(row["pid"], 4)
            tech_pad = _pad_right(row["tech"][:28], 28)
            print(f"  │  ○ {pid_pad} ❌ {tech_pad} "
                  f"ASR {asr_str}  {conv_str}")
        print(f"  └{'─' * _W}┘")

    print()


def _display_execution_strategy(ctx: PipelineContext) -> None:
    """
    执行策略 — 合并技术排序 + 失败路由 + 停止策略
    """
    from src.payloads.technique_name_mapper import get_normalized_asr, normalize_technique_name
    from src.scenarios.asr_strategy_display import _get_tier

    model_name = ctx.strategy_info.get("model_name", ctx.target_model)
    strategy_mode = ctx.strategy_info.get("strategy_mode", "academic")
    _warm = ctx.warm_start_asr or None

    tech_list = []
    seen = set()
    for plan in ctx.attack_plans:
        tech = getattr(plan, "attack_technique", "")
        if tech and tech not in seen:
            seen.add(tech)
            # P1-2: 优先使用 warm_start (经验融合 ASR), 与 Stage 2 数据源一致
            if _warm:
                _norm = normalize_technique_name(tech)
                if _norm in _warm:
                    asr = _warm[_norm]
                else:
                    asr = get_normalized_asr(tech, model_name)
            else:
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
            f"{t}({c})" for t, c in _sort_tech_by_asr(_tech_set, _exec_model, ctx.warm_start_asr)
        ),
        f"OWASP 覆盖 ({len(_owasp_set)} 类): " + ", ".join(
            f"{o}({c})" for o, c in sorted(_owasp_set.items(), key=lambda x: -x[1])
        ),
    ]
    info_box("攻击计划摘要", plan_lines)

    # ── ② 执行策略 ──
    _display_execution_strategy(ctx)

    # ── ③ 统一攻击载荷 × Converter 组合矩阵 ──
    _owasp_threshold = ctx.config_loader.get_owasp_success_threshold()
    _stop_on_first = ctx.config_loader.get_stop_on_first_success()
    # P3: 计算 Stage 4 技术 ASR 映射（用于技术映射桥接展示）
    _stage4_tech_asr: dict[str, float] = {}
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr
        _exec_model_for_asr = ctx.strategy_info.get("model_name", ctx.target_model)
        _warm_for_asr = ctx.warm_start_asr or None
        for _tech_name in _tech_set:
            if _warm_for_asr:
                from src.payloads.technique_name_mapper import normalize_technique_name
                _norm = normalize_technique_name(_tech_name)
                if _norm in _warm_for_asr:
                    _stage4_tech_asr[_tech_name] = _warm_for_asr[_norm]
                    continue
            _stage4_tech_asr[_tech_name] = get_normalized_asr(_tech_name, _exec_model_for_asr)
    except Exception:
        pass

    _display_unified_attack_matrix(
        ctx.attack_plans,
        strategy_info=ctx.strategy_info,
        target_type=ctx.target_type,
        converter_chains_from_router=ctx.converter_chains,
        owasp_set=_owasp_set,
        mode_count=_mode_count,
        tech_set=_tech_set,
        warm_start=ctx.warm_start_asr,
        owasp_success_threshold=_owasp_threshold,
        stop_on_first_success=_stop_on_first,
        stage4_tech_asr=_stage4_tech_asr or None,
    )

    # ── ④ 开始执行 ──
    print(f"  [OK] 开始执行 {_plan_count} 个攻击计划...\n")

    from src.scenarios.adaptive_runner import run_adaptive_scenario_async

    # P1-1: max_attempts_per_objective — env > pipeline.yaml > default(5)
    _max_attempts = int(
        os.getenv("MAX_ATTEMPTS_PER_OBJECTIVE", "")
        or ctx.config_loader.get_pipeline_defaults().get("max_attempts_per_objective", 5)
    )

    # P2: 创建独立 adversarial_target（如有 ADVERSARIAL_* 环境变量）
    # 多轮攻击（RedTeamingAttack/CrescendoAttack）需要 adversarial_chat 生成攻击 prompt
    # 默认复用 judge_target（轻量级模型，快速生成攻击 prompt）
    _adversarial_target = None
    _adv_endpoint = os.getenv("ADVERSARIAL_ENDPOINT", "").strip()
    _adv_model = os.getenv("ADVERSARIAL_MODEL", "").strip()
    _adv_api_key = os.getenv("ADVERSARIAL_API_KEY", "").strip()
    if _adv_endpoint and _adv_model:
        try:
            from src.targets import create_prompt_target, TargetParams
            from src.targets.rate_limited_target import RateLimitConfig, wrap_target_with_rate_limiting
            _adv_params = TargetParams(
                temperature=0.7,
                discover_capabilities=False,
                httpx_timeout=float(ctx.config_loader.get_target_httpx_timeout()),
                httpx_verify=ctx.config_loader.get_target_httpx_verify(),
            )
            _adversarial_target, _ = await create_prompt_target(
                target_url=_adv_endpoint,
                api_key=_adv_api_key or ctx.judge_api_key,
                model_name=_adv_model,
                params=_adv_params,
            )
            _adversarial_target = wrap_target_with_rate_limiting(
                _adversarial_target,
                config=RateLimitConfig(max_concurrent_requests=ctx.api_max_concurrent),
                semaphore_key=f"adversarial:{_adv_endpoint}",
            )
            print(f"  [P2] 独立 adversarial_chat: {_adv_model} @ {_adv_endpoint}")
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"P2: Failed to create adversarial_target: {e}, falling back to judge_target")
            _adversarial_target = None

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
        warm_start_asr=ctx.warm_start_asr or None,
        strategy_attack_techniques=(
            getattr(ctx.strategy_selection, "attack_techniques", None)
            if ctx.strategy_selection else None
        ),
        adversarial_target=_adversarial_target,
    )
    ctx.batch_result = ctx.adaptive_result.batch_result

    # ── 从执行结果构建停止策略统计 (供 Stage 6 展示) ──
    _populate_stop_context(ctx)

    # ── ⑤ 执行结果概要 ──
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
    # P0-ASR-2: 显示运行时 ASR 实测数据（实时反馈闭环）
    if ctx.adaptive_result.runtime_asr:
        _rasr = ctx.adaptive_result.runtime_asr
        _rasr_parts = [f"{k}: {v:.0%}" for k, v in sorted(_rasr.items(), key=lambda x: -x[1])[:5]]
        result_lines.append(f"运行时 ASR (实时反馈): {' | '.join(_rasr_parts)}")
    info_box("执行结果", result_lines)

    # ── ⑥ ASR 排序结果速览 ──
    if ctx.adaptive_result.native_result is not None:
        try:
            _display_per_payload_results(
                ctx.attack_plans,
                ctx.adaptive_result.native_result,
                warm_start=ctx.warm_start_asr or None,
                model_name=ctx.strategy_info.get("model_name", ctx.target_model),
            )
        except Exception as e:
            print(f"  [!] 结果速览输出失败: {e}")

    # ── ⑦ Per-Group Breakdown（格式对齐②） ──
    if ctx.adaptive_result.native_result is not None:
        try:
            from src.scenarios.scenario_output import display_enhanced_group_breakdown
            display_enhanced_group_breakdown(
                ctx.adaptive_result.native_result,
                owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
                model_name=ctx.strategy_info.get("model_name", ctx.target_model),
                warm_start=ctx.warm_start_asr or None,
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
