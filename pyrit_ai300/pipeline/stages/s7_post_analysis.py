"""
Stage 6/7: 执行后分析 + ASR 经验写回
======================================

ASR 实测 vs 学术先验对比 + 经验 ASR 持久化 + 策略建议。

显示架构 (v9.0 精简优化 — 合并冗余展示):
  ① ASR 实测 vs 先验对比        — 保留原有对比表
  ② ★ 攻击结果汇总 ★            — 合并 Per-Group Breakdown + 失败汇总 (消除重复)
  ③ ★ 成功攻击详细展示 ★        — ┏━ 卡片: 评分 + 完整对话 (仅成功)
  ④ Converter 健康统计           — 熔断/健康状态
  ⑤ ASR 经验写回 (Tier 2)       — 持久化 + Top-3
  ⑥ 运行时停止策略               — L2/L3 统计

设计原则:
  - 成功 = 详细：每个成功攻击都是宝贵经验，展示完整对话 + 评分 rationale
  - 失败 = 汇总：大量失败按失败类型分组，展示技术/Converter 分布
  - 消除冗余：原 Stage 5 逐载荷卡片 + Stage 6 载荷摘要 + 失败汇总 = 3 次重复
    → 精简为 1 次：Stage 5 one-liner + Stage 6 合并汇总
  - 0% 场景：仅显示统计行，省略逐行展示

三层数据架构:
  Tier 1: 学术先验 (asr_prior_registry.py, 只读)
  Tier 2: 经验 ASR (empirical_asr_store.py, JSON 持久化)  ← 本阶段写回
  Tier 3: 运行时 Q 值 (PyRIT 原生 CentralMemory, SQLite)
"""

import logging
from typing import Any

from pipeline.context import PipelineContext
from pipeline.display import info_box, stage_header

logger = logging.getLogger(__name__)

# ── 统一卡片宽度（双线框，与 executor/Stage 1-5 一致） ──
_W = 68

# 失败类型中文标签
_FAILURE_TYPE_CN = {
    "model_refusal": "模型拒绝",
    "timeout": "超时",
    "scorer_validation_error": "评分器验证错误",
    "objective_not_achieved": "目标未达成",
    "unknown": "未知失败",
}

# P2-3: 失败类型改进建议
_FAILURE_SUGGESTIONS: dict[str, list[str]] = {
    "model_refusal": [
        "→ 启用 Converter 变体 (Base64/ROT13/Unicode) 绕过内容过滤",
        "→ 切换到多轮攻击 (Crescendo/Tree-of-Attacks) 逐步建立上下文",
        "→ 检查 Converter Target 模型是否为安全对齐模型 (需更换为限制较少的模型)",
    ],
    "timeout": [
        "→ 降低 max_attempts_per_objective (当前可能过高)",
        "→ 增加 max_concurrency 提高并行度",
        "→ 对多轮攻击降低 max_turns 参数",
    ],
    "scorer_validation_error": [
        "→ 检查 Judge Target 模型是否正常响应",
        "→ 验证 true_false_question 模板路径是否正确",
        "→ 考虑更换为更稳定的评分器类型 (如 SelfAskTrueFalseScorer)",
    ],
    "objective_not_achieved": [
        "→ 升级到更高 ASR 技术 (参考 Stage 2 ASR Tier 排序)",
        "→ 增加攻击变体覆盖 (启用更多 Converter 链)",
        "→ 检查目标模型是否有特定防护 (如 system prompt 注入检测)",
    ],
    "unknown": [
        "→ 检查错误日志获取详细失败原因",
        "→ 验证 Target 端点配置和网络连通性",
        "→ 考虑增加重试次数 (max_retries)",
    ],
}


def _cjk_width(s: str) -> int:
    """近似计算字符串显示宽度（CJK 字符算 2 列）"""
    return sum(2 if ord(c) > 0x7F else 1 for c in s)


def _trunc(text: str, limit: int = 60) -> str:
    """截断文本，添加省略号"""
    text = text.replace("\n", " ").strip()
    return text[:limit - 3] + "..." if len(text) > limit else text


async def run(ctx: PipelineContext) -> None:
    """执行后分析阶段 + ASR 经验写回"""
    stage_header(6, "执行后分析 + ASR 反馈", "ASR 实测 vs 先验对比 + 经验写回")

    # ════════════════════════════════════════════════════════════
    # P1-B: 合并为 3 个逻辑分组 (减少 info_box 过载)
    # ════════════════════════════════════════════════════════════

    # ── 组 1: 执行成果摘要 (时间 + ASR对比 + Per-Group + 失败汇总) ──

    # P1-2: 时间预估 vs 实际对比
    if ctx.adaptive_result is not None:
        _exec_s = ctx.adaptive_result.execution_time
        _exec_min = _exec_s / 60
        _n_plans = ctx.batch_result.total_plans if ctx.batch_result else 0
        _n_executed = ctx.batch_result.executed if ctx.batch_result else 0
        _est_atomic = _n_plans + 1
        _est_min = (_est_atomic * 45) / 60
        _est_max = (_est_atomic * 90) / 60
        _time_lines = [
            f"实际: {_exec_min:.1f} min ({_exec_s:.0f}s)",
            f"预估: ~{_est_min:.0f}-{_est_max:.0f} min "
            f"(基于 {_n_plans} 计划 → {_n_executed} 结果)",
        ]
        if _exec_min > _est_max:
            _ratio = _exec_min / max(_est_max, 0.1)
            _time_lines.append(
                f"⚠ 超出预估 {_ratio:.1f}× — "
                f"可能原因: 多轮攻击深迭代 | Converter 链 LLM 调用 | "
                f"API 限流重试"
            )
        elif _exec_min < _est_min:
            _time_lines.append(
                "✓ 优于预估 — 可能原因: FIRST_SUCCESS 提前停止 | "
                "弱模型快速响应"
            )
        info_box("时间分析", _time_lines)

    # ① ASR 实测 vs 学术先验对比
    # P0-C/P1-C: 传递 warm_start 使 ASR 数据源与 Stage 2/4/5 统一
    from src.scenarios.asr_strategy_display import display_post_execution
    display_post_execution(
        adaptive_result=ctx.adaptive_result,
        model_name=ctx.strategy_info.get("model_name", ctx.target_model),
        warm_start=ctx.warm_start_asr or None,
    )

    # ② ★ 攻击结果汇总（合并 Per-Group Breakdown + 失败汇总）★
    _display_unified_results(ctx)

    # ── 组 2: 攻击详情 (成功详情 + Converter增量) ──

    # ③ 成功攻击详细展示
    _display_success_detail(ctx)

    # ④ L2 韧性: 从执行结果回填 Converter 健康统计
    _feed_converter_health_from_results(ctx)

    # P4-2: Converter 增量分析区块
    _display_converter_delta(ctx)

    # ── 组 3: 经验反馈 (经验写回 + 模型洞察 + 停止策略) ──

    # ⑤ L5 ASR 反馈回路 Tier 2: 经验 ASR 写回
    _write_empirical_asr(ctx)

    # P4-1: 模型特定洞察区块
    _display_model_insight(ctx)

    # ⑥ 运行时停止策略统计
    _display_stop_stats(ctx)

    # P2-C: ★ 成果回溯 + 下次运行建议 ★
    _display_retrospective(ctx)

    # P2-A: 阶段间衔接行
    from pipeline.display import handoff_line
    _sr_pct = (ctx.batch_result.success_rate * 100) if ctx.batch_result else 0
    _n_success = ctx.batch_result.succeeded if ctx.batch_result else 0
    _n_total = ctx.batch_result.executed if ctx.batch_result else 0
    handoff_line(6, 7, f"ASR={_sr_pct:.0f}% | 成功={_n_success}/{_n_total} | 报告生成中...")


# ============================================================
# ③ 成功攻击详细展示 — ┏━ 卡片风格
# ============================================================


def _display_success_detail(ctx: PipelineContext) -> None:
    """③ 成功攻击详细展示 — ┏━ 卡片: 评分 + 完整对话

    每个成功攻击都是宝贵经验，展示:
      - PID + OWASP + 技术 + ✅ 成功
      - Converter 使用情况
      - 评分 (含 score_rationale)
      - 攻击对话 (USER → Converter标注 → ASST)
      - SequentialAttack 子结果中的成功 Converter
    """
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    native_result = ctx.adaptive_result.native_result
    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    from src.scenarios.scenario_output import (
        _extract_result_info,
        _extract_converters_from_identifier,
        _OWASP_NAMES,
    )

    # 展平所有结果
    all_results = []
    for _group_name, results in display_groups.items():
        for r in results:
            if r is not None:
                all_results.append(r)

    # 筛选成功结果
    success_results = []
    for idx, r in enumerate(all_results):
        outcome = getattr(r, "outcome", None)
        outcome_str = (
            str(outcome.value).upper()
            if hasattr(outcome, "value")
            else str(outcome).upper()
        )
        if outcome_str == "SUCCESS":
            success_results.append((idx + 1, r))

    if not success_results:
        print("\n  (无成功攻击结果)")
        return

    # Banner
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  成功攻击详细展示  ★")
    print()
    print(f"    共 {len(success_results)} 个成功攻击 · 展示完整对话 + 评分依据")
    print()
    print("  ╚" + "═" * _W + "╝")

    for pid_num, r in success_results:
        pid = f"P{pid_num}"

        # 提取信息
        techniques: set[str] = set()
        converters: set[str] = set()
        owasp_ids: set[str] = set()
        _extract_result_info(r, techniques=techniques, converters=converters, owasp_ids=owasp_ids)

        # OWASP
        owasp_id_str = ", ".join(sorted(owasp_ids)) if owasp_ids else ""
        owasp_name = ""
        if owasp_id_str:
            oid = owasp_id_str.split(", ")[0].strip()
            owasp_name = _OWASP_NAMES.get(oid, "")

        tech_display = ", ".join(sorted(techniques)) if techniques else "(unknown)"

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
                child_conv_names = _extract_converters_from_identifier(child_identifier)
                child_converters.extend(child_conv_names)
            child_outcome = getattr(child, "outcome", None)
            if child_outcome is not None:
                child_outcome_str = (
                    str(child_outcome.value).upper()
                    if hasattr(child_outcome, "value")
                    else str(child_outcome).upper()
                )
                if child_outcome_str == "SUCCESS":
                    child_name = (
                        getattr(child_identifier, "unique_name", "")
                        if child_identifier else ""
                    )
                    if child_name:
                        tech_display = (
                            child_name.split("::")[0]
                            if "::" in child_name
                            else child_name
                        )

        # 对话摘要
        conversation = getattr(r, "conversation", None) or getattr(r, "request_pieces", None)
        user_msgs: list[str] = []
        asst_msgs: list[str] = []
        if conversation:
            try:
                if hasattr(conversation, "__iter__"):
                    for piece in conversation:
                        role = getattr(piece, "role", "") or ""
                        val = (
                            getattr(piece, "original_value", "")
                            or getattr(piece, "value", "")
                            or getattr(piece, "text", "")
                        )
                        if not val:
                            continue
                        if role.lower() == "user":
                            user_msgs.append(_trunc(val, 80))
                        elif role.lower() == "assistant":
                            asst_msgs.append(_trunc(val, 80))
            except Exception:
                pass

        # ── 卡片 ──
        print()
        print("  ┏" + "━" * _W)
        print(f"  ┃  ◆ {pid} [{owasp_id_str}] {tech_display}  ✅ 成功")

        # 结果区域
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
            score_rationale = getattr(score, "score_rationale", "")
            print(f"  ┃    │ 评分: SUCCESS ({score_val})")
            if score_rationale:
                # 评分理由可能较长，截断展示
                rationale_short = _trunc(score_rationale, _W - 25)
                print(f"  ┃    │       {rationale_short}")
        else:
            print("  ┃    │ 评分: SUCCESS")

        print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        # 攻击对话（成功才展示）
        if user_msgs or asst_msgs:
            print(f"  ┃    ┌─ 攻击对话 ─{'─' * max(0, _W - 20)}┐")
            max_turns = max(len(user_msgs), len(asst_msgs))
            for t_idx in range(min(max_turns, 3)):
                if t_idx < len(user_msgs):
                    print(f"  ┃    │ [USER] {user_msgs[t_idx]}")
                if converters or child_converters:
                    conv_short = ", ".join(sorted(converters or set(child_converters)))
                    if t_idx == 0:
                        print(f"  ┃    │        ↳ [{_trunc(conv_short, 40)}]")
                if t_idx < len(asst_msgs):
                    print(f"  ┃    │ [ASST] {asst_msgs[t_idx]}")
                if t_idx < min(max_turns, 3) - 1:
                    print("  ┃    │")
            if max_turns > 3:
                print(f"  ┃    │ ... ({max_turns - 3} more turns)")
            print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

        print("  ┗" + "━" * _W)

    print()


# ============================================================
# ④ 失败攻击汇总 — 按失败类型分组
# ============================================================


def _display_unified_results(ctx: PipelineContext) -> None:
    """
    ② ★ 攻击结果汇总（合并 Per-Group Breakdown + 失败汇总）★

    v9.0 精简优化 — 消除原 3 次重复展示:
      原: 逐载荷卡片(Stage5⑦) + 载荷级摘要(Stage6②) + 失败汇总(Stage6④) = 3 次
      新: 载荷级 one-liner(Stage5⑦) + 本函数 = 2 次

    本函数合并展示:
      1. Per-Group Breakdown: 按技术分组统计 (成功率/技术/Converter/OWASP)
      2. 失败攻击汇总: 按失败类型分组 (技术/Converter 分布)
      → 一次遍历，交叉展示，避免重复

    0% 场景特殊处理: 仅显示统计行，省略逐行展示
    """
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    native_result = ctx.adaptive_result.native_result
    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    from src.scenarios.scenario_output import (
        _extract_result_info,
        _extract_converters_from_identifier,
    )
    from src.scenarios.failure_type_selector import extract_failure_type_from_result

    # 展平所有结果
    all_results = []
    for _group_name, results in display_groups.items():
        for r in results:
            if r is not None:
                all_results.append(r)

    if not all_results:
        return

    # ── 一次遍历: 同时收集 Per-Group 统计 + 失败类型分组 ──
    total = len(all_results)
    success_count = 0
    failure_groups: dict[str, list[tuple[int, Any, str]]] = {}  # (idx, result, group_name)

    # 构建 idx → group_name 映射
    _idx_to_group: dict[int, str] = {}
    _flat_idx = 0
    for _gn, _results in display_groups.items():
        for _r in _results:
            if _r is not None:
                _idx_to_group[_flat_idx] = _gn
                _flat_idx += 1

    for idx, r in enumerate(all_results):
        outcome = getattr(r, "outcome", None)
        outcome_str = (
            str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
        )
        if outcome_str == "SUCCESS":
            success_count += 1
        else:
            ftype = extract_failure_type_from_result(r)
            _gn = _idx_to_group.get(idx, "")
            failure_groups.setdefault(ftype, []).append((idx + 1, r, _gn))

    fail_count = total - success_count
    rate = success_count / total if total > 0 else 0.0

    # ── Banner ──
    print()
    print("  ╔" + "═" * _W + "╗")
    print()
    print("       ★  攻击结果汇总  ★")
    print()
    print(f"    总计: {total} | 成功: {success_count} ({rate:.0%}) | 失败: {fail_count}")
    print()
    print("  ╚" + "═" * _W + "╝")

    # ── Per-Group Breakdown (来自 display_groups) ──
    from src.scenarios.scenario_output import display_enhanced_group_breakdown
    try:
        display_enhanced_group_breakdown(
            native_result,
            owasp_id=",".join(ctx.config_owasp_ids) if ctx.config_owasp_ids else "",
            model_name=ctx.strategy_info.get("model_name", ctx.target_model),
            warm_start=ctx.warm_start_asr or None,
        )
    except Exception as e:
        logger.warning(f"Per-Group Breakdown 输出失败: {e}")

    # ── 失败攻击汇总 (按失败类型分组) ──
    if failure_groups:
        sorted_failures = sorted(failure_groups.items(), key=lambda x: -len(x[1]))
        total_failures = sum(len(v) for v in failure_groups.values())

        print()
        print("  ╔" + "═" * _W + "╗")
        print()
        print("       ★  失败攻击汇总 (按失败类型分组)  ★")
        print()
        print(f"    共 {total_failures} 个失败攻击 · 按失败类型分组展示技术/Converter 分布")
        print()
        print("  ╚" + "═" * _W + "╝")

        for ftype, items in sorted_failures:
            ftype_cn = _FAILURE_TYPE_CN.get(ftype, ftype)
            count = len(items)

            # ── 卡片头 ──
            print()
            print("  ┏" + "━" * _W)
            print(f"  ┃  ◆ {ftype} ({ftype_cn}) — {count} 次")

            # ── 技术分布 ──
            tech_dist: dict[str, int] = {}
            for _pid, r, _gn in items:
                techniques: set[str] = set()
                converters: set[str] = set()
                owasp_ids: set[str] = set()
                _extract_result_info(
                    r, techniques=techniques, converters=converters,
                    owasp_ids=owasp_ids, group_name=_gn,
                )

                child_results = getattr(r, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_identifier = None
                    if hasattr(child, "get_attack_strategy_identifier"):
                        child_identifier = child.get_attack_strategy_identifier()
                    if child_identifier is not None:
                        child_name = getattr(child_identifier, "unique_name", "") or ""
                        child_tech = child_name.split("::")[0] if "::" in child_name else child_name
                        if child_tech:
                            techniques.add(child_tech)

                for t in sorted(techniques) if techniques else ["(unknown)"]:
                    tech_dist[t] = tech_dist.get(t, 0) + 1

            print("  ┃")
            tech_hdr = f"技术分布 ({len(tech_dist)} 种)"
            tech_dashes = max(1, _W - 6 - _cjk_width(tech_hdr) - 2)
            print(f"  ┃    ┌─ {tech_hdr} {'─' * tech_dashes}┐")

            sorted_tech = sorted(tech_dist.items(), key=lambda x: -x[1])
            for t_name, t_count in sorted_tech[:8]:
                pct = t_count / count * 100
                print(f"  ┃    │ {t_name:40s} {t_count:>3d} 次  ({pct:.0f}%)")
            if len(sorted_tech) > 8:
                print(f"  ┃    │ ... ({len(sorted_tech) - 8} more)")
            print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

            # ── Converter 分布 ──
            conv_dist: dict[str, int] = {}
            baseline_count = 0
            for _pid, r, _gn in items:
                techniques = set()
                converters = set()
                owasp_ids = set()
                _extract_result_info(
                    r, techniques=techniques, converters=converters,
                    owasp_ids=owasp_ids, group_name=_gn,
                )

                child_results = getattr(r, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_identifier = None
                    if hasattr(child, "get_attack_strategy_identifier"):
                        child_identifier = child.get_attack_strategy_identifier()
                    if child_identifier is not None:
                        child_conv_names = _extract_converters_from_identifier(child_identifier)
                        for cn in child_conv_names:
                            converters.add(cn)

                if converters:
                    for cv in sorted(converters):
                        conv_dist[cv] = conv_dist.get(cv, 0) + 1
                else:
                    baseline_count += 1

            print("  ┃")
            conv_hdr = f"Converter 分布 ({len(conv_dist)} 种 + {baseline_count} 基线)"
            conv_dashes = max(1, _W - 6 - _cjk_width(conv_hdr) - 2)
            print(f"  ┃    ┌─ {conv_hdr} {'─' * conv_dashes}┐")

            if baseline_count > 0:
                pct = baseline_count / count * 100
                print(f"  ┃    │ {'(基线无变换)':40s} {baseline_count:>3d} 次  ({pct:.0f}%)")

            sorted_conv = sorted(conv_dist.items(), key=lambda x: -x[1])
            for cv_name, cv_count in sorted_conv[:8]:
                pct = cv_count / count * 100
                print(f"  ┃    │ {cv_name:40s} {cv_count:>3d} 次  ({pct:.0f}%)")
            if len(sorted_conv) > 8:
                print(f"  ┃    │ ... ({len(sorted_conv) - 8} more)")
            print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

            # P2-3: 失败建议区块
            _suggestions = _FAILURE_SUGGESTIONS.get(ftype, [])
            if _suggestions:
                print("  ┃")
                sug_hdr = "改进建议"
                sug_dashes = max(1, _W - 6 - _cjk_width(sug_hdr) - 2)
                print(f"  ┃    ┌─ {sug_hdr} {'─' * sug_dashes}┐")
                for sug in _suggestions:
                    print(f"  ┃    │ {sug}")
                print(f"  ┃    └{'─' * max(0, _W - 3)}┘")

            print("  ┗" + "━" * _W)

    print()


# ============================================================
# ④ Converter 健康统计 — 保留原有逻辑
# ============================================================


def _feed_converter_health_from_results(ctx: PipelineContext) -> None:
    """
    从执行结果回填 Converter 健康统计

    Pipeline 数据流修复: ConverterHealthMonitor 在 Stage 3 初始化并注册链,
    但执行阶段（Stage 5 AdaptiveScenario 内部）无法直接调用 record_success/
    record_failure。本函数在 Stage 6 后处理阶段遍历 AttackResult, 从 identifier
    提取 converter 名称, 根据 outcome 反馈到 health_monitor。

    这样 _write_empirical_asr() 中的 get_stats() 能返回有效数据。
    """
    if ctx.converter_health_monitor is None:
        return
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    native_result = ctx.adaptive_result.native_result
    if not hasattr(native_result, "get_display_groups"):
        return

    try:
        from src.scenarios.scenario_output import _extract_converters_from_identifier

        monitor = ctx.converter_health_monitor
        display_groups = native_result.get_display_groups()

        for _group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue

                outcome = getattr(r, "outcome", None)
                outcome_str = (
                    str(outcome.value).upper()
                    if hasattr(outcome, "value")
                    else str(outcome).upper()
                )
                is_success = outcome_str == "SUCCESS"

                # 从顶层 AttackResult 提取 converter
                identifier = None
                if hasattr(r, "get_attack_strategy_identifier"):
                    try:
                        identifier = r.get_attack_strategy_identifier()
                    except Exception:
                        pass
                if identifier is not None:
                    conv_names = _extract_converters_from_identifier(identifier)
                    for cn in conv_names:
                        if is_success:
                            monitor.record_success(cn)
                        else:
                            monitor.record_failure(cn, getattr(outcome, "value", "failure"))

                # SequentialAttackResult: 遍历子结果
                child_results = getattr(r, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_identifier = None
                    if hasattr(child, "get_attack_strategy_identifier"):
                        try:
                            child_identifier = child.get_attack_strategy_identifier()
                        except Exception:
                            pass
                    if child_identifier is not None:
                        child_conv_names = _extract_converters_from_identifier(child_identifier)
                        child_outcome = getattr(child, "outcome", None)
                        child_str = (
                            str(child_outcome.value).upper()
                            if hasattr(child_outcome, "value")
                            else str(child_outcome).upper()
                        )
                        child_success = child_str == "SUCCESS"
                        for cn in child_conv_names:
                            if child_success:
                                monitor.record_success(cn)
                            else:
                                monitor.record_failure(cn, child_str)

        # 展示 converter 健康摘要
        stats = monitor.get_stats()
        disabled = monitor.get_disabled_converters()
        if stats and any(s["attempts"] > 0 for s in stats.values()):
            health_lines = []
            for name, s in sorted(stats.items(), key=lambda x: -x[1]["attempts"]):
                if s["attempts"] == 0:
                    continue
                status = "✓ 健康" if not s["disabled"] else "✗ 熔断"
                health_lines.append(
                    f"  {name:30s} {status}  {s['successes']}/{s['attempts']} "
                    f"({s['success_rate']:.0%})"
                )
            if disabled:
                health_lines.append(f"\n  [熔断] {', '.join(disabled)}")
            if health_lines:
                info_box("Converter 健康统计", health_lines)

    except Exception as e:
        print(f"  [!] Converter 健康统计回填失败: {e}")


# ============================================================
# ⑥ ASR 经验写回 — 保留原有逻辑
# ============================================================


def _write_empirical_asr(ctx: PipelineContext) -> None:
    """
    L5 ASR 反馈回路: 将本次运行结果写回经验 ASR 存储

    融合公式:
      new_empirical = (old_empirical * old_count + new_data) / (old_count + 1)
    """
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    try:
        from src.scenarios.empirical_asr_store import (
            extract_tech_stats_from_results,
            update_empirical_asr,
        )

        # 提取 per-technique 统计
        tech_stats = extract_tech_stats_from_results(
            ctx.adaptive_result.native_result,
            ctx.strategy_info.get("model_name", ctx.target_model),
        )

        if not tech_stats:
            return

        # 获取 converter 健康统计
        converter_stats = None
        if ctx.converter_health_monitor is not None:
            converter_stats = ctx.converter_health_monitor.get_stats()

        # 写回经验 ASR
        updated = update_empirical_asr(
            model_name=ctx.strategy_info.get("model_name", ctx.target_model),
            model_tier=ctx.strategy_info.get("model_tier", ctx.model_tier),
            tech_stats=tech_stats,
            converter_stats=converter_stats,
        )

        ctx.tech_stats = tech_stats

        # 展示经验 ASR 更新摘要
        run_count = updated.get("run_count", 0)
        tech_count = len(updated.get("techniques", {}))
        conv_count = len(updated.get("converter_effectiveness", {}))

        emp_lines = [
            f"模型: {updated.get('model_name', '')}",
            f"运行次数: {run_count}",
            f"技术统计: {tech_count} 个技术",
            f"Converter 统计: {conv_count} 个",
        ]

        # 展示 Top-3 经验 ASR + P1-1: 先验对比
        emp_techs = updated.get("techniques", {})
        sorted_techs = sorted(
            emp_techs.items(),
            key=lambda x: -x[1].get("empirical_asr", 0.0),
        )[:3]

        # P1-1: 查询学术先验用于对比
        _prior_map: dict[str, float] = {}
        try:
            from src.payloads.technique_name_mapper import get_normalized_asr
            _model = ctx.strategy_info.get("model_name", ctx.target_model)
            for tech, _ in sorted_techs:
                try:
                    _prior_map[tech] = get_normalized_asr(tech, _model)
                except Exception:
                    pass
        except Exception:
            pass

        for tech, data in sorted_techs:
            asr = data.get("empirical_asr", 0.0)
            attempts = data.get("attempts", 0)
            _prior = _prior_map.get(tech)
            if _prior is not None:
                _delta = asr - _prior
                _delta_str = f" | 先验={_prior:.0%} (Δ{_delta:+.0%})"
            else:
                _delta_str = ""
            emp_lines.append(
                f"  {tech:30s} ASR={asr:.0%} ({attempts} 次){_delta_str}"
            )

        # Patched 技术
        patched = ctx.patched_techniques or []
        if patched:
            emp_lines.append(f"\n[PATCHED] {len(patched)} 个技术:")
            for p in patched[:3]:
                emp_lines.append(
                    f"  {p['technique']:30s} 学术={p['academic']:.0%} → 实测={p['empirical']:.0%} "
                    f"(Δ{p['delta']:+.0%})"
                )

        info_box("ASR 经验写回 (Tier 2)", emp_lines)

    except Exception as e:
        print(f"  [!] ASR 经验写回失败: {e}")


# ============================================================
# ⑦ 运行时停止策略 — 保留原有逻辑
# ============================================================


def _display_stop_stats(ctx: PipelineContext) -> None:
    """展示运行时停止策略统计"""
    if ctx.stop_context is None:
        return
    try:
        stats = ctx.stop_context.get_stats() if hasattr(ctx.stop_context, "get_stats") else {}
        if stats and (stats.get("should_stop") or stats.get("global_success", 0) > 0):
            stop_lines = [
                f"停止原因: {stats.get('stop_reason', 'N/A')}",
                f"全局成功: {stats.get('global_success', 0)}",
            ]
            owasp_stats = stats.get("owasp_success", {})
            if owasp_stats:
                stop_lines.append("OWASP 分类成功:")
                for oid, count in sorted(owasp_stats.items()):
                    total = stats.get("owasp_total", {}).get(oid, 0)
                    stop_lines.append(f"  {oid}: {count}/{total}")

            # P4-3: UNKNOWN 停止原因预警
            stop_reason = stats.get("stop_reason", "")
            if not stop_reason or stop_reason == "UNKNOWN":
                stop_lines.append(
                    "  ⚠ 停止原因为 UNKNOWN — "
                    "可能 OWASP ID 未传递到停止策略上下文"
                )
                stop_lines.append(
                    "    检查: memory_labels['owasp_id'] 是否正确设置"
                )

            info_box("运行时停止策略", stop_lines)
    except Exception:
        pass


# ============================================================
# P4-1: 模型特定洞察区块
# ============================================================


def _display_model_insight(ctx: PipelineContext) -> None:
    """P4-1: 模型特定洞察 — 基于模型分层和执行结果生成洞察"""
    if ctx.adaptive_result is None or ctx.batch_result is None:
        return

    try:
        _model = ctx.strategy_info.get("model_name", ctx.target_model)
        _tier = ctx.strategy_info.get("model_tier", ctx.model_tier)
        _sr = ctx.batch_result.success_rate
        _n_total = ctx.batch_result.total_plans
        _n_success = ctx.batch_result.succeeded
        _converter_used = ctx.adaptive_result.converter_variants_used

        insight_lines = [
            f"模型: {_model} (Tier: {_tier})",
            f"整体 ASR: {_sr:.0%} ({_n_success}/{_n_total})",
            f"Converter 使用: {_converter_used} 次",
        ]

        # 基于 Tier 的洞察
        if _tier == "weak":
            if _sr < 0.1:
                insight_lines.append(
                    "⚠ 弱模型 ASR < 10% — 建议增加 Converter 变体覆盖"
                )
            elif _sr > 0.5:
                insight_lines.append(
                    "✓ 弱模型 ASR > 50% — 防护较弱，可尝试更复杂技术"
                )
            if _converter_used == 0:
                insight_lines.append(
                    "⚠ Converter 未使用 — 弱模型应优先启用编码链绕过过滤"
                )
        elif _tier == "moderate":
            if _sr < 0.2:
                insight_lines.append(
                    "⚠ 中等模型 ASR < 20% — 建议升级到多轮攻击策略"
                )
        elif _tier == "strong":
            if _sr > 0.3:
                insight_lines.append(
                    "⚠ 强模型 ASR > 30% — 重大安全风险，需加固防护"
                )
            elif _sr < 0.05:
                insight_lines.append(
                    "✓ 强模型 ASR < 5% — 防护较好"
                )

        # 失败类型洞察
        if ctx.adaptive_result.failure_type_distribution:
            _ftd = ctx.adaptive_result.failure_type_distribution
            _top_failure = ctx.adaptive_result.most_common_failure_type
            if _top_failure:
                _top_count = _ftd.get(_top_failure, 0)
                insight_lines.append(
                    f"主要失败模式: {_top_failure} ({_top_count} 次)"
                )
                if _top_failure == "model_refusal":
                    insight_lines.append(
                        "  → 模型主动拒绝 — 需 Converter 编码绕过或多轮渐进"
                    )
                elif _top_failure == "timeout":
                    insight_lines.append(
                        "  → 执行超时 — 需降低迭代深度或增加并发"
                    )

        info_box("模型洞察 (P4-1)", insight_lines)

    except Exception as e:
        logger.debug(f"P4-1 model insight failed: {e}")


# ============================================================
# P4-2: Converter 增量分析区块
# ============================================================


def _display_converter_delta(ctx: PipelineContext) -> None:
    """P4-2: Converter 增量分析 — 对比基线 vs Converter 变体的 ASR 差异"""
    if ctx.adaptive_result is None or ctx.adaptive_result.native_result is None:
        return

    try:
        native_result = ctx.adaptive_result.native_result
        if not hasattr(native_result, "get_display_groups"):
            return

        display_groups = native_result.get_display_groups()
        if not display_groups:
            return

        from src.scenarios.scenario_output import _extract_result_info

        # 收集基线 vs Converter 变体的成功/失败统计
        baseline_total = 0
        baseline_success = 0
        converter_total = 0
        converter_success = 0
        converter_tech_asr: dict[str, dict[str, int]] = {}  # {tech: {success, total}}

        for _group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue
                techniques: set[str] = set()
                converters: set[str] = set()
                owasp_ids: set[str] = set()
                _extract_result_info(
                    r, techniques=techniques, converters=converters,
                    owasp_ids=owasp_ids, group_name=_group_name,
                )

                outcome = getattr(r, "outcome", None)
                outcome_str = (
                    str(outcome.value).upper()
                    if hasattr(outcome, "value")
                    else str(outcome).upper()
                )
                is_success = outcome_str == "SUCCESS"

                if converters:
                    converter_total += 1
                    if is_success:
                        converter_success += 1
                    for tech in techniques:
                        if tech not in converter_tech_asr:
                            converter_tech_asr[tech] = {"success": 0, "total": 0}
                        converter_tech_asr[tech]["total"] += 1
                        if is_success:
                            converter_tech_asr[tech]["success"] += 1
                else:
                    baseline_total += 1
                    if is_success:
                        baseline_success += 1

        delta_lines: list[str] = []

        if baseline_total > 0 or converter_total > 0:
            b_asr = baseline_success / baseline_total if baseline_total > 0 else 0
            c_asr = converter_success / converter_total if converter_total > 0 else 0
            delta = c_asr - b_asr

            delta_lines.append(
                f"基线 ASR: {b_asr:.0%} ({baseline_success}/{baseline_total})"
            )
            delta_lines.append(
                f"Converter ASR: {c_asr:.0%} ({converter_success}/{converter_total})"
            )

            if converter_total > 0:
                if delta > 0:
                    delta_lines.append(
                        f"✓ Converter 增量: +{delta:.0%} — Converter 提升了攻击效果"
                    )
                elif delta < 0:
                    delta_lines.append(
                        f"⚠ Converter 负增量: {delta:.0%} — Converter 降低了攻击效果"
                    )
                    delta_lines.append(
                        "  可能原因: Converter 编码被检测 | "
                        "Converter Target 模型质量差 | "
                        "编码后语义丢失"
                    )
                else:
                    delta_lines.append(
                        f"→ Converter 无增量 (Δ={delta:.0%}) — "
                        "Converter 未影响攻击效果"
                    )
            else:
                delta_lines.append(
                    "⚠ Converter 变体未使用 (0 次) — "
                    "建议检查 Stage 3 路由配置"
                )

            # Per-technology Converter ASR
            if converter_tech_asr:
                delta_lines.append("")
                delta_lines.append("Per-Technology Converter ASR:")
                sorted_tech = sorted(
                    converter_tech_asr.items(),
                    key=lambda x: -x[1]["success"] / max(x[1]["total"], 1),
                )
                for tech, stats in sorted_tech[:5]:
                    t_asr = stats["success"] / stats["total"] if stats["total"] > 0 else 0
                    delta_lines.append(
                        f"  {tech:30s} {t_asr:.0%} "
                        f"({stats['success']}/{stats['total']})"
                    )

        if delta_lines:
            info_box("Converter 增量分析 (P4-2)", delta_lines)

    except Exception as e:
        logger.debug(f"P4-2 converter delta failed: {e}")


def _display_retrospective(ctx: PipelineContext) -> None:
    """P2-C: ★ 成果回溯 + 下次运行建议 ★

    以攻击成果为首要目标，形成完整链条：
    - 前期策略选择依据 → 实际结果验证
    - 成功攻击的关键因素
    - 失败模式分析
    - 下次运行的可操作建议
    """
    if ctx.adaptive_result is None or ctx.batch_result is None:
        return

    try:
        _sr = ctx.batch_result.success_rate
        _n_success = ctx.batch_result.succeeded
        _n_total = ctx.batch_result.executed
        _model = ctx.strategy_info.get("model_name", ctx.target_model)
        _mode = ctx.strategy_info.get("strategy_mode", "academic")
        _tier = ctx.strategy_info.get("model_tier", "unknown")

        # ── 成果回溯 ──
        retro_lines: list[str] = []

        # 1. 策略选择验证
        retro_lines.append(f"模型: {_model} | 策略: {_mode} | 分层: {_tier}")
        retro_lines.append("")

        # 2. 成功攻击 Top-3 (技术 + Converter + 成因)
        _tech_success: dict[str, int] = {}
        _all_results = []
        _native = getattr(ctx.adaptive_result, "native_result", None)
        if _native and hasattr(_native, "get_display_groups"):
            for _gn, _results in _native.get_display_groups().items():
                for _r in _results:
                    if _r is not None:
                        _all_results.append(_r)
        elif ctx.batch_result.results:
            _all_results = ctx.batch_result.results

        from src.scenarios.scenario_output import _clean_technique_name
        _success_details: list[tuple[str, str]] = []
        for result in _all_results:
            outcome = getattr(result, "outcome", None)
            outcome_str = (
                str(outcome.value).upper()
                if hasattr(outcome, "value")
                else str(outcome).upper()
            )
            if "SUCCESS" not in outcome_str:
                continue

            tech = ""
            if hasattr(result, "get_attack_strategy_identifier"):
                try:
                    _id = result.get_attack_strategy_identifier()
                    _raw = getattr(_id, "unique_name", "") or ""
                    tech, _ = _clean_technique_name(_raw)
                except Exception:
                    pass

            # Extract converter info from identifier children
            conv_info = ""
            _id = None
            if hasattr(result, "get_attack_strategy_identifier"):
                try:
                    _id = result.get_attack_strategy_identifier()
                except Exception:
                    pass
            if _id is not None:
                _children = getattr(_id, "children", {}) or {}
                _req_conv = _children.get("request_converters", [])
                if _req_conv:
                    conv_info = ", ".join(_req_conv[:3])
                    if len(_req_conv) > 3:
                        conv_info += f" (+{len(_req_conv) - 3})"

            if tech:
                _tech_success[tech] = _tech_success.get(tech, 0) + 1
                _success_details.append((tech, conv_info))

        if _tech_success:
            retro_lines.append("成功攻击 Top-3 技术:")
            for tech, count in sorted(
                _tech_success.items(), key=lambda x: -x[1]
            )[:3]:
                _conv_detail = ""
                for _t, _c in _success_details:
                    if _t == tech and _c:
                        _conv_detail = f" [Converter: {_c}]"
                        break
                retro_lines.append(f"  ✓ {tech:30s} ×{count}{_conv_detail}")
        else:
            retro_lines.append("成功攻击: 无成功记录")

        # 3. 失败模式分析
        retro_lines.append("")
        _failure_dist = getattr(
            ctx.adaptive_result, "failure_type_distribution", None
        ) or {}
        if _failure_dist:
            retro_lines.append("主要失败模式:")
            for ftype, count in sorted(
                _failure_dist.items(), key=lambda x: -x[1]
            )[:3]:
                retro_lines.append(f"  ✗ {ftype:30s} ×{count}")
        elif _n_success == 0:
            retro_lines.append("主要失败模式: 全部失败 — 检查目标 API 和评分器配置")
        else:
            retro_lines.append("主要失败模式: 无显著模式")

        # 4. 下次运行建议
        retro_lines.append("")
        retro_lines.append("下次运行建议:")

        if _sr < 0.1:
            retro_lines.append(
                "  → ASR < 10%: 考虑 STRATEGY_MODE=exam (速度优先)"
            )
            if _tier == "strong":
                retro_lines.append(
                    "  → 强模型: 增加 max_attempts_per_objective, "
                    "启用更强 Converter 链 (persuasion + decomposition)"
                )
        elif _sr < 0.3:
            retro_lines.append(
                "  → ASR 10-30%: 考虑 STRATEGY_MODE=balanced (平衡)"
            )
            retro_lines.append(
                "  → 增加多轮攻击比例, 降级链深度 +1"
            )
        elif _sr > 0.7:
            retro_lines.append(
                "  → ASR > 70%: 考虑 STRATEGY_MODE=academic (学术先验优先)"
            )
            retro_lines.append(
                "  → 模型可能已修补: 增加 encoding 链和 new techniques"
            )

        # Converter 使用建议
        _conv_used = getattr(
            ctx.adaptive_result, "converter_variants_used", 0
        )
        if _conv_used == 0 and _n_success > 0:
            retro_lines.append(
                "  → Converter 未使用但有成功: 下次启用 Converter 链可能提升 ASR"
            )
        elif _conv_used > 0 and _n_success == 0:
            retro_lines.append(
                "  → Converter 已使用但无成功: 检查 Converter 模型配置"
            )

        info_box("★ 成果回溯 + 下次运行建议 ★", retro_lines)

    except Exception as e:
        logger.debug(f"P2-C retrospective failed: {e}")
