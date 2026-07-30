"""
ASR-Guided Strategy Display — ASR引导策略关键决策展示
==========================================================

在 Pipeline 各阶段输出 ASR 引导策略的关键决策信息，让用户清晰看到：
  [2/8] 分析阶段 — 策略模式 + 模型分层 + 学术先验总览
  [4/8] 选择阶段 — ASR 先验排序 + Tier 分层 + 技术选择依据
  [5/8] 执行阶段 — 技术执行顺序 + Converter 变体路由 + 失败路由策略

设计原则:
  - 纯展示层，不修改任何执行逻辑
  - 调用安全：所有展示函数 catch 异常，不影响 pipeline 执行
  - 可配置：STRATEGY_MODE / MODEL_NAME 环境变量控制
"""

import os
from typing import Any, Optional

# ── Tier 定义 (引用 asr_prior_registry 唯一定义点) ──

from src.payloads.asr_prior_registry import (  # noqa: F401 — re-exports for backward compatibility
    TIER_S_THRESHOLD,
    TIER_A_THRESHOLD,
    TIER_B_THRESHOLD,
    TIER_C_THRESHOLD,
    tier_from_asr,
)

TIER_DESCRIPTIONS = {
    "S": "多轮迭代攻击 (极高)",
    "A": "树搜索/迭代/模拟对话 (高)",
    "B": "说服/角色扮演/包装 (中)",
    "C": "编码变换/基线 (低, 兜底)",
    "D": "极低 (兜底尝试 — ASR 非零即值得尝试)",
}


def _get_tier(asr: float) -> str:
    """根据 ASR 值返回 Tier 等级 (引用 asr_prior_registry 唯一定义)"""
    return tier_from_asr(asr)


def _get_strategy_mode() -> str:
    """从环境变量读取策略模式"""
    return os.getenv("STRATEGY_MODE", "academic").lower()


def _get_model_name(target_model: str = "") -> str:
    """获取模型名称（用于 ASR 查询）"""
    env_model = os.getenv("TARGET_MODEL_FOR_ASR", "")
    return env_model or target_model or "gpt-4o"


def _infer_model_tier(model_name: str) -> str:
    """推断模型过滤强度等级（委托 recon_engine 的静态映射表）

    Returns:
        "strong" — 强内容过滤 (GPT-4o, Claude 4, Gemini 2.5 Pro 等)
        "moderate" — 中等过滤 (Llama 3.3, Qwen 3, DeepSeek V3 等)
        "weak"   — 弱过滤 (小参数开源模型等)
        "unknown"
    """
    from src.recon.recon_engine import infer_model_tier_static
    return infer_model_tier_static(model_name)


# ============================================================
# [2/8] 分析阶段展示
# ============================================================


def display_analysis_stage(
    target_model: str = "",
    recon_result: Optional[Any] = None,
) -> dict[str, Any]:
    """
    [2/8] 分析阶段 — 展示策略模式和模型分层

    优先使用侦察结果中的探测式模型分层（recon_result.model_tier），
    回退到静态模型名推断（_infer_model_tier）。

    Args:
        target_model: 目标模型名称（从 .env 读取）
        recon_result: 侦察结果（含 model_tier 探测结果）

    Returns:
        包含策略信息的字典（供 pipeline 后续使用）
    """
    strategy_mode = _get_strategy_mode()
    model_name = _get_model_name(target_model)

    # 优先使用探测式分层，回退静态推断
    if recon_result is not None and getattr(recon_result, "model_tier", "unknown") != "unknown":
        model_tier = recon_result.model_tier
    else:
        model_tier = _infer_model_tier(model_name)

    mode_descriptions = {
        "academic": "学术先验驱动 (策略优先, 高 ASR 技术优先尝试)",
        "exam": "考试模式 (编码优先, 快速验证基础安全)",
        "balanced": "均衡模式 (策略+编码交替)",
    }

    tier_descriptions = {
        "strong": "强内容过滤 → 策略攻击优先, 编码攻击低效",
        "moderate": "中等过滤 → 策略+编码交替",
        "weak": "弱内容过滤 → 编码攻击也可生效",
        "unknown": "未知过滤强度 → 默认强过滤策略",
    }

    print("\n  ┌─ ASR策略: 策略分析 ─────────────────────────────┐")
    print(f"  │ 策略模式: {strategy_mode}")
    print(f"  │   → {mode_descriptions.get(strategy_mode, '未知')}")
    print(f"  │ 目标模型: {model_name}")
    print(f"  │ 模型分层: {model_tier}", end="")
    tier_desc = tier_descriptions.get(model_tier, tier_descriptions["unknown"])
    print(f" ({tier_desc})")
    # 显示探测来源
    if recon_result is not None and getattr(recon_result, "model_tier_probe_detail", None):
        print("  │ 探测来源: 动态探针 (3-step gradient probe)")
    elif model_tier != "unknown":
        print("  │ 探测来源: 静态模型名推断")
    print("  └──────────────────────────────────────────────────┘")

    return {
        "strategy_mode": strategy_mode,
        "model_name": model_name,
        "model_tier": model_tier,
    }


# ============================================================
# [4/8] 选择阶段展示
# ============================================================


def display_selection_stage(
    selected_groups: list[Any] = None,
    all_seed_groups: list[Any] = None,
    model_name: str = "",
    strategy_mode: str = "",
    warm_start_asr: dict[str, float] | None = None,
) -> None:
    """
    [4/8] 选择阶段 — 展示 ASR 先验排序和 Tier 分层

    显示选中种子组中各技术的 ASR, 按 Tier 分层展示。
    当 warm_start_asr 提供 (Tier 2 融合 ASR) 时, 使用融合 ASR 替代纯学术先验。
    """
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr, normalize_technique_name
        from src.payloads.asr_prior_registry import get_asr_prior

        if not strategy_mode:
            strategy_mode = _get_strategy_mode()
        if not model_name:
            model_name = _get_model_name()

        # 从选中组中提取技术信息（v4.0: 使用标准化映射）
        tech_asr_map: dict[str, tuple[float, str]] = {}  # tech -> (asr, normalized_name)
        if selected_groups:
            for sg in selected_groups:
                for seed in getattr(sg, "seeds", []):
                    meta = getattr(seed, "metadata", {}) or {}
                    tech = meta.get("technique_group", meta.get("technique", ""))
                    if tech and tech not in tech_asr_map:
                        normalized = normalize_technique_name(tech)
                        # Tier 2 融合 ASR 优先, 回退到 Tier 1 学术先验
                        if warm_start_asr and normalized in warm_start_asr:
                            asr = warm_start_asr[normalized]
                        else:
                            asr = get_normalized_asr(tech, model_name)
                        tech_asr_map[tech] = (asr, normalized)

        if not tech_asr_map:
            return

        # 按 Tier 分组 (v4.0: 增加 D tier)
        tier_groups: dict[str, list[tuple[str, float, str]]] = {
            "S": [], "A": [], "B": [], "C": [], "D": []
        }
        for tech, (asr, normalized) in tech_asr_map.items():
            tier = _get_tier(asr)
            tier_groups[tier].append((tech, asr, normalized))

        # 排序
        for tier in tier_groups:
            tier_groups[tier].sort(key=lambda x: -x[1])

        _asr_label = "经验融合 ASR" if warm_start_asr else "学术 ASR 先验"
        print(f"\n  ┌─ ASR策略: {_asr_label}排序 ─────────────────────┐")
        print(f"  │ 模型: {model_name} | 策略: {strategy_mode}")
        print(f"  │ 共 {len(tech_asr_map)} 个技术 (选中组)")

        for tier in ["S", "A", "B", "C", "D"]:
            items = tier_groups[tier]
            if not items:
                continue
            threshold_str = {
                "S": ">=70%",
                "A": "40-70%",
                "B": "15-40%",
                "C": "5-15%",
                "D": "<5%",
            }[tier]
            print("  │")
            print(f"  │ Tier {tier} (ASR {threshold_str}) — {TIER_DESCRIPTIONS[tier]}:")
            for tech, asr, normalized in items:
                # 标记 patched
                prior = get_asr_prior(normalized)
                patched_mark = " [PATCHED]" if prior and prior.patched else ""
                # 紧凑 10 字符条形图（Tier header 已含 ASR 范围+语义描述）
                bar_len = int(asr * 10)
                bar = "█" * bar_len + "░" * (10 - bar_len)
                # 映射同行显示（节省垂直空间）
                if normalized != tech:
                    print(f"  │   {tech:28s} {bar}  → {normalized}{patched_mark}")
                else:
                    print(f"  │   {tech:28s} {bar}{patched_mark}")

        print("  └──────────────────────────────────────────────────┘")

        # 策略模式说明
        if strategy_mode == "academic":
            print("  [策略] academic 模式: Tier S → A → B → C → D 顺序尝试")
            print("         高 ASR 技术优先, Tier D 兜底 — ASR 非零即值得尝试")
            print("         首次运行使用学术先验 Q 值, 后续 memory 学习优化")
        elif strategy_mode == "exam":
            print("  [策略] exam 模式: 单轮 → 编码 → 多轮 (按执行速度排序)")
            print("         快速验证基础安全, 策略攻击兜底")
        else:
            print("  [策略] balanced 模式: 各 Tier 交替尝试")

    except Exception:
        pass  # 非关键路径


# ============================================================
# [5/8] 执行阶段展示
# ============================================================


def display_execution_stage(
    target_type: str = "",
    model_name: str = "",
    strategy_mode: str = "",
    attack_plans: list[Any] = None,
) -> None:
    """
    [5/8] 执行阶段 — 展示技术执行顺序 + Converter 路由 + 失败路由策略

    在原生 AdaptiveScenario 执行前，展示：
    1. Target 感知 Converter 路由结果
    2. 技术执行顺序（按学术 ASR 先验排序）
    3. 失败类型路由策略表
    """
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr

        if not strategy_mode:
            strategy_mode = _get_strategy_mode()
        if not model_name:
            model_name = _get_model_name()

        print("\n  ┌─ ASR策略: 执行决策 ─────────────────────────────┐")

        # 1. Target 感知 Converter 路由
        if target_type:
            try:
                from src.converters.target_aware_router import (
                    get_target_group,
                    get_target_converter_profile,
                    select_converter_chains_for_target,
                )
                _group = get_target_group(target_type)
                _profile = get_target_converter_profile(target_type)
                _chains = select_converter_chains_for_target(
                    target_type,
                    converter_target_available=True,
                )
                print(f"  │ Target 路由: {target_type} → {_group}")
                print(f"  │ 安全机制: {_profile.get('bypass_mechanism', 'unknown')}")
                if _chains:
                    print(f"  │ Converter 链 ({len(_chains)} 条):")
                    for i, chain in enumerate(_chains[:5]):
                        print(f"  │   {i+1}. {chain}")
                    if len(_chains) > 5:
                        print(f"  │   ... 还有 {len(_chains) - 5} 条")
            except Exception:
                pass

        # 2. 技术执行顺序（从 attack_plans 提取）
        if attack_plans:
            tech_list = []
            seen = set()
            for plan in attack_plans:
                tech = getattr(plan, "attack_technique", "")
                if tech and tech not in seen:
                    seen.add(tech)
                    asr = get_normalized_asr(tech, model_name)
                    tech_list.append((tech, asr, _get_tier(asr)))

            if tech_list:
                # 始终按 ASR 降序展示（高 ASR 优先）
                # 即使 exam 模式按速度执行，展示也应高 ASR 优先
                tech_list.sort(key=lambda x: -x[1])

                print("  │")
                print(f"  │ 技术执行顺序 ({len(tech_list)} 技术, 按策略 {strategy_mode} 排序):")
                for i, (tech, asr, tier) in enumerate(tech_list):
                    print(f"  │   {i+1}. [{tier}] {tech:40s} ASR={asr:.0%}")

        # 3. 失败类型路由策略表
        print("  │")
        print("  │ 失败类型路由策略:")
        print("  │   model_refusal       → 策略升级 (Tier S/A 优先)")
        print("  │   timeout             → 降级到单轮 (prompt_sending)")
        print("  │   scorer_error        → 换技术 (跳过当前)")
        print("  │   objective_failed    → 强技术升级 (Tier S)")
        print("  └──────────────────────────────────────────────────┘")

    except Exception:
        pass  # 非关键路径


# ============================================================
# [7/8] 执行后展示
# ============================================================


def display_post_execution(
    adaptive_result: Any = None,
    model_name: str = "",
) -> None:
    """
    [7/8] 执行后 — 展示 ASR 实测结果与学术先验对比

    在 AdaptiveScenario 执行完成后，展示：
    1. 各技术的实测 ASR
    2. 与学术先验的对比
    3. 失败类型分布
    """
    try:
        from src.payloads.technique_name_mapper import get_normalized_asr

        if not model_name:
            model_name = _get_model_name()

        if adaptive_result is None:
            return

        batch_result = getattr(adaptive_result, "batch_result", None)
        if batch_result is None or not batch_result.results:
            return

        # 统计各技术的成功/失败
        tech_stats: dict[str, dict[str, int]] = {}
        for result in batch_result.results:
            if result is None:
                continue
            # 从 result 获取技术名
            tech = ""
            identifier = getattr(result, "identifier", None)
            if identifier:
                tech = getattr(identifier, "attack_technique", "")
                if not tech:
                    children = getattr(identifier, "children", {})
                    tech = children.get("attack_technique", "")
            if not tech:
                continue

            if tech not in tech_stats:
                tech_stats[tech] = {"success": 0, "fail": 0, "total": 0}
            tech_stats[tech]["total"] += 1
            outcome = str(getattr(result, "outcome", "")).upper()
            if "SUCCESS" in outcome:
                tech_stats[tech]["success"] += 1
            else:
                tech_stats[tech]["fail"] += 1

        if not tech_stats:
            return

        print("\n  ┌─ ASR策略: 实测 ASR vs 学术先验 ──────────────────┐")
        print(f"  │ 模型: {model_name}")
        print("  │")
        print(f"  │ {'技术':40s} {'实测ASR':>8s} {'学术先验':>8s} {'差异':>8s} {'样本':>6s}")
        print(f"  │ {'─'*40} {'─'*8} {'─'*8} {'─'*8} {'─'*6}")

        # 按学术 ASR 降序排列（高 ASR 技术优先展示）
        for tech in sorted(tech_stats.keys(), key=lambda t: -get_normalized_asr(t, model_name)):
            stats = tech_stats[tech]
            total = stats["total"]
            if total == 0:
                continue
            empirical_asr = stats["success"] / total
            academic_asr = get_normalized_asr(tech, model_name)
            diff = empirical_asr - academic_asr
            diff_str = f"{diff:+.0%}"
            if diff > 0.1:
                diff_str += " ↑"
            elif diff < -0.1:
                diff_str += " ↓"
            print(f"  │ {tech:40s} {empirical_asr:7.0%} {academic_asr:7.0%} {diff_str:>8s} {total:6d}")

        # 失败类型分布
        failure_dist = getattr(adaptive_result, "failure_type_distribution", None)
        if failure_dist:
            print("  │")
            print("  │ 失败类型分布:")
            for ftype, count in sorted(failure_dist.items(), key=lambda x: -x[1]):
                print(f"  │   {ftype:30s} {count:4d} 次")

        most_common = getattr(adaptive_result, "most_common_failure_type", None)
        if most_common:
            print(f"  │ 最常见失败: {most_common}")

        print("  └──────────────────────────────────────────────────┘")

    except Exception:
        pass  # 非关键路径
