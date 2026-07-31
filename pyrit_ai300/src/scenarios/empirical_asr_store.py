"""
Empirical ASR Store — L5 ASR 反馈回路 Tier 2
=============================================

三层数据架构:
  Tier 1: 学术先验 (asr_prior_registry.py, 只读, 不可变)
  Tier 2: 经验 ASR (本模块, JSON 持久化, per-model)  ← 新增
  Tier 3: 运行时 Q 值 (PyRIT 原生 CentralMemory, SQLite)

Tier 2 设计:
  - 存储: output/empirical_asr/{model_slug}.json
  - 每次 pipeline 运行后自动更新
  - 下次运行时加载并融合学术先验
  - 融合权重随 run_count 递增:
    run_count=0:   100% Tier1
    run_count<=2:   80% Tier1 + 20% Tier2
    run_count<=5:   60% Tier1 + 40% Tier2
    run_count>5:    50% Tier1 + 50% Tier2

功能:
  1. load_empirical_asr — 加载 per-model 经验 ASR
  2. update_empirical_asr — 融合本次运行结果到经验 ASR
  3. compute_effective_asr — 融合学术 + 经验计算 effective ASR
  4. detect_patched_techniques — 检测被补丁修复的技术
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 经验 ASR 存储目录
_EMPIRICAL_ASR_DIR = Path("output") / "empirical_asr"

# 融合权重曲线
_WEIGHT_CURVE = {
    0: 0.0,    # 0 次运行: 100% 学术
    2: 0.2,    # 1-2 次: 80% 学术 + 20% 经验
    5: 0.4,    # 3-5 次: 60% 学术 + 40% 经验
    99: 0.5,   # 6+ 次: 50% 学术 + 50% 经验
}

# Patched 检测阈值: 实测低于先验 30% 标记为 patched
_PATCHED_THRESHOLD = 0.3


def _get_model_slug(model_name: str) -> str:
    """
    将模型名转换为文件安全的 slug

    Args:
        model_name: 模型名 (如 "LongCat-2.0", "gpt-4o")

    Returns:
        slug (如 "longcat-2_0", "gpt-4o")
    """
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", model_name.lower())
    return slug


def _get_empirical_asr_path(model_name: str) -> Path:
    """获取 per-model 经验 ASR 文件路径"""
    slug = _get_model_slug(model_name)
    _EMPIRICAL_ASR_DIR.mkdir(parents=True, exist_ok=True)
    return _EMPIRICAL_ASR_DIR / f"{slug}.json"


def load_empirical_asr(model_name: str) -> Optional[Dict[str, Any]]:
    """
    加载 per-model 经验 ASR

    Args:
        model_name: 目标模型名

    Returns:
        经验 ASR 字典, 不存在返回 None
    """
    path = _get_empirical_asr_path(model_name)
    if not path.exists():
        logger.debug(f"Empirical ASR not found for '{model_name}': {path}")
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        logger.info(
            f"Loaded empirical ASR for '{model_name}': "
            f"run_count={data.get('run_count', 0)}, "
            f"techniques={len(data.get('techniques', {}))}"
        )
        return data
    except Exception as e:
        logger.warning(f"Failed to load empirical ASR from {path}: {e}")
        return None


def update_empirical_asr(
    model_name: str,
    model_tier: str,
    tech_stats: Dict[str, Dict[str, int]],
    converter_stats: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    更新经验 ASR — 融合本次运行结果到持久化存储

    融合公式:
      new_empirical_asr = (old_empirical * old_count + new_data)
                          / (old_count + 1)

    Args:
        model_name: 目标模型名
        model_tier: 模型过滤强度
        tech_stats: {technique: {"attempts": N, "successes": S, "failures": F,
                                  "failure_types": {type: count}}}
        converter_stats: {converter: {"attempts": N, "successes": S, ...}}

    Returns:
        更新后的经验 ASR 字典
    """
    path = _get_empirical_asr_path(model_name)

    # 加载已有数据
    existing = load_empirical_asr(model_name) or {
        "model_name": model_name,
        "model_tier": model_tier,
        "run_count": 0,
        "techniques": {},
        "converter_effectiveness": {},
    }

    old_run_count = existing.get("run_count", 0)
    old_techniques = existing.get("techniques", {})

    # 融合技术统计
    for tech, new_stats in tech_stats.items():
        new_attempts = new_stats.get("attempts", 0)
        new_successes = new_stats.get("successes", 0)
        new_failures = new_stats.get("failures", 0)
        new_failure_types = new_stats.get("failure_types", {})

        old = old_techniques.get(tech, {
            "attempts": 0,
            "successes": 0,
            "failures": 0,
            "empirical_asr": 0.0,
            "failure_types": {},
            "total_runs": 0,
        })

        # 增量融合
        total_attempts = old["attempts"] + new_attempts
        total_successes = old["successes"] + new_successes
        total_failures = old["failures"] + new_failures
        total_runs = old.get("total_runs", 0) + 1

        if total_attempts > 0:
            # 按运行次数加权平均
            old_weight = old.get("total_runs", 0)
            new_weight = 1
            if old_weight + new_weight > 0:
                empirical_asr = (
                    old.get("empirical_asr", 0.0) * old_weight
                    + (new_successes / max(new_attempts, 1)) * new_weight
                ) / (old_weight + new_weight)
            else:
                empirical_asr = 0.0
        else:
            empirical_asr = old.get("empirical_asr", 0.0)

        # 融合 failure_types
        merged_ft: Dict[str, int] = dict(old.get("failure_types", {}))
        for ft, count in new_failure_types.items():
            merged_ft[ft] = merged_ft.get(ft, 0) + count

        old_techniques[tech] = {
            "attempts": total_attempts,
            "successes": total_successes,
            "failures": total_failures,
            "empirical_asr": round(empirical_asr, 4),
            "failure_types": merged_ft,
            "total_runs": total_runs,
        }

    # 融合 converter 统计
    converter_eff = existing.get("converter_effectiveness", {})
    if converter_stats:
        for conv, stats in converter_stats.items():
            old_conv = converter_eff.get(conv, {
                "attempts": 0,
                "successes": 0,
                "asr": 0.0,
                "disabled": False,
            })
            total_att = old_conv["attempts"] + stats.get("attempts", 0)
            total_suc = old_conv["successes"] + stats.get("successes", 0)
            is_disabled = stats.get("disabled", False) or old_conv.get("disabled", False)
            failure_reason = stats.get("failure_reason", "") or old_conv.get("failure_reason", "")
            converter_eff[conv] = {
                "attempts": total_att,
                "successes": total_suc,
                "asr": round(total_suc / max(total_att, 1), 4),
                "disabled": is_disabled,
                "failure_reason": failure_reason,
            }

    # 更新元数据
    updated = {
        "model_name": model_name,
        "model_tier": model_tier,
        "run_count": old_run_count + 1,
        "last_updated": _get_iso_timestamp(),
        "techniques": old_techniques,
        "converter_effectiveness": converter_eff,
    }

    # 写入文件
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(updated, f, ensure_ascii=False, indent=2)
        logger.info(
            f"Empirical ASR updated for '{model_name}': "
            f"run_count={updated['run_count']}, "
            f"techniques={len(old_techniques)}, "
            f"path={path}"
        )
    except Exception as e:
        logger.warning(f"Failed to write empirical ASR to {path}: {e}")

    return updated


def compute_effective_asr(
    technique: str,
    model_name: str,
    academic_asr: float,
    empirical_data: Optional[Dict[str, Any]] = None,
) -> float:
    """
    三层 ASR 融合计算

    权重随运行次数递增:
    - 0 次运行: 100% 学术
    - 1-2 次运行: 80% 学术 + 20% 经验
    - 3-5 次运行: 60% 学术 + 40% 经验
    - 6+ 次运行: 50% 学术 + 50% 经验 (上限)

    Args:
        technique: 技术名
        model_name: 目标模型名
        academic_asr: 学术先验 ASR
        empirical_data: 经验 ASR 数据 (来自 load_empirical_asr)

    Returns:
        融合后的 effective ASR (0.0-1.0)
    """
    if empirical_data is None:
        return academic_asr

    run_count = empirical_data.get("run_count", 0)
    tech_data = empirical_data.get("techniques", {}).get(technique)
    # P0-2 向后兼容: 旧版 JSON 可能存储 PascalCase 键 (如 "PromptSendingAttack")
    if tech_data is None:
        from src.payloads.technique_name_mapper import PASCAL_TO_SNAKE
        _pascal_name = next(
            (p for p, s in PASCAL_TO_SNAKE.items() if s == technique),
            None,
        )
        if _pascal_name:
            tech_data = empirical_data.get("techniques", {}).get(_pascal_name)
    if tech_data is None or tech_data.get("attempts", 0) == 0:
        return academic_asr

    empirical_asr = tech_data.get("empirical_asr", 0.0)

    # 获取经验权重
    empirical_weight = _get_empirical_weight(run_count)

    effective = (1 - empirical_weight) * academic_asr + empirical_weight * empirical_asr
    logger.debug(
        f"Effective ASR for '{technique}': "
        f"academic={academic_asr:.0%} * {1 - empirical_weight:.0%} + "
        f"empirical={empirical_asr:.0%} * {empirical_weight:.0%} = "
        f"{effective:.0%} (run_count={run_count})"
    )
    return effective


def _get_empirical_weight(run_count: int) -> float:
    """根据运行次数获取经验权重"""
    for threshold, weight in sorted(_WEIGHT_CURVE.items(), reverse=True):
        if run_count >= threshold:
            return weight
    return 0.0


def detect_patched_techniques(
    academic_asr_map: Dict[str, float],
    empirical_data: Optional[Dict[str, Any]],
    threshold: float = _PATCHED_THRESHOLD,
) -> List[Dict[str, Any]]:
    """
    检测被补丁修复的技术

    判定标准: 实测 ASR < 学术先验 ASR - threshold (30%)

    Args:
        academic_asr_map: {technique: academic_asr}
        empirical_data: 经验 ASR 数据
        threshold: 差异阈值

    Returns:
        patched 技术列表, 按 delta 降序排列:
        [{"technique": "crescendo", "academic": 0.82, "empirical": 0.20,
          "delta": -0.62, "status": "patched"}]
    """
    if empirical_data is None:
        return []

    emp_techniques = empirical_data.get("techniques", {})
    patched = []

    for tech, academic in academic_asr_map.items():
        tech_data = emp_techniques.get(tech)
        # P0-2 向后兼容: 旧版 JSON 可能存储 PascalCase 键
        if tech_data is None:
            from src.payloads.technique_name_mapper import PASCAL_TO_SNAKE
            _pascal_name = next(
                (p for p, s in PASCAL_TO_SNAKE.items() if s == tech),
                None,
            )
            if _pascal_name:
                tech_data = emp_techniques.get(_pascal_name)
        if tech_data is None:
            continue
        attempts = tech_data.get("attempts", 0)
        if attempts < 2:  # 样本不足, 不判定
            continue

        empirical_asr = tech_data.get("empirical_asr", 0.0)
        delta = empirical_asr - academic
        if academic > 0.15 and delta < -threshold:
            patched.append({
                "technique": tech,
                "academic": round(academic, 3),
                "empirical": round(empirical_asr, 3),
                "delta": round(delta, 3),
                "attempts": attempts,
                "status": "patched",
            })

    return sorted(patched, key=lambda x: x["delta"])


def generate_strategy_recommendation(
    model_name: str,
    empirical_data: Optional[Dict[str, Any]],
    academic_asr_map: Dict[str, float],
    patched_list: List[Dict[str, Any]],
) -> List[str]:
    """
    根据经验 ASR 生成下次运行策略建议

    Returns:
        策略建议字符串列表
    """
    recommendations = []

    if empirical_data is None:
        recommendations.append("首次运行: 使用学术先验 warm-start, 建议 academic 模式")
        return recommendations

    run_count = empirical_data.get("run_count", 0)
    recommendations.append(f"经验数据: {run_count} 次运行, 融合权重={_get_empirical_weight(run_count):.0%}")

    # patched 技术建议
    for p in patched_list[:3]:
        recommendations.append(
            f"[PATCHED] {p['technique']}: 学术 {p['academic']:.0%} → 实测 {p['empirical']:.0%} "
            f"(Δ{p['delta']:+.0%}), 建议降低优先级"
        )

    # 最有效技术
    emp_techs = empirical_data.get("techniques", {})
    effective = [
        (tech, data.get("empirical_asr", 0.0), data.get("attempts", 0))
        for tech, data in emp_techs.items()
        if data.get("attempts", 0) >= 2
    ]
    effective.sort(key=lambda x: -x[1])

    if effective:
        top3 = effective[:3]
        for tech, asr, attempts in top3:
            recommendations.append(
                f"[推荐] {tech}: 经验 ASR {asr:.0%} ({attempts} 次尝试), 建议优先"
            )

    # 被熔断的 converter
    conv_eff = empirical_data.get("converter_effectiveness", {})
    disabled = [
        name for name, data in conv_eff.items()
        if data.get("disabled", False)
    ]
    if disabled:
        recommendations.append(
            f"[熔断] {', '.join(disabled)}: 已被熔断, 建议下次跳过"
        )

    return recommendations


def _get_iso_timestamp() -> str:
    """获取 ISO 格式时间戳"""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def extract_tech_stats_from_results(
    native_result: Any,
    model_name: str,
) -> Dict[str, Dict[str, int]]:
    """
    从原生 ScenarioResult 提取 per-technique 统计

    Args:
        native_result: PyRIT 原生 ScenarioResult
        model_name: 目标模型名

    Returns:
        {technique: {"attempts": N, "successes": S, "failures": F,
                      "failure_types": {type: count}}}
    """
    tech_stats: Dict[str, Dict[str, int]] = {}

    if native_result is None or not hasattr(native_result, "get_display_groups"):
        return tech_stats

    from src.scenarios.failure_type_selector import extract_failure_type_from_result

    display_groups = native_result.get_display_groups()
    for _group_name, results in display_groups.items():
        for r in results:
            if r is None:
                continue

            # 提取技术名
            tech = _extract_technique_name(r)
            if not tech:
                continue

            if tech not in tech_stats:
                tech_stats[tech] = {
                    "attempts": 0,
                    "successes": 0,
                    "failures": 0,
                    "failure_types": {},
                }

            tech_stats[tech]["attempts"] += 1

            outcome = getattr(r, "outcome", None)
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

            if outcome_str == "SUCCESS":
                tech_stats[tech]["successes"] += 1
            else:
                tech_stats[tech]["failures"] += 1
                # 提取失败类型
                ftype = extract_failure_type_from_result(r)
                tech_stats[tech]["failure_types"][ftype] = \
                    tech_stats[tech]["failure_types"].get(ftype, 0) + 1

            # 检查 SequentialAttackResult 子结果
            child_results = getattr(r, "child_attack_results", None) or []
            for child in child_results:
                if child is None:
                    continue
                child_tech = _extract_technique_name(child)
                if not child_tech or child_tech == tech:
                    continue  # 同技术, 已统计
                if child_tech not in tech_stats:
                    tech_stats[child_tech] = {
                        "attempts": 0,
                        "successes": 0,
                        "failures": 0,
                        "failure_types": {},
                    }
                tech_stats[child_tech]["attempts"] += 1
                child_outcome = getattr(child, "outcome", None)
                child_outcome_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                if child_outcome_str == "SUCCESS":
                    tech_stats[child_tech]["successes"] += 1
                else:
                    tech_stats[child_tech]["failures"] += 1
                    cft = extract_failure_type_from_result(child)
                    tech_stats[child_tech]["failure_types"][cft] = \
                        tech_stats[child_tech]["failure_types"].get(cft, 0) + 1

    return tech_stats


def _extract_technique_name(result: Any) -> str:
    """从 AttackResult 提取技术名 (标准化为 snake_case)

    P0-2 修复: 统一返回 snake_case 技术名, 与 asr_prior_registry key 一致。
    原实现返回 PascalCase (如 "PromptSendingAttack"), 导致经验 ASR 读写键名不一致。
    """
    from src.payloads.technique_name_mapper import normalize_technique_name

    # 方法1: identifier
    identifier = None
    if hasattr(result, "get_attack_strategy_identifier"):
        try:
            identifier = result.get_attack_strategy_identifier()
        except Exception:
            pass
    if identifier:
        name = getattr(identifier, "unique_name", "")
        if name:
            # 格式: "PromptSendingAttack::hash" 或 "PromptSendingAttack+Converter::hash"
            base = name.split("::")[0] if "::" in name else name
            # 分离 Converter 变体: "PromptSendingAttack+stealth_evasion" → "PromptSendingAttack"
            if "+" in base:
                base = base.split("+", 1)[0]
            # 标准化: PascalCase → snake_case
            return normalize_technique_name(base)

    # 方法2: attack_technique (已经是 snake_case)
    tech = getattr(result, "attack_technique", "")
    if tech:
        return normalize_technique_name(tech)

    return ""
