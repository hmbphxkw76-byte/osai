"""
Diversity Analyzer
==================

攻击多样性与覆盖度分析器 — 从攻击结果中计算多样性指标。

计算指标：
  1. 技术 Shannon 熵 — 衡量攻击技术覆盖的均匀度（越高越多样）
  2. 技术覆盖广度 — 使用的独立技术数 / 总可用技术数
  3. OWASP 覆盖广度 — 已覆盖 OWASP ID 数 / 总 20 个 OWASP ID
  4. Converter 多样性指数 — 使用的独立 Converter 链数 / 总攻击数
  5. 失败模式集中度 — 最大失败原因占比（越高越集中，越低越分散）
  6. 成功/失败技术分布 — 按成功/失败分别统计技术分布

设计原则：
  - 纯函数设计，无副作用
  - 不依赖 PyRIT 内部状态，仅接收已收集的统计数据
  - 所有指标可独立计算，也可批量计算
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================
# 常量
# ============================================================

# PyRIT 1.0.0 支持的攻击技术总数（用于计算覆盖率）
_TOTAL_AVAILABLE_TECHNIQUES = 12

# OWASP Top 10 总数（LLM 10 + Agentic AI 10 = 20）
_TOTAL_OWASP_IDS = 20


# ============================================================
# 核心指标计算
# ============================================================


def calculate_shannon_entropy(distribution: Dict[str, int]) -> float:
    """
    计算 Shannon 熵

    衡量分布的多样性/均匀度。
    - 值越高 → 分布越均匀（多样性好）
    - 值为 0 → 只有一个类别（无多样性）
    - 最大值 = log2(n)，n 为类别数

    Args:
        distribution: {类别名: 计数} 字典

    Returns:
        Shannon 熵值（float，0 到 log2(n)）
    """
    total = sum(distribution.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in distribution.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_normalized_entropy(distribution: Dict[str, int]) -> float:
    """
    计算归一化 Shannon 熵（0.0 ~ 1.0）

    将 Shannon 熵除以最大可能熵（log2(n)），得到 0-1 范围的归一化值。
    1.0 表示完全均匀分布，0.0 表示完全集中。

    Args:
        distribution: {类别名: 计数} 字典

    Returns:
        归一化熵值（0.0 ~ 1.0）
    """
    n = len(distribution)
    if n <= 1:
        return 0.0

    raw_entropy = calculate_shannon_entropy(distribution)
    max_entropy = math.log2(n)

    return round(raw_entropy / max_entropy, 4) if max_entropy > 0 else 0.0


def calculate_coverage_ratio(used_count: int, total_available: int) -> float:
    """
    计算覆盖率

    Args:
        used_count: 已使用的数量
        total_available: 总可用数量

    Returns:
        覆盖率（0.0 ~ 1.0）
    """
    if total_available <= 0:
        return 0.0
    return round(min(used_count / total_available, 1.0), 4)


def calculate_concentration_ratio(distribution: Dict[str, int]) -> float:
    """
    计算集中度（最大类别占比）

    衡量分布是否集中于某一类别。
    - 值越高 → 越集中于单一类别
    - 值越低 → 越分散

    Args:
        distribution: {类别名: 计数} 字典

    Returns:
        最大类别占比（0.0 ~ 1.0）
    """
    total = sum(distribution.values())
    if total == 0 or not distribution:
        return 0.0

    max_count = max(distribution.values())
    return round(max_count / total, 4)


def split_technique_distribution_by_outcome(
    attack_results: List[Any],
) -> Tuple[Dict[str, int], Dict[str, int]]:
    """
    按成功/失败拆分攻击技术分布

    Args:
        attack_results: AttackResult 列表

    Returns:
        (success_distribution, failure_distribution) 元组
    """
    success_dist: Dict[str, int] = {}
    failure_dist: Dict[str, int] = {}

    for ar in attack_results:
        # 提取攻击类型
        technique = _extract_technique(ar)

        # 提取 outcome
        outcome = _extract_outcome(ar)

        if outcome == "SUCCESS":
            success_dist[technique] = success_dist.get(technique, 0) + 1
        else:
            failure_dist[technique] = failure_dist.get(technique, 0) + 1

    return success_dist, failure_dist


def calculate_owasp_coverage_breadth(
    coverage_matrix: Dict[str, Dict[str, Any]],
) -> Tuple[int, int, float]:
    """
    计算 OWASP 覆盖广度

    Args:
        coverage_matrix: OWASP 覆盖矩阵（由 OWASPMapper.build_coverage_matrix 生成）

    Returns:
        (covered_count, total_count, coverage_ratio) 元组
    """
    if not coverage_matrix:
        return 0, _TOTAL_OWASP_IDS, 0.0

    covered = sum(1 for info in coverage_matrix.values() if info.get("covered"))
    total = len(coverage_matrix) if len(coverage_matrix) > 0 else _TOTAL_OWASP_IDS

    # 确保分母不超过总 OWASP 数
    total = min(total, _TOTAL_OWASP_IDS)
    ratio = calculate_coverage_ratio(covered, total)

    return covered, total, ratio


# ============================================================
# 多样性分析主类
# ============================================================


class DiversityAnalysisResult:
    """
    多样性分析结果

    包含所有计算的多样性指标，可直接用于报告渲染。
    """

    def __init__(
        self,
        technique_entropy: float = 0.0,
        technique_normalized_entropy: float = 0.0,
        technique_coverage_ratio: float = 0.0,
        unique_techniques_used: int = 0,
        owasp_covered_count: int = 0,
        owasp_total_count: int = _TOTAL_OWASP_IDS,
        owasp_coverage_ratio: float = 0.0,
        converter_diversity_ratio: float = 0.0,
        unique_converters_used: int = 0,
        failure_concentration: float = 0.0,
        top_failure_reason: str = "",
        success_technique_distribution: Optional[Dict[str, int]] = None,
        failure_technique_distribution: Optional[Dict[str, int]] = None,
    ):
        self.technique_entropy = technique_entropy
        self.technique_normalized_entropy = technique_normalized_entropy
        self.technique_coverage_ratio = technique_coverage_ratio
        self.unique_techniques_used = unique_techniques_used
        self.owasp_covered_count = owasp_covered_count
        self.owasp_total_count = owasp_total_count
        self.owasp_coverage_ratio = owasp_coverage_ratio
        self.converter_diversity_ratio = converter_diversity_ratio
        self.unique_converters_used = unique_converters_used
        self.failure_concentration = failure_concentration
        self.top_failure_reason = top_failure_reason
        self.success_technique_distribution = success_technique_distribution or {}
        self.failure_technique_distribution = failure_technique_distribution or {}

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于 Pydantic 模型序列化）"""
        return {
            "technique_entropy": self.technique_entropy,
            "technique_normalized_entropy": self.technique_normalized_entropy,
            "technique_coverage_ratio": self.technique_coverage_ratio,
            "unique_techniques_used": self.unique_techniques_used,
            "owasp_covered_count": self.owasp_covered_count,
            "owasp_total_count": self.owasp_total_count,
            "owasp_coverage_ratio": self.owasp_coverage_ratio,
            "converter_diversity_ratio": self.converter_diversity_ratio,
            "unique_converters_used": self.unique_converters_used,
            "failure_concentration": self.failure_concentration,
            "top_failure_reason": self.top_failure_reason,
            "success_technique_distribution": self.success_technique_distribution,
            "failure_technique_distribution": self.failure_technique_distribution,
        }

    def get_diversity_grade(self) -> str:
        """
        根据归一化熵给出多样性等级

        Returns:
            等级字符串："Excellent" / "Good" / "Moderate" / "Low" / "Poor"
        """
        e = self.technique_normalized_entropy
        if e >= 0.8:
            return "Excellent"
        elif e >= 0.6:
            return "Good"
        elif e >= 0.4:
            return "Moderate"
        elif e >= 0.2:
            return "Low"
        else:
            return "Poor"


class DiversityAnalyzer:
    """
    攻击多样性分析器

    从攻击结果和统计数据中计算多样性指标。
    可直接用于报告生成，也可独立调用进行分析。
    """

    def analyze(
        self,
        attack_results: List[Any],
        technique_distribution: Dict[str, int],
        converter_usage: Dict[str, int],
        failure_reasons: Dict[str, int],
        coverage_matrix: Optional[Dict[str, Dict[str, Any]]] = None,
        total_attacks: int = 0,
    ) -> DiversityAnalysisResult:
        """
        执行完整的多样性分析

        Args:
            attack_results: AttackResult 列表（用于拆分成功/失败技术分布）
            technique_distribution: 技术分布统计 {技术名: 计数}
            converter_usage: Converter 链使用统计 {链名: 计数}
            failure_reasons: 失败原因统计 {原因: 计数}
            coverage_matrix: OWASP 覆盖矩阵（可选）
            total_attacks: 总攻击数

        Returns:
            DiversityAnalysisResult 实例
        """
        # 1. 技术多样性
        technique_entropy = calculate_shannon_entropy(technique_distribution)
        technique_normalized = calculate_normalized_entropy(technique_distribution)
        unique_techniques = len(technique_distribution)
        technique_coverage = calculate_coverage_ratio(
            unique_techniques, _TOTAL_AVAILABLE_TECHNIQUES
        )

        # 2. OWASP 覆盖广度
        owasp_covered, owasp_total, owasp_ratio = 0, _TOTAL_OWASP_IDS, 0.0
        if coverage_matrix:
            owasp_covered, owasp_total, owasp_ratio = calculate_owasp_coverage_breadth(
                coverage_matrix
            )

        # 3. Converter 多样性
        unique_converters = len(converter_usage)
        converter_diversity = 0.0
        if total_attacks > 0 and unique_converters > 0:
            # Converter 多样性 = 使用了 Converter 的攻击比例 × Converter 种类多样性
            converter_attack_count = sum(converter_usage.values())
            converter_usage_ratio = converter_attack_count / total_attacks
            converter_entropy = calculate_normalized_entropy(converter_usage)
            converter_diversity = round(converter_usage_ratio * converter_entropy, 4)

        # 4. 失败模式集中度
        failure_concentration = calculate_concentration_ratio(failure_reasons)
        top_failure_reason = ""
        if failure_reasons:
            top_failure_reason = max(failure_reasons, key=failure_reasons.get)

        # 5. 成功/失败技术分布拆分
        success_dist, failure_dist = split_technique_distribution_by_outcome(
            attack_results
        )

        return DiversityAnalysisResult(
            technique_entropy=technique_entropy,
            technique_normalized_entropy=technique_normalized,
            technique_coverage_ratio=technique_coverage,
            unique_techniques_used=unique_techniques,
            owasp_covered_count=owasp_covered,
            owasp_total_count=owasp_total,
            owasp_coverage_ratio=owasp_ratio,
            converter_diversity_ratio=converter_diversity,
            unique_converters_used=unique_converters,
            failure_concentration=failure_concentration,
            top_failure_reason=top_failure_reason,
            success_technique_distribution=success_dist,
            failure_technique_distribution=failure_dist,
        )


# ============================================================
# 辅助函数
# ============================================================


def _extract_technique(ar: Any) -> str:
    """从 AttackResult 提取攻击技术名称"""
    # 优先从 labels 提取
    labels = getattr(ar, "labels", None)
    if isinstance(labels, dict):
        tech = labels.get("attack_technique")
        if tech:
            return str(tech)

    # 回退到 attack strategy identifier
    try:
        strategy_id = ar.get_attack_strategy_identifier()
        if strategy_id:
            return str(strategy_id).split("::")[0]
    except Exception:
        pass

    # 回退到 atomic_attack_identifier
    raw = getattr(ar, "atomic_attack_identifier", None)
    if raw:
        return str(raw).split("::")[0]

    return "unknown"


def _extract_outcome(ar: Any) -> str:
    """从 AttackResult 提取 outcome 字符串"""
    outcome = getattr(ar, "outcome", None)
    if outcome is None:
        return "unknown"
    if hasattr(outcome, "value"):
        return str(outcome.value).upper()
    return str(outcome).upper()


# ============================================================
# 报告渲染辅助
# ============================================================


def render_diversity_section(result: DiversityAnalysisResult) -> str:
    """
    渲染多样性分析 Markdown 章节

    生成一个完整的 Markdown 章节，可直接插入报告中。

    Args:
        result: DiversityAnalysisResult 实例

    Returns:
        Markdown 格式的多样性分析章节字符串
    """
    grade = result.get_diversity_grade()

    lines = [
        "### Diversity & Coverage Analysis",
        "",
        "This section provides quantitative metrics on the diversity and breadth",
        "of the attack techniques used during the assessment.",
        "",
        "| Metric | Value | Description |",
        "|--------|-------|-------------|",
        f"| Technique Entropy | {result.technique_entropy:.2f} bits | Shannon entropy of technique distribution (higher = more diverse) |",
        f"| Normalized Entropy | {result.technique_normalized_entropy:.2%} | Entropy relative to maximum possible (0-100%) |",
        f"| Diversity Grade | {grade} | Qualitative assessment of technique diversity |",
        f"| Unique Techniques | {result.unique_techniques_used} / {_TOTAL_AVAILABLE_TECHNIQUES} | Number of distinct attack techniques used |",
        f"| Technique Coverage | {result.technique_coverage_ratio:.0%} | Ratio of available techniques actually employed |",
        f"| OWASP Coverage | {result.owasp_covered_count} / {result.owasp_total_count} ({result.owasp_coverage_ratio:.0%}) | OWASP IDs covered by at least one attack |",
        f"| Converter Diversity | {result.converter_diversity_ratio:.2%} | Weighted diversity of converter chains used |",
        f"| Unique Converters | {result.unique_converters_used} | Number of distinct converter chains employed |",
        f"| Failure Concentration | {result.failure_concentration:.0%} | Proportion of failures attributed to the top reason |",
        "",
    ]

    # 成功技术分布
    if result.success_technique_distribution:
        lines.extend([
            "#### Successful Attack Techniques",
            "",
            "| Technique | Count |",
            "|-----------|-------|",
        ])
        for tech, count in sorted(
            result.success_technique_distribution.items(), key=lambda x: -x[1]
        ):
            lines.append(f"| {tech} | {count} |")
        lines.append("")

    # 失败技术分布
    if result.failure_technique_distribution:
        lines.extend([
            "#### Failed Attack Techniques",
            "",
            "| Technique | Count |",
            "|-----------|-------|",
        ])
        for tech, count in sorted(
            result.failure_technique_distribution.items(), key=lambda x: -x[1]
        ):
            lines.append(f"| {tech} | {count} |")
        lines.append("")

    # 失败模式分析
    if result.top_failure_reason:
        lines.extend([
            "#### Failure Mode Analysis",
            "",
            f"- **Top Failure Reason**: `{result.top_failure_reason}`",
            f"- **Concentration**: {result.failure_concentration:.0%} of failures share the same root cause",
            "",
        ])

        if result.failure_concentration > 0.5:
            lines.append(
                "> ⚠️ **Warning**: High failure concentration suggests a systematic issue. "
                "Consider adjusting attack parameters or scorer configurations."
            )
            lines.append("")

    return "\n".join(lines)
