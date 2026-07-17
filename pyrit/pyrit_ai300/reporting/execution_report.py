# -*- coding: utf-8 -*-
"""
AI-300 Framework - Execution Report Generator
执行报告生成器：生成 Smart Match 执行过程的 Markdown 报告

功能：
1. 从 Smart Match 攻击结果生成详细的执行报告（Markdown 格式）
2. 包含分类统计、执行计划、详细结果、最佳组合

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# 分类/策略/评分器元数据（从 display 模块迁移）
CATEGORY_META: Dict[str, Dict[str, str]] = {
    "direct_short": {"label": "Direct Short", "desc": "直接注入短文本"},
    "role_play": {"label": "Role Play", "desc": "角色扮演类"},
    "multilingual": {"label": "Multilingual", "desc": "多语言载荷"},
    "encoded": {"label": "Encoded", "desc": "已编码载荷"},
    "long_context": {"label": "Long Context", "desc": "长文本载荷"},
    "prompt_leaking": {"label": "Prompt Leaking", "desc": "提示泄露"},
    "adversarial": {"label": "Adversarial", "desc": "对抗性后缀"},
    "markdown_injection": {"label": "Markdown Injection", "desc": "Markdown注入"},
    "indirect_injection": {"label": "Indirect Injection", "desc": "间接注入"},
    "context_splitting": {"label": "Context Splitting", "desc": "上下文拆分"},
    "instruction_override": {"label": "Instruction Override", "desc": "指令覆盖"},
    "payload_splitting": {"label": "Payload Splitting", "desc": "载荷拆分"},
    "data_exfiltration": {"label": "Data Exfiltration", "desc": "数据渗出"},
    "cross_context_contamination": {"label": "Cross-Context", "desc": "跨上下文污染"},
    "context_manipulation": {"label": "Context Manipulation", "desc": "上下文操纵"},
}

STRATEGY_META: Dict[str, Dict[str, str]] = {
    "single_turn": {"label": "Single-Turn", "desc": "单轮攻击"},
    "multi_turn": {"label": "Multi-Turn", "desc": "多轮攻击"},
    "tree_attack": {"label": "Tree Attack", "desc": "树状攻击"},
}

SCORER_META: Dict[str, Dict[str, str]] = {
    "refusal": {"label": "SelfAskRefusalScorer", "desc": "拒绝检测"},
    "true_false": {"label": "SelfAskTrueFalseScorer", "desc": "真假判断"},
    "substring": {"label": "SubStringScorer", "desc": "子串匹配"},
    "category": {"label": "SelfAskCategoryScorer", "desc": "分类评分"},
}


class ExecutionReportGenerator:
    """
    执行报告生成器

    从 Smart Match 攻击结果生成 Markdown 格式的执行报告。

    使用方式：
        reporter = ExecutionReportGenerator(output_dir="results/smart_match_reports")
        reporter.save_execution_report(results, plan, module_name, config_path, target_path)
    """

    def __init__(self, output_dir: str = "results/smart_match_reports"):
        """
        Args:
            output_dir: 报告输出目录
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_execution_report(
        self,
        results: Dict[str, Any],
        plan: List[Dict[str, Any]],
        module_name: str = "unknown",
        config_path: str = "",
        target_path: str = "",
    ) -> str:
        """
        保存执行报告到文件

        Returns:
            报告文件路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"smart_match_{module_name}_{timestamp}.md"
        filepath = self.output_dir / filename

        content = self._generate_report_markdown(results, plan, module_name, config_path, target_path)
        filepath.write_text(content, encoding="utf-8")
        logger.info("Execution report saved: %s", filepath)

        return str(filepath)

    def _generate_report_markdown(
        self,
        results: Dict[str, Any],
        plan: List[Dict[str, Any]],
        module_name: str,
        config_path: str,
        target_path: str,
    ) -> str:
        """生成 Markdown 格式执行报告"""
        total = results.get("total_executions", 0)
        success = results.get("success_count", 0)
        failure = results.get("failure_count", 0)
        rate = (success / (success + failure) * 100) if (success + failure) > 0 else 0
        category_stats = results.get("category_stats", {})
        best_combinations = results.get("best_combinations", [])
        plan_summary = results.get("plan_summary", {})

        lines = [
            f"# Smart Match Execution Report — {module_name}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Config:** {config_path}",
            f"**Target:** {target_path}",
            "**Mode:** smart_match",
            "",
            "---",
            "",
            "## 1. Execution Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Executions | {total} |",
            f"| Successful | {success} |",
            f"| Failed | {failure} |",
            f"| Success Rate | {rate:.1f}% |",
            "",
            "## 2. Plan Summary",
            "",
            f"- **By Category:** {', '.join(f'{k}: {v}' for k, v in plan_summary.get('by_category', {}).items())}",
            f"- **By Preset:** {', '.join(f'{k}: {v}' for k, v in plan_summary.get('by_preset', {}).items())}",
            f"- **By Strategy:** {', '.join(f'{k}: {v}' for k, v in plan_summary.get('by_strategy', {}).items())}",
            "",
            "## 3. Scorers (PyRIT Built-in)",
            "",
        ]

        # Collect unique scorers from plan
        plan_scorers = list(set(item.get("scorer", "") for item in plan if item.get("scorer")))
        if plan_scorers:
            lines.append("| Scorer | PyRIT Class | Description |")
            lines.append("|--------|------------|-------------|")
            for sname in plan_scorers:
                meta = SCORER_META.get(sname, {})
                label = meta.get("label", sname)
                desc = meta.get("desc", "")
                lines.append(f"| {label} | `pyrit.score.*.{label}` | {desc} |")
        else:
            lines.append("_No scorers configured._")

        lines.extend([
            "",
            "## 4. Execution Plan (Priority Order)",
            "",
            "| # | Category | Converter Preset | Converters | Strategy | Scorer | Expected | Payload |",
            "|---|----------|-----------------|------------|----------|--------|----------|---------|",
        ])

        for i, item in enumerate(plan, 1):
            cat = item.get("payload_category", "?")
            cat_meta = CATEGORY_META.get(cat, {})
            cat_label = cat_meta.get("label", cat)
            preset = item.get("converter_preset", "?")
            converters = " → ".join(item.get("converters", []))
            strategy = item.get("attack_strategy", "?")
            strat_meta = STRATEGY_META.get(strategy, {})
            strat_label = strat_meta.get("label", strategy)
            expected = item.get("expected_success", "?")
            raw_payload = item.get("payload", "")
            payload_str = str(raw_payload) if not isinstance(raw_payload, str) else raw_payload
            payload = payload_str[:55].replace("|", "\\|")
            if len(payload_str) > 55:
                payload += "..."

            # Scorer display
            scorer_name = item.get("scorer", "")
            scorer_meta = SCORER_META.get(scorer_name, {})
            scorer_label = scorer_meta.get("label", scorer_name[:14] if scorer_name else "—")

            lines.append(
                f"| {i} | {cat_label} | {preset} | {converters} | {strat_label} | {scorer_label} | {expected} | {payload} |"
            )

        lines.extend([
            "",
            "## 5. Detailed Results",
            "",
            "| # | Category | Preset | Strategy | Scorer | Status | Response |",
            "|---|----------|--------|----------|--------|--------|----------|",
        ])

        for i, r in enumerate(results.get("results", []), 1):
            cat = r.get("payload_category", "?")
            cat_meta = CATEGORY_META.get(cat, {})
            cat_label = cat_meta.get("label", cat)
            preset = r.get("converter_preset", "?")
            strategy = r.get("attack_strategy", "?")
            scorer_name = r.get("scorer", "")
            scorer_meta = SCORER_META.get(scorer_name, {})
            scorer_label = scorer_meta.get("label", scorer_name[:14] if scorer_name else "—")
            status = r.get("status", "?")
            raw_response = r.get("response", r.get("error", ""))
            response_str = str(raw_response) if not isinstance(raw_response, str) else raw_response
            response = response_str[:70].replace("|", "\\|")

            lines.append(
                f"| {i} | {cat_label} | {preset} | {strategy} | {scorer_label} | {status} | {response} |"
            )

        lines.extend([
            "",
            "## 6. Category Statistics",
            "",
            "| Category | Success | Failed | Rate | Best Combination |",
            "|----------|---------|--------|------|-----------------|",
        ])

        for cat, stats in sorted(category_stats.items()):
            cat_meta = CATEGORY_META.get(cat, {})
            cat_label = cat_meta.get("label", cat)
            s = stats.get("success", 0)
            f = stats.get("failure", 0)
            total_cat = s + f
            rate_cat = (s / total_cat * 100) if total_cat > 0 else 0

            best_combo = ""
            combos = stats.get("combinations", {})
            if combos:
                best_key = max(combos, key=lambda k: combos[k]["success"])
                best_s = combos[best_key]["success"]
                best_f = combos[best_key]["failure"]
                best_total = best_s + best_f
                best_rate = (best_s / best_total * 100) if best_total > 0 else 0
                best_combo = f"{best_key} ({best_rate:.0f}%)"

            lines.append(
                f"| {cat_label} | {s} | {f} | {rate_cat:.0f}% | {best_combo} |"
            )

        if best_combinations:
            lines.extend([
                "",
                "## 7. Top Performing Combinations",
                "",
                "| Category | Combination | Success Rate | Tests |",
                "|----------|-------------|-------------|-------|",
            ])
            for combo in best_combinations:
                cat = combo.get("category", "?")
                cat_meta = CATEGORY_META.get(cat, {})
                cat_label = cat_meta.get("label", cat)
                lines.append(
                    f"| {cat_label} | {combo.get('combination', '')} | "
                    f"{combo.get('success_rate', 0) * 100:.0f}% | {combo.get('total_tests', 0)} |"
                )

        lines.extend([
            "",
            "---",
            "",
            "*Generated by AI-300 Framework v2.0 — Smart Match Engine*",
        ])

        return "\n".join(lines)
