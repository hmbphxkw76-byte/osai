# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 5: ASR 驱动的结果输出 + 增强报告系统 + 证据收集。.

职责:
  - ``output_scenario_async()`` 场景结果汇总 (Per-Group Breakdown, 按 ASR 排序)
  - ``output_scorer_async()`` 评分器指标
  - EvidenceExporter 统一生成攻击 Markdown 报告 (render_async)
  - 证据收集 (结构化漏洞证据 JSON + Markdown) — 核心
  - 组级 ASR 降级链报告 — 核心
  - 攻击多样性分析 (可选, ``--analyze`` 标志触发)
  - Converter 转换日志 (可选, ``--analyze`` 标志触发)
  - 三层渐进式选择向导推荐 (可选, ``--analyze`` 标志触发)
  - 打印 ASR 总结

优化4: diversity_analyzer / tiered_selection_wizard / converter_log 降级为可选
  离线分析, 默认不在流水线中执行, 通过 ``--analyze`` 标志触发。

产出 (写入 PipelineContext):
  - ctx.output_dir = 报告输出目录
  - ctx.metadata["diversity_metrics"] = 多样性指标
  - ctx.metadata["converter_log"] = Converter 日志报告
  - ctx.metadata["evidence_collection"] = 证据集合

依赖的原生 API:
  - pyrit.output.output_scenario_async
  - pyrit.output.output_scorer_async
  - pyrit.output.attack_result.markdown.MarkdownAttackResultMemoryPrinter (via EvidenceExporter)
  - pyrit.output.conversation.markdown.MarkdownConversationMemoryPrinter (via EvidenceExporter)
  - pyrit.output.score.markdown.MarkdownScorePrinter (via EvidenceExporter)

自研模块 (报告增强):
  - pipeline.analysis.evidence_collector.EvidenceCollector — 核心 (必选)
  - pipeline.asr.rank_builder.GroupFallbackExecutor — 核心 (必选)
  - pipeline.analysis.diversity_analyzer.DiversityAnalyzer — 可选 (``--analyze``)
  - pipeline.converters.log.ConverterLogCollector — 可选 (``--analyze``)
  - pipeline.asr.tiered_selection_wizard.TieredSelectionWizard — 可选 (``--analyze``)

修改此文件不影响 Stage 1–4。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 19:30 — 优化4: diversity/converter_log/tiered_wizard 降级为可选
>     ``--analyze`` 标志触发, 默认不执行, 缩短流水线执行时间
>   2026-8-2 00:00 — R-2: HTML 报告迁移到 Jinja2 模板引擎
>     优先使用 Jinja2 渲染, 回退到 f-string (向后兼容)
"""

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from pyrit.output import output_scenario_async, output_scorer_async  # noqa: E402

from pipeline.context import PipelineContext  # noqa: E402

# Windows 文件名非法字符: < > : " / \ | ? *
_FILENAME_SANITIZE_RE = re.compile(r'[<>:"/\\|?*]')


def _sanitize_filename(name: str) -> str:
    """将字符串中 Windows 非法文件名字符替换为下划线。."""
    return _FILENAME_SANITIZE_RE.sub("_", name)


def _has_pdf_support() -> bool:
    """F4: 检测是否安装了 PDF 渲染依赖 (weasyprint 或 xhtml2pdf)."""
    try:
        import weasyprint  # noqa: F401

        return True
    except ImportError:
        pass
    try:
        import xhtml2pdf  # noqa: F401

        return True
    except ImportError:
        pass
    return False


def _is_attack_success(ar: Any) -> bool:
    """判断 AttackResult 是否成功 (仅 SUCCESS 返回 True)。."""
    outcome = getattr(ar, "outcome", None)
    if outcome is None:
        return False
    outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
    return outcome_str == "SUCCESS"


async def run(ctx: PipelineContext) -> None:
    """执行 Stage 6/6: 结果输出 + 增强报告。."""
    print("\n" + "=" * 70)
    print("阶段 6/6: 结果输出 — 证据收集 + 报告生成")
    print("=" * 70)

    result = ctx.result

    # ── 原生: 场景结果汇总 (按 ASR 排序) ──
    print("\n--- 场景结果汇总 (按 ASR 排序) ---")
    await output_scenario_async(
        result,
        sort_groups_by_success_rate=True,
    )

    # ── 原生: 评分器指标 ──
    if ctx.objective_scorer:
        print("\n--- 评分器指标 ---")
        await output_scorer_async(
            scorer_identifier=ctx.objective_scorer.get_identifier(),
        )

    # ── 输出目录 (使用 OutputManager) ──
    output_mgr = ctx.output_manager
    if output_mgr:
        # 证据目录: attacks/ conversations/ scores/ blurred/
        output_dir = output_mgr.evidence_run_dir
    else:
        # Fallback: 旧路径逻辑
        if ctx.args.output_dir:
            output_dir = Path(ctx.args.output_dir)
        else:
            output_dir = Path(f"outputs/{ctx.output_manager.prefix}{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        output_dir.mkdir(parents=True, exist_ok=True)

    # ── 攻击结果 Markdown 报告 (由 EvidenceExporter 统一生成, 不再重复写入) ──
    # L5 对齐: EvidenceExporter 使用 render_async() 生成 4 位编号文件,
    # 此处不再用 output_attack_async + FileSink 重复写入 3 位编号文件。
    total_attacks = sum(len(v) for v in result.attack_results.values()) if result else 0
    print(f"\n--- 攻击结果 Markdown 报告 ({total_attacks} 条, 由 EvidenceExporter 生成) ---")
    print(f"  证据目录: {output_dir}")
    if output_mgr:
        print(f"  报告 (HTML/PDF/MD): {output_mgr.reports_dir}/")
        print(f"  证据目录: {output_dir}/")

    # ── 核心: 证据收集 ──
    _collect_evidence(ctx, output_dir)

    # ── E1 修复: 生成 attacks 日志 (逐攻击 Markdown, 对齐参考目录 logs/XXX_attacks.md) ──
    await _generate_attacks_log(ctx, output_dir)

    # ── 核心: 组级 ASR 降级链报告 ──
    _report_group_fallback(ctx, output_dir)

    # ── 可选: 离线分析 (优化4: ``--analyze`` 标志触发) ──
    if getattr(ctx.args, "analyze", False):
        _analyze_diversity(ctx, output_dir)
        _collect_converter_logs(ctx, output_dir)
        _recommend_tiered_selection(ctx, output_dir)

    # ── P3: L5 报告生成 (ReportGenerator + EvidenceExporter, 回退到手动 section builder) ──
    await _generate_reports(ctx, output_dir)

    ctx.output_dir = output_dir

    # ── 架构汇总: 数据 5 层 + Executor 5 层 ──
    _print_architecture_summary(ctx)

    # ── ASR 总结 ──
    print("\n  ┌─ ASR 总结 ──────────────────────────────────────────────┐")
    print(f"  │ ScenarioResult ID: {result.id}")
    print(f"  │ 总体 ASR: {ctx.overall_asr}%")
    if ctx.asr_per_technique:
        best_technique = max(ctx.asr_per_technique, key=ctx.asr_per_technique.get)
        best_asr = ctx.asr_per_technique[best_technique]
        print(f"  最佳技术: {best_technique} ({best_asr:.1f}%)")
    if output_mgr:
        print(f"  │ 证据目录: {output_dir}")
        print(f"  │ 报告目录: {output_mgr.reports_dir}")
    else:
        print(f"  │ 报告目录: {output_dir}")
    print("  └───────────────────────────────────────────────────────────────┘")

    # ── A3 修复: 报告生成摘要块 (对齐参考日志格式) ──
    l5_report = ctx.metadata.get("l5_report", {})
    if l5_report:
        # F1 修复: 从 ctx.result 提取攻击统计
        total_attacks = sum(len(v) for v in result.attack_results.values()) if result else 0
        success_attacks = sum(
            1 for v in (result.attack_results.values() if result else [])
            for ar in v if ar.outcome and ar.outcome.name == "SUCCESS"
        ) if result else 0
        success_rate = success_attacks / total_attacks * 100 if total_attacks > 0 else 0

        print("\n  ┌─ 报告生成 ──────────────────────────────────────────────┐")
        if l5_report.get("report_path"):
            print(f"  │ 报告路径: {l5_report['report_path']}")
        if l5_report.get("evidence_archive"):
            print(f"  │ 证据包:   {l5_report['evidence_archive']}")
        print(f"  │ 发现漏洞: {l5_report.get('owasp_findings_count', 0)} 个")
        print(f"  │ 攻击总数: {total_attacks}")
        print(f"  │ 成功攻击: {success_attacks}")
        print(f"  │ 成功率:   {success_rate:.1f}%")
        if l5_report.get("report_html_path"):
            print(f"  │ HTML 报告: {l5_report['report_html_path']}")
        if l5_report.get("report_pdf_path"):
            print(f"  │ PDF 报告: {l5_report['report_pdf_path']}")
        print("  └───────────────────────────────────────────────────────────────┘")

    # 列出生成的报告文件
    report_files = sorted(output_dir.glob("*"))
    if report_files:
        print(f"\n  生成的报告文件 ({len(report_files)}):")
        for f in report_files[:20]:
            print(f"    • {f.name}")
        if len(report_files) > 20:
            print(f"    ... 还有 {len(report_files) - 20} 个文件")


# ============================================================
# 增强报告: 攻击多样性分析
# ============================================================


def _analyze_diversity(ctx: PipelineContext, output_dir: Path) -> None:
    """执行攻击多样性分析并保存报告。."""
    print("\n--- 攻击多样性分析 ---")
    try:
        from pipeline.analysis.diversity_analyzer import DiversityAnalyzer

        analyzer = DiversityAnalyzer()

        # 获取可用技术列表
        available_techniques: list[str] = []
        try:
            from pyrit.registry import AttackTechniqueRegistry

            available_techniques = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
        except ImportError:
            pass

        metrics = analyzer.analyze(
            attack_results=ctx.result.attack_results,
            available_techniques=available_techniques or None,
        )

        # 打印报告
        print(analyzer.format_report(metrics))

        # 保存 JSON
        metrics_path = output_dir / "diversity_metrics.json"
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics.to_dict(), f, indent=2, ensure_ascii=False)

        ctx.metadata["diversity_metrics"] = metrics.to_dict()
        print(f"  多样性指标已保存: {metrics_path}")

    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"  [警告] 多样性分析失败: {e}")


# ============================================================
# 增强报告: Converter 转换日志
# ============================================================


def _collect_converter_logs(ctx: PipelineContext, output_dir: Path) -> None:
    """收集 Converter 转换日志并保存报告。."""
    print("\n--- Converter 转换日志 ---")
    try:
        from pipeline.converters.log import ConverterLogCollector

        collector = ConverterLogCollector()
        report = collector.collect(attack_results=ctx.result.attack_results)

        # 打印报告
        print(collector.format_report(report))

        # 保存 JSON
        log_path = output_dir / "converter_log.json"
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        ctx.metadata["converter_log"] = report.to_dict()
        print(f"  Converter 日志已保存: {log_path}")

    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"  [警告] Converter 日志收集失败: {e}")


# ============================================================
# 增强报告: 证据收集
# ============================================================


def _collect_evidence(ctx: PipelineContext, output_dir: Path) -> None:
    """收集结构化漏洞证据并保存。."""
    print("\n--- 证据收集 ---")
    try:
        from pipeline.analysis.evidence_collector import EvidenceCollector

        # 获取模型信息
        model_name = os.getenv("TARGET_MODEL", "unknown")
        model_tier = ctx.metadata.get("model_tier", "unknown")
        owasp_id = os.getenv("OWASP_ID", "")

        collector = EvidenceCollector(
            target_model=model_name,
            model_tier=model_tier,
        )

        collection = collector.collect(
            attack_results=ctx.result.attack_results,
            scenario_result_id=ctx.result.id,
            asr_per_technique=ctx.asr_per_technique,
            overall_asr=ctx.overall_asr,
            owasp_id=owasp_id,
        )

        # 保存 JSON
        json_path = collector.save_json(collection, output_dir=output_dir)

        # 保存 Markdown
        md_path = collector.save_markdown(collection, output_dir=output_dir)

        ctx.metadata["evidence_collection"] = collection.to_dict()
        print(f"  证据数: {len(collection.evidence)}")
        print(f"  JSON: {json_path}")
        print(f"  Markdown: {md_path}")

    except Exception as e:
        print(f"  [警告] 证据收集失败: {e}")


# ============================================================
# E1 修复: attacks 日志生成 (逐攻击 Markdown 合并文件)
# ============================================================


async def _generate_attacks_log(ctx: PipelineContext, output_dir: Path) -> None:
    """生成 attacks 日志 — 将所有攻击结果渲染为 Markdown 并合并写入 logs 目录。.

      对齐参考目录 logs/exam_XXX_attacks.md 格式:
    - 使用 PyRIT 原生 MarkdownAttackResultMemoryPrinter.render_async() 渲染
    - 所有攻击合并到单个 *_attacks.md 文件
    - 文件名: redteam_{timestamp}_attacks.md
    """
    print("\n--- attacks 日志生成 ---")
    try:
        from pyrit.output.attack_result.markdown import MarkdownAttackResultMemoryPrinter

        output_mgr = ctx.output_manager
        if output_mgr:
            attacks_log_path = output_mgr.logs_dir / f"{output_mgr.prefix}{output_mgr.timestamp}_attacks.md"
        else:
            attacks_log_path = output_dir / "attacks.md"

        # 获取所有攻击结果
        all_results: list[Any] = []
        if ctx.result:
            for group_results in ctx.result.attack_results.values():
                all_results.extend(group_results)

        if not all_results:
            print("  (无攻击结果, 跳过 attacks 日志)")
            return

        printer = MarkdownAttackResultMemoryPrinter()
        parts: list[str] = []

        for ar in all_results:
            try:
                content = await printer.render_async(
                    ar,
                    include_auxiliary_scores=True,
                    include_pruned_conversations=True,
                    include_adversarial_conversation=True,
                )
                parts.append(content)
            except Exception as e:
                logger.warning(f"Failed to render attack for log: {e}")

        full_content = "\n\n".join(parts)
        attacks_log_path.write_text(full_content, encoding="utf-8")
        print(f"  attacks 日志: {attacks_log_path} ({len(all_results)} 条)")

    except Exception as e:
        logger.warning(f"Attacks log generation failed: {e}")
        print(f"  [警告] attacks 日志生成失败: {e}")


# ============================================================
# 增强报告: 组级 ASR 降级链
# ============================================================


def _report_group_fallback(ctx: PipelineContext, output_dir: Path) -> None:
    """生成组级 ASR 降级链报告。."""
    print("\n--- 组级 ASR 降级链 ---")
    try:
        from pipeline.asr.rank_builder import GroupFallbackExecutor

        model_name = os.getenv("TARGET_MODEL", "gpt-4o")
        model_tier = ctx.metadata.get("model_tier", "unknown")
        owasp_id = os.getenv("OWASP_ID", "")

        executor = GroupFallbackExecutor(
            model_name=model_name,
            model_tier=model_tier,
            owasp_id=owasp_id,
        )

        # 从 ASR 排行榜获取技术列表
        techniques = list(ctx.asr_per_technique.keys())
        if not techniques:
            print("  (无技术数据, 跳过降级链报告)")
            return

        # 构建降级计划
        historical_asr = {tech: asr / 100.0 for tech, asr in ctx.asr_per_technique.items()}
        plan = executor.build_fallback_plan(
            technique_names=techniques,
            historical_asr=historical_asr,
        )

        # 记录执行结果
        successful = [tech for tech, asr in ctx.asr_per_technique.items() if asr > 0]
        failed = [tech for tech, asr in ctx.asr_per_technique.items() if asr == 0]
        plan = executor.record_execution_outcome(plan, successful, failed)

        # 打印报告
        print(executor.get_fallback_summary(plan))

        # 保存 JSON
        fallback_data = {
            "execution_order": plan.execution_order,
            "fallback_count": plan.fallback_count,
            "successful_groups": plan.successful_groups,
            "failed_groups": plan.failed_groups,
            "total_groups": plan.total_groups,
            "success_rate": plan.success_rate,
            "fallback_records": [
                {
                    "from_group": r.from_group,
                    "to_group": r.to_group,
                    "from_tier": r.from_tier,
                    "to_tier": r.to_tier,
                    "reason": r.reason,
                    "from_asr": r.from_asr,
                    "to_asr": r.to_asr,
                }
                for r in plan.fallback_records
            ],
        }
        fallback_path = output_dir / "group_fallback.json"
        with open(fallback_path, "w", encoding="utf-8") as f:
            json.dump(fallback_data, f, indent=2, ensure_ascii=False)
        print(f"  降级链报告已保存: {fallback_path}")

    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"  [警告] 降级链报告生成失败: {e}")


# ============================================================
# 增强报告: 三层渐进式选择向导
# ============================================================


def _recommend_tiered_selection(ctx: PipelineContext, output_dir: Path) -> None:
    """生成三层渐进式选择推荐。."""
    print("\n--- 三层渐进式选择向导 ---")
    try:
        from pipeline.asr.tiered_selection_wizard import TieredSelectionWizard

        model_name = os.getenv("TARGET_MODEL", "gpt-4o")
        model_tier = ctx.metadata.get("model_tier", "unknown")
        owasp_id = os.getenv("OWASP_ID", "")

        wizard = TieredSelectionWizard(
            model_name=model_name,
            model_tier=model_tier,
        )

        # 获取可用技术
        available_techniques: list[str] = []
        try:
            from pyrit.registry import AttackTechniqueRegistry

            available_techniques = list(AttackTechniqueRegistry.get_registry_singleton().get_factories().keys())
        except ImportError:
            pass

        if not available_techniques:
            print("  (无可用技术, 跳过选择向导)")
            return

        recommendation = wizard.recommend(
            available_techniques=available_techniques,
            owasp_id=owasp_id,
        )

        # 打印推荐
        print(wizard.format_recommendation(recommendation))

        # 保存 JSON
        wizard_path = output_dir / "tiered_recommendation.json"
        with open(wizard_path, "w", encoding="utf-8") as f:
            json.dump(recommendation.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"  选择向导推荐已保存: {wizard_path}")

    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"  [警告] 选择向导推荐失败: {e}")


# ============================================================
# P3: HTML/PDF 报告生成
# ============================================================


# ============================================================
# P2-1: 报告 Section Builders (模板化)
# ============================================================


def _build_report_header(ctx: PipelineContext) -> str:
    """Section 1: 报告概述 + 指标卡片。."""
    parts: list[str] = ["# AI Red Team Assessment Report (Fallback Mode)\n"]
    parts.append(f"> **生成时间**: {datetime.now().isoformat()}\n")
    parts.append("\n<div class='summary-grid'>\n")

    total_results = sum(len(v) for v in ctx.result.attack_results.values()) if ctx.result else 0
    evidence = ctx.metadata.get("evidence_collection", {})
    success_count = evidence.get("successful_attacks", 0) if evidence else 0
    evidence_count = len(evidence.get("evidence", [])) if evidence else 0

    for value, label in [
        (f"{ctx.overall_asr}%", "总体 ASR"),
        (str(total_results), "攻击总数"),
        (str(success_count), "成功攻击"),
        (str(evidence_count), "漏洞证据"),
    ]:
        parts.append(f"<div class='metric-box'><span class='metric-value'>{value}</span>"
                      f"<span class='metric-label'>{label}</span></div>\n")
    parts.append("</div>\n")

    parts.append(f"\n**ScenarioResult ID**: `{ctx.result.id}`\n")
    model_name = ctx.metadata.get("model_name", os.getenv("TARGET_MODEL", "unknown"))
    model_tier = ctx.metadata.get("model_tier", "unknown")
    parts.append(f"**目标模型**: {model_name} (tier={model_tier})\n")
    if ctx.target_type:
        parts.append(f"**Target 类型**: `{ctx.target_type}`\n")
    return "\n".join(parts)


def _build_data_layer_section(ctx: PipelineContext) -> str:
    """Section 1.5: 数据 5 层架构决策汇总.

    展示 L1→L5 各层的关键决策结果, 确保架构决策可审计、可追溯.
    """
    parts: list[str] = ["\n## 数据 5 层架构决策\n"]

    # L1: Seed Source
    parts.append("### L1 — Seed Source\n")
    parts.append(f"- 数据集数量: {len(ctx.sorted_datasets)}\n")
    if ctx.args and ctx.args.datasets:
        parts.append(f"- 远程数据集: {', '.join(ctx.args.datasets)}\n")
    if ctx.args and ctx.args.local_datasets:
        parts.append(f"- 本地数据集: {len(ctx.args.local_datasets)} 个\n")
    if ctx.gcg_seeds_count > 0:
        parts.append(f"- GCG 生成种子: {ctx.gcg_seeds_count} 组\n")
    if ctx.fuzzer_seeds_count > 0:
        parts.append(f"- Fuzzer 变异种子: {ctx.fuzzer_seeds_count} 组\n")
    parts.append("\n")

    # L2: Seed Organization
    parts.append("### L2 — Seed Organization\n")
    if ctx.warm_start_asr:
        parts.append(f"- 富元数据覆盖: {len(ctx.warm_start_asr)} 个技术有 ASR 基线\n")
        top5 = sorted(ctx.warm_start_asr.items(), key=lambda x: x[1], reverse=True)[:5]
        parts.append("\n| 技术 | ASR 先验 |\n|---|---|\n")
        for tech, asr in top5:
            parts.append(f"| {tech} | {asr:.0%} |\n")
        parts.append("\n")
    else:
        parts.append("- 富元数据: (无 warm-start 先验)\n\n")

    # L3: Dataset Config
    parts.append("### L3 — Dataset Config\n")
    parts.append(f"- 数据集数: {len(ctx.sorted_datasets)}\n")
    if ctx.args:
        parts.append(f"- Per-dataset 预算: {getattr(ctx.args, 'max_dataset_size', 'N/A')}\n")
    parts.append("- 排序策略: ASR 降序 (高优先级数据集优先)\n")
    parts.append(f"- 数据集列表: {', '.join(ctx.sorted_datasets[:10])}\n")
    if len(ctx.sorted_datasets) > 10:
        parts.append(f"  ... 还有 {len(ctx.sorted_datasets) - 10} 个\n")
    parts.append("\n")

    # L4: Memory Persistence
    parts.append("### L4 — Memory Persistence\n")
    parts.append(f"- Memory 类型: {ctx.config.memory_db_type if ctx.config else 'N/A'}\n")
    if ctx.result:
        parts.append(f"- ScenarioResult ID: `{ctx.result.id}`\n")
    parts.append("- Memory Labels: run_date + pipeline_version + selector_scope + asr_driven\n")
    parts.append("\n")

    # L5: Analytics & Select
    parts.append("### L5 — Analytics & Select\n")
    if ctx.args:
        parts.append(f"- EpsilonGreedy: epsilon={getattr(ctx.args, 'epsilon', 'N/A')}, "
                      f"scope={getattr(ctx.args, 'selector_scope', 'N/A')}\n")
    if ctx.warm_start_asr:
        parts.append(f"- Warm-start: {len(ctx.warm_start_asr)} 个技术先验注入\n")
    fallback_plan = getattr(ctx, "fallback_plan", None)
    if fallback_plan and hasattr(fallback_plan, "total_groups"):
        parts.append(f"- Tier 降级链: {fallback_plan.total_groups} 组, "
                      f"{fallback_plan.fallback_count} 个降级点\n")
    if ctx.asr_per_technique:
        parts.append(f"- 实测 ASR 统计: {len(ctx.asr_per_technique)} 个技术\n")
        best_tech = max(ctx.asr_per_technique, key=ctx.asr_per_technique.get)
        parts.append(f"- 实测最佳技术: {best_tech} ({ctx.asr_per_technique[best_tech]:.1f}%)\n")
    parts.append("\n")

    return "\n".join(parts)


def _build_asr_matrix(ctx: PipelineContext) -> str:
    """Section 2: ASR 矩阵 + 技术成功率详情。."""
    if not ctx.asr_per_technique:
        return ""
    evidence = ctx.metadata.get("evidence_collection", {})
    parts: list[str] = ["\n## ASR 矩阵 (Attack Success Rate)\n"]
    parts.append("\n| 技术 | ASR | 可视化 | 等级 |\n|---|---|---|---|\n")
    for tech, asr in sorted(ctx.asr_per_technique.items(), key=lambda x: x[1], reverse=True):
        bar_width = int(asr / 5) * 5
        if asr >= 40:
            bar_class, level = "asr-bar-high", "<span class='asr-high'>高</span>"
        elif asr >= 15:
            bar_class, level = "asr-bar-medium", "<span class='asr-medium'>中</span>"
        elif asr > 0:
            bar_class, level = "asr-bar-low", "<span class='asr-low'>低</span>"
        else:
            bar_class, level = "", "—"
        bar_html = f"<span class='asr-bar {bar_class}' style='width:{bar_width}px;'></span>" if bar_class else ""
        parts.append(f"| {tech} | {asr:.1f}% | {bar_html} | {level} |\n")

    if evidence and evidence.get("failure_analysis"):
        tech_rates = evidence["failure_analysis"].get("technique_success_rates", [])
        if tech_rates:
            parts.append("\n### 技术成功率详情\n")
            parts.append("\n| 技术 | 成功 | 失败 | 总计 | 成功率 |\n|---|---|---|---|---|\n")
            for tr in tech_rates:
                sr = tr.get("success_rate", 0)
                sr_class = ("asr-cell-high" if sr >= 40 else "asr-cell-medium" if sr >= 15
                            else "asr-cell-low" if sr > 0 else "asr-cell-zero")
                parts.append(f"| {tr.get('technique', 'N/A')} | {tr.get('successes', 0)} | "
                             f"{tr.get('failures', 0)} | {tr.get('total', 0)} | "
                             f"<span class='asr-cell {sr_class}'>{sr:.1f}%</span> |\n")
    return "\n".join(parts)


def _build_owasp_mapping(ctx: PipelineContext, evidence: dict) -> str:
    """Section 3: OWASP 映射。."""
    from pipeline.analysis.evidence_collector import get_owasp_category

    parts: list[str] = []
    if evidence and evidence.get("owasp_coverage"):
        parts.append("\n## OWASP 分类映射\n")
        parts.append("\n| OWASP ID | 分类名称 | 证据数 | 覆盖 |\n|---|---|---|---|\n")
        for owasp_id, count in sorted(evidence["owasp_coverage"].items()):
            category = get_owasp_category(owasp_id)
            badge_class = "owasp-asi" if owasp_id.startswith("ASI") else "owasp-llm"
            badge = f"<span class='owasp-badge {badge_class}'>{owasp_id}</span>"
            parts.append(f"| {badge} | {category} | {count} | ✅ |\n")
    elif os.getenv("OWASP_ID"):
        owasp_id = os.getenv("OWASP_ID", "")
        category = get_owasp_category(owasp_id)
        badge_class = "owasp-asi" if owasp_id.startswith("ASI") else "owasp-llm"
        badge = f"<span class='owasp-badge {badge_class}'>{owasp_id}</span>"
        parts.append("\n## OWASP 分类映射\n")
        parts.append(f"\n| OWASP ID | 分类名称 |\n|---|---|\n| {badge} | {category} |\n")
    return "\n".join(parts)


def _build_evidence_section(ctx: PipelineContext, evidence: dict) -> str:
    """Section 4: 完整攻击证据。."""
    if not (evidence and evidence.get("evidence")):
        return ""
    parts: list[str] = ["\n## 完整攻击证据\n", f"> 共 {len(evidence['evidence'])} 条漏洞证据\n"]
    for i, ev in enumerate(evidence["evidence"], 1):
        parts.append(_build_single_evidence(i, ev))
    return "\n".join(parts)


def _build_single_evidence(idx: int, ev: dict) -> str:
    """构建单条漏洞证据的 Markdown (R-2: 优先使用 Jinja2 模板, 回退到 f-string)。."""
    try:
        # R-2: 优先使用 Jinja2 模板渲染
        from pipeline.reporting.template_renderer import get_renderer

        renderer = get_renderer()
        if renderer.has_jinja2():
            return renderer.render_sync("evidence_card.html", idx=idx, ev=ev)
    except ImportError as e:
        logger.debug(f"Jinja2 模板渲染失败, 回退到 f-string: {e}")

    # 回退: 使用原有的 f-string 逻辑 (向后兼容)
    ev_id = ev.get("evidence_id", f"EVD-{idx:04d}")
    tech_display = ev.get("technique_display_name", ev.get("technique_name", "N/A"))
    asr_val = ev.get("asr", 0)
    confidence = ev.get("confidence", "medium")
    converter_chain = ev.get("converter_chain", "")
    owasp_id = ev.get("owasp_id", "")
    arxiv_ref = ev.get("arxiv_reference", "")

    p: list[str] = [f"\n### 证据 #{idx}: `{ev_id}`\n", "<div class='evidence-card vulnerability'>\n"]
    p.append(f"**攻击技术**: {tech_display}\n\n")
    if converter_chain:
        p.append(f"**Converter 链**: `{converter_chain}`\n\n")
    if owasp_id:
        badge_class = "owasp-asi" if owasp_id.startswith("ASI") else "owasp-llm"
        p.append(f"**OWASP**: <span class='owasp-badge {badge_class}'>{owasp_id}</span> "
                 f"{ev.get('owasp_category', '')}\n\n")
    asr_class = "asr-high" if asr_val >= 40 else ("asr-medium" if asr_val >= 15 else "asr-low")
    p.append(f"**ASR**: <span class='{asr_class}'>{asr_val:.1f}%</span>\n\n")
    p.append(f"**置信度**: {confidence}\n\n")
    if arxiv_ref:
        p.append(f"**学术引用**: {arxiv_ref}\n\n")
    objective = ev.get("objective", "")
    if objective:
        p.append(f"**攻击目标**: {str(objective)[:300]}\n\n")

    # 攻击链路
    attack_chain = ev.get("attack_chain", [])
    if attack_chain:
        p.append("#### 攻击链路 (Attack Chain)\n\n<ul class='attack-chain'>\n")
        for step in attack_chain:
            outcome = step.get("outcome", "").upper()
            step_class = "success" if outcome == "SUCCESS" else "failure"
            reason_str = f" — {step.get('failure_reason', '')}" if step.get("failure_reason") else ""
            p.append(f"<li class='{step_class}'><strong>步骤 {step.get('step', '')}</strong>: "
                     f"{step.get('technique', '')} → {outcome} ({step.get('role', '')}){reason_str}</li>\n")
        p.append("</ul>\n\n")

    # Converter 日志
    conv_log = ev.get("converter_log", [])
    if conv_log:
        p.append("#### Converter 转换日志\n\n")
        for cl in conv_log:
            step, role = cl.get("step", ""), cl.get("role", "")
            original = cl.get("original", "")
            if cl.get("transformed", "false") == "true":
                converted = cl.get("converted", "")
                p.append(f"<div class='converter-entry'><strong>步骤 {step}</strong> ({role})<br>"
                         f"原始: <code>{original[:200]}</code><br>"
                         f"<span class='arrow'>→</span> 变换: <code>{converted[:200]}</code></div>\n")
            else:
                p.append(f"<div class='converter-entry'><strong>步骤 {step}</strong> ({role}) — "
                         f"<code>{original[:200]}</code></div>\n")
        p.append("\n")

    jailbreak = ev.get("jailbreak_prompt", "")
    if jailbreak:
        p.append(f"#### 越狱载荷 (Jailbreak Prompt)\n\n```\n{jailbreak[:1000]}\n```\n\n")
    harmful = ev.get("harmful_output", "")
    if harmful:
        p.append(f"#### 目标模型响应 (Harmful Output)\n\n```\n{harmful[:1000]}\n```\n\n")
    p.append("</div>\n")
    return "\n".join(p)


def _build_failure_analysis(ctx: PipelineContext, evidence: dict) -> str:
    """Section 5: 失败分析。."""
    if not (evidence and evidence.get("failure_analysis")):
        return ""
    fa = evidence["failure_analysis"]
    parts: list[str] = ["\n## 失败分析\n",
                        f"- 总攻击: {fa.get('total_attacks', 0)}\n",
                        f"- 成功: {fa.get('total_successes', 0)}\n",
                        f"- 失败: {fa.get('total_failures', 0)}\n\n"]
    ftype_dist = fa.get("failure_type_distribution", {})
    if ftype_dist:
        parts.append("### 失败类型分布\n\n| 失败类型 | 次数 |\n|---|---|\n")
        for ftype, count in sorted(ftype_dist.items(), key=lambda x: x[1], reverse=True):
            parts.append(f"| {ftype} | {count} |\n")
        parts.append("\n")
    return "\n".join(parts)


def _build_asr_trend(ctx: PipelineContext, evidence: dict) -> str:
    """Section 6: ASR 趋势。."""
    if not (evidence and evidence.get("asr_trend")):
        return ""
    parts: list[str] = ["\n## ASR 趋势 (跨运行历史)\n\n", "| 技术 | 历史 ASR | 数据来源 |\n|---|---|---|\n"]
    for item in evidence["asr_trend"]:
        parts.append(f"| {item.get('technique', 'N/A')} | {item.get('historical_asr', 0):.1f}% | "
                     f"{item.get('source', 'N/A')} |\n")
    parts.append("\n")
    return "\n".join(parts)


def _build_diversity_section(ctx: PipelineContext) -> str:
    """Section 7: 多样性分析。."""
    diversity = ctx.metadata.get("diversity_metrics")
    if not diversity:
        return ""
    return (f"\n## 攻击多样性分析\n\n"
            f"- Shannon 熵: {diversity.get('technique_entropy', 0):.3f}\n"
            f"- 技术覆盖度: {diversity.get('technique_coverage', 0):.1%}\n"
            f"- 范式覆盖度: {diversity.get('paradigm_coverage', 0):.1%}\n")


def _build_converter_stats(ctx: PipelineContext) -> str:
    """Section 8: Converter 路由统计。."""
    converter_log = ctx.metadata.get("converter_log")
    if not converter_log:
        return ""
    parts: list[str] = ["\n## Converter 路由统计\n\n",
                        "| Converter 链 | 使用次数 | 成功 | 失败 | ASR |\n|---|---|---|---|---|\n"]
    for name, stats in sorted(converter_log.get("chain_stats", {}).items(),
                              key=lambda x: x[1].get("success_rate", 0), reverse=True):
        sr = stats.get("success_rate", 0)
        sr_class = ("asr-cell-high" if sr >= 0.4 else "asr-cell-medium" if sr >= 0.15
                    else "asr-cell-low" if sr > 0 else "asr-cell-zero")
        parts.append(f"| {name} | {stats.get('total_uses', 0)} | {stats.get('successes', 0)} | "
                     f"{stats.get('failures', 0)} | <span class='asr-cell {sr_class}'>{sr:.1%}</span> |\n")
    return "\n".join(parts)


def _build_fallback_chain(ctx: PipelineContext) -> str:
    """Section 9: 降级链报告。."""
    fallback_plan = getattr(ctx, "fallback_plan", None)
    if not (fallback_plan and hasattr(fallback_plan, "execution_order")):
        return ""
    parts: list[str] = ["\n## ASR Tier 降级链\n\n",
                        f"- 总组数: {fallback_plan.total_groups}\n",
                        f"- 降级点: {fallback_plan.fallback_count}\n",
                        f"- 成功率: {fallback_plan.success_rate:.1%}\n\n",
                        "| 执行顺序 | 技术 | Tier |\n|---|---|---|\n"]
    for idx, tech in enumerate(fallback_plan.execution_order):
        parts.append(f"| {idx + 1} | {tech} | — |\n")
    parts.append("\n")
    return "\n".join(parts)


async def _generate_reports(ctx: PipelineContext, output_dir: Path) -> None:
    """L5 报告生成.

    优先使用 ReportGenerator (三级证据链 + OWASP 矩阵 + ZIP 证据包),
    回退到手动 section builder (向后兼容).

    L5 对齐 pyrit_ai300/src/reporting/report_generator.py:
      - 使用 ``except Exception`` 宽口径捕获, 确保任何异常都不中断流水线
      - 使用 ``logger.exception`` 记录完整 traceback, 便于定位根因
    """
    print("\n--- L5 报告生成 ---")
    try:
        await _generate_l5_report(ctx, output_dir)
    except Exception as e:
        logger.exception(f"ReportGenerator failed, falling back to manual section builder: {e}")
        print(f"  [提示] ReportGenerator 降级到手动 section builder: {type(e).__name__}: {e}")
        _generate_html_pdf_reports(ctx, output_dir)


async def _generate_l5_report(ctx: PipelineContext, output_dir: Path) -> None:
    """使用 ReportGenerator 生成 L5 级别的完整报告.

    集成:
    - ReportGenerator: 三级证据链 (Finding→AttackResult→Conversation) + OWASP 覆盖矩阵
      + 攻击时间线 + Converter 变换日志 + Shannon 熵多样性分析
    - EvidenceExporter: PyRIT 原生 render_async() + evidence.json + CSV 导出 + ZIP 打包

    即使未指定 --html-report / --pdf-report, 仍生成 Markdown 报告和 ZIP 证据包.
    """
    from pipeline.reporting.report_generator import ReportGenerator

    # L5 对齐: 记录结束时间, 传递评估时间范围给报告生成器
    if ctx.end_time is None:
        ctx.end_time = datetime.now()
    start_time = ctx.start_time or datetime.now()
    end_time = ctx.end_time

    generator = ReportGenerator()
    report_output_dir = ctx.output_manager.reports_dir if ctx.output_manager else output_dir
    evidence_dir = ctx.output_manager.evidence_run_dir if ctx.output_manager else output_dir

    # 使用 redteam_{timestamp}_report 格式作为报告基础名
    if ctx.output_manager:
        report_base_name = f"{ctx.output_manager.prefix}{ctx.output_manager.timestamp}_report"
    else:
        report_base_name = f"{os.getenv('OUTPUT_PREFIX', 'redteam_')}{datetime.now().strftime('%Y%m%d_%H%M%S')}_report"

    report_result = await generator.generate_report(
        scenario_result=ctx.result,
        output_dir=report_output_dir,
        evidence_dir=evidence_dir,
        generate_html=True,  # D1 修复: 默认生成 HTML 报告 (对齐参考目录)
        generate_pdf=getattr(ctx.args, "pdf_report", False),  # 默认不生成 PDF (格式丑陋), 仅 --pdf-report 显式开启
        title="AI Red Team Report",
        start_time=start_time,
        end_time=end_time,
        report_base_name=report_base_name,
    )

    print(f"  Markdown 报告: {report_result.report_path}")
    if report_result.report_html_path:
        print(f"  HTML 报告: {report_result.report_html_path}")
    if report_result.report_pdf_path:
        print(f"  PDF 报告: {report_result.report_pdf_path}")
    if report_result.evidence_archive:
        print(f"  证据包 (ZIP): {report_result.evidence_archive}")
    print(f"  OWASP 发现: {len(report_result.owasp_findings)} 个")

    ctx.metadata["l5_report"] = {
        "report_path": report_result.report_path,
        "report_html_path": report_result.report_html_path,
        "report_pdf_path": report_result.report_pdf_path,
        "evidence_archive": report_result.evidence_archive,
        "owasp_findings_count": len(report_result.owasp_findings),
    }


def _generate_html_pdf_reports(ctx: PipelineContext, output_dir: Path) -> None:
    """生成 HTML/PDF 格式报告 (P2-1: 模板化重构, 回退方案).

    当 ReportGenerator 不可用时使用此函数生成报告.
    """
    # L5 对齐: 即使未指定 --html-report / --pdf-report, 也生成 Markdown 报告 (降级回退时)
    generate_html = getattr(ctx.args, "html_report", False)
    generate_pdf = getattr(ctx.args, "pdf_report", False)
    if not generate_html and not generate_pdf:
        generate_html = True  # 降级时强制生成 HTML

    print("\n--- HTML/PDF 报告生成 (完整证据 + OWASP + 三级证据链) ---")
    try:
        from pipeline.reporting.format_converter import convert_report_formats

        evidence = ctx.metadata.get("evidence_collection", {})
        sections: list[str] = []

        sections.append(_build_report_header(ctx))
        sections.append(_build_data_layer_section(ctx))
        sections.append(_build_asr_matrix(ctx))
        sections.append(_build_owasp_mapping(ctx, evidence))
        sections.append(_build_evidence_section(ctx, evidence))
        sections.append(_build_failure_analysis(ctx, evidence))
        sections.append(_build_asr_trend(ctx, evidence))
        sections.append(_build_diversity_section(ctx))
        sections.append(_build_converter_stats(ctx))
        sections.append(_build_fallback_chain(ctx))

        markdown_content = "\n".join(s for s in sections if s)

        # 使用 OutputManager 的报告目录 (如果有)
        report_output_dir = ctx.output_manager.reports_dir if ctx.output_manager else output_dir
        report_output_dir.mkdir(parents=True, exist_ok=True)

        # G8 修复: 使用 redteam_{timestamp}_report 格式 (对齐 L5)
        if ctx.output_manager:
            report_base_name = f"{ctx.output_manager.prefix}{ctx.output_manager.timestamp}_report"
        else:
            report_base_name = (
                f"{os.getenv('OUTPUT_PREFIX', 'redteam_')}"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_report"
            )

        # 使用 format_converter 直接转换 Markdown → HTML/PDF
        result = convert_report_formats(
            markdown_content,
            report_output_dir / report_base_name,
            generate_html=generate_html,
            generate_pdf=generate_pdf,
            title="AI Red Team Report",
        )

        # 同时保存 Markdown
        (report_output_dir / f"{report_base_name}.md").write_text(markdown_content, encoding="utf-8")

        if result.get("html"):
            print(f"  HTML 报告: {result['html']}")
        if result.get("pdf"):
            print(f"  PDF 报告: {result['pdf']}")
        if not result.get("html") and not result.get("pdf"):
            print("  [提示] 安装 weasyprint 或 xhtml2pdf 以生成 PDF")

    except Exception as e:
        print(f"  [警告] HTML/PDF 报告生成失败: {e}")


# ============================================================
# 架构汇总: 数据 5 层 + Executor 5 层
# ============================================================


def _print_architecture_summary(ctx: PipelineContext) -> None:
    """打印数据 5 层 + Executor 5 层架构的全景汇总。."""
    print("\n" + "=" * 70)
    print("架构汇总 — 数据 5 层 + Executor 5 层")
    print("=" * 70)

    # ── 数据 5 层架构 (L5: 逐层决策详情) ──
    print("\n  ── 数据 5 层架构 (L1→L5) ──")

    # L1: Seed Source
    seed_sources = []
    if ctx.args and ctx.args.datasets:
        seed_sources.append(f"{len(ctx.args.datasets)} 远程")
    if ctx.args and ctx.args.local_datasets:
        seed_sources.append(f"{len(ctx.args.local_datasets)} 本地")
    if ctx.gcg_seeds_count > 0:
        seed_sources.append(f"{ctx.gcg_seeds_count} GCG")
    if ctx.fuzzer_seeds_count > 0:
        seed_sources.append(f"{ctx.fuzzer_seeds_count} Fuzzer")
    print(f"    L1 (Seed Source): {' + '.join(seed_sources) if seed_sources else '(无)'}")
    # L1 决策: per-dataset seed count + OWASP coverage
    for ds_name in ctx.sorted_datasets[:5]:
        print(f"      • {ds_name}")
    if len(ctx.sorted_datasets) > 5:
        print(f"      ... 还有 {len(ctx.sorted_datasets) - 5} 个数据集")

    # L2: Seed Organization
    print("    L2 (Seed Organization): AttackSeedGroup (Stage 1→2)")
    # L2 决策: 富元数据覆盖 + warm-start 先验数
    if ctx.warm_start_asr:
        print(f"      富元数据: {len(ctx.warm_start_asr)} 个技术有 ASR 基线")
        top3 = sorted(ctx.warm_start_asr.items(), key=lambda x: x[1], reverse=True)[:3]
        top_str = " | ".join(f"{t}({v:.0%})" for t, v in top3)
        print(f"      Top 3 先验: {top_str}")

    # L3: Dataset Config
    print(f"    L3 (Dataset Config): CompoundDatasetAttackConfiguration ({len(ctx.sorted_datasets)} datasets)")
    # L3 决策: per-dataset budget
    if ctx.args:
        print(f"      Per-dataset 预算: {getattr(ctx.args, 'max_dataset_size', 'N/A')}"  )
        print("      排序: ASR 降序 (高优先级数据集优先)")

    # L4: Memory Persistence
    print(f"    L4 (Memory Persistence): {ctx.config.memory_db_type if ctx.config else 'N/A'} (CentralMemory)")
    # L4 决策: DB path + ScenarioResult ID
    if ctx.result:
        print(f"      ScenarioResult ID: {ctx.result.id}")
    if ctx.config:
        print("      Memory labels: run_date + pipeline_version + selector_scope")

    # L5: Analytics & Select
    asr_count = len(ctx.asr_per_technique)
    print(f"    L5 (Analytics & Select): EpsilonGreedy + ASR ({asr_count} 技术统计)")
    # L5 决策: Tier 分布 + dynamic alpha
    fallback_plan = getattr(ctx, "fallback_plan", None)
    if fallback_plan and hasattr(fallback_plan, "total_groups"):
        print(f"      Tier 降级链: {fallback_plan.total_groups} 组, {fallback_plan.fallback_count} 个降级点")
    if ctx.warm_start_asr:
        print(f"      Warm-start: {len(ctx.warm_start_asr)} 技术先验 → 动态 alpha 融合")
    if ctx.asr_per_technique:
        best_tech = max(ctx.asr_per_technique, key=ctx.asr_per_technique.get)
        print(f"      实测最佳: {best_tech} ({ctx.asr_per_technique[best_tech]:.1f}%)")

    # ── Executor 5 层架构 ──
    print("\n  ── Executor 5 层架构 (L1→L5) ──")
    print(
        f"    L1 (Attack Parameters): max_attempts={ctx.max_attempts_per_objective}, "
        f"max_concurrency={ctx.args.max_concurrency if ctx.args else 'N/A'}"
    )
    print(f"    L2 (Attack Strategy): {ctx.scenario_name}")
    print(
        f"    L3 (Attack Config): converter_routing={ctx.converter_routing_count}, "
        f"baseline={'on' if not getattr(ctx.args, 'no_baseline', False) else 'off'}"
    )
    atomic_count = ctx.scenario.atomic_attack_count if ctx.scenario else 0
    total_results = sum(len(v) for v in ctx.result.attack_results.values()) if ctx.result else 0
    strategy = "EXHAUSTIVE" if ctx.max_attempts_per_objective >= 999 else "FIRST_SUCCESS"
    print(f"    L4 (Compound Attack): {atomic_count} AtomicAttack → {total_results} AttackResult ({strategy})")
    print(f"    L5 (Scenario): {type(ctx.scenario).__name__ if ctx.scenario else 'N/A'}")

    # ── 阶段间数据流 ──
    print("\n  ── 阶段间数据流 (Stage 1→6) ──")
    print("    Stage 1 → 2: Registry 初始化 + 种子生成 + 多模态检测")
    print("    Stage 2 → 3: 场景配置 + 参数注入 + Converter 路由")
    print("    Stage 3 → 4: AtomicAttack 构建 + ASR 智能调度")
    print("    Stage 4 → 5: ScenarioResult + ASR 统计 + 失败类型分布")
    print("    Stage 5 → 6: ASR 分析 + 经验写回 + 建议生成")
    print("    Stage 6    : 报告生成 + 证据收集 + 架构汇总")

    # ── 关键决策点 ──
    print("\n  ── 关键决策点 ──")
    if ctx.gcg_seeds_count > 0:
        print(f"    • GCG 对抗后缀: {ctx.gcg_seeds_count} 组种子注入")
    if ctx.fuzzer_seeds_count > 0:
        print(f"    • Fuzzer MCTS: {ctx.fuzzer_seeds_count} 组种子注入")
    if ctx.is_multimodal:
        print(f"    • 多模态: {len(ctx.multimodal_converters)} 个 Converter 预设")
    if ctx.rate_limited:
        print("    • 限速包装: 已启用")
    if ctx.http_target_configured:
        print("    • HTTP Target: 已配置")
    if ctx.warm_start_asr:
        print(f"    • Warm-start ASR: {len(ctx.warm_start_asr)} 个技术先验")
    if ctx.converter_routing_count > 0:
        print(f"    • Converter 路由: {ctx.converter_routing_count} 个分配")
    print(f"    • 停止策略: {strategy}")
    print(f"    • 场景类型: {ctx.scenario_name}")
