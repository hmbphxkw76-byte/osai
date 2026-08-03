# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 5: 结果输出.

职责:
  - 使用 PyRIT 原生 output_attack_async 输出 Markdown 报告
  - 可选: 桥接到主 pipeline 的证据收集和报告体系 (仅 Browser 模式)

双模式支持:
  Browser 模式: 完整报告 + G-09 桥接
  API 模式: 独立报告 (无 G-09 桥接, 因为无 profile)

产出 (写入 WebRedTeamContext):
  - ctx.output_dir = 报告输出目录

依赖的原生 API:
  - pyrit.output.output_attack_async
  - pyrit.output.FileSink
"""

import logging
from datetime import datetime
from pathlib import Path

from web_redteam.pipeline.context import WebRedTeamContext

logger = logging.getLogger(__name__)


async def run(ctx: WebRedTeamContext) -> None:
    """执行 Stage 5: 结果输出。."""
    logger.info("=" * 70)
    logger.info("[Stage 5] 结果输出")
    logger.info("=" * 70)

    from pyrit.output import FileSink, output_attack_async

    # 确定输出目录
    output_dir_str = getattr(ctx.args, "output_dir", None)
    if output_dir_str:
        output_dir = Path(output_dir_str)
    else:
        if ctx.api_mode:
            target_name = ctx.api_config.model_name if ctx.api_config else "api_target"
        else:
            target_name = ctx.profile.target.name if ctx.profile else "unknown"
        output_dir = Path(f"outputs/web_redteam_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    output_dir.mkdir(parents=True, exist_ok=True)

    result = ctx.result
    if result is None:
        logger.warning("  无攻击结果可输出")
        return

    # 输出 Markdown 报告 (原生 API)
    md_path = output_dir / "attack_report.md"
    try:
        await output_attack_async(
            result,
            format="markdown",
            include_auxiliary_scores=True,
            include_adversarial_conversation=True,
            sink=FileSink(path=md_path),
        )
        logger.info(f"  Markdown 报告: {md_path}")
    except Exception as e:
        logger.error(f"输出 Markdown 报告失败: {e}")
        # Fallback: 简单文本输出
        txt_path = output_dir / "attack_result.txt"
        txt_path.write_text(str(result), encoding="utf-8")
        logger.info(f"  文本结果 (fallback): {txt_path}")

    ctx.output_dir = output_dir

    # G-09: 桥接到主 pipeline 的证据收集和报告体系 (仅 Browser 模式)
    if not ctx.api_mode:
        try:
            from pipeline.integrations.web_redteam import (
                collect_web_redteam_evidence,
                create_shared_output_manager,
                generate_web_redteam_report,
            )

            shared_mgr = create_shared_output_manager(
                timestamp=datetime.now().strftime("%Y%m%d_%H%M%S"),
            )
            target_name = ctx.profile.target.name if ctx.profile else "unknown"

            evidence = collect_web_redteam_evidence(
                ctx,
                shared_mgr,
                model_name=f"web_{target_name}",
            )
            if evidence:
                report_path = generate_web_redteam_report(ctx, shared_mgr, evidence=evidence)
                if report_path:
                    logger.info(f"  [G-09] 主 pipeline 报告: {report_path}")
                    logger.info(f"G-09 bridge: report saved to {report_path}")
        except (ImportError, OSError, ValueError) as e:
            logger.debug(f"G-09 bridge skipped: {e}")
            logger.debug(f"  [提示] 主 pipeline 集成跳过: {e}")
    else:
        # API 模式: 输出独立的 JSON 摘要
        _save_api_summary(ctx, output_dir)

    logger.info("=" * 70)
    logger.info("端到端流程完成")
    logger.info("=" * 70)
    logger.info(f"  报告目录: {output_dir}")

    logger.info(f"Stage 5: output saved to {output_dir}")


def _save_api_summary(ctx: WebRedTeamContext, output_dir: Path) -> None:
    """API 模式: 保存攻击摘要 JSON。."""
    import json

    summary: dict[str, object] = {
        "mode": "api",
        "timestamp": datetime.now().isoformat(),
        "target_url": ctx.api_config.url if ctx.api_config else "unknown",
        "model_name": ctx.api_config.model_name if ctx.api_config else "unknown",
        "max_rpm": ctx.api_config.max_rpm if ctx.api_config else None,
        "max_concurrency": ctx.api_config.max_concurrency if ctx.api_config else 3,
        "attack_type": getattr(ctx.args, "attack_type", "prompt_sending"),
        "objective": getattr(ctx.args, "objective", ""),
        "recon_data": "loaded" if ctx.recon_result else "none",
    }

    # 尝试提取攻击结果统计
    if ctx.result is not None:
        attack_results = getattr(ctx.result, "attack_results", None)
        if attack_results:
            if isinstance(attack_results, dict):
                total = sum(len(v) for v in attack_results.values())
                summary["total_attacks"] = total
                summary["attack_categories"] = list(attack_results.keys())
            elif isinstance(attack_results, list):
                summary["total_attacks"] = len(attack_results)

    summary_path = output_dir / "api_attack_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, default=str)

    logger.info(f"  API 摘要: {summary_path}")
