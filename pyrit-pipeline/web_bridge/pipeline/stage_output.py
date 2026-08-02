# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 5: 结果输出。.

职责:
  - 使用 PyRIT 原生 output_attack_async 输出 Markdown 报告
  - 可选: 输出场景级汇总

产出 (写入 WebBridgeContext):
  - ctx.output_dir = 报告输出目录

依赖的原生 API:
  - pyrit.output.output_attack_async
  - pyrit.output.FileSink
"""

import logging
from datetime import datetime
from pathlib import Path

from web_bridge.pipeline.context import WebBridgeContext

logger = logging.getLogger(__name__)


async def run(ctx: WebBridgeContext) -> None:
    """执行 Stage 5: 结果输出。."""
    print("\n" + "=" * 70)
    print("[Stage 5] 结果输出")
    print("=" * 70)

    from pyrit.output import FileSink, output_attack_async

    # 确定输出目录
    output_dir_str = getattr(ctx.args, "output_dir", None)
    if output_dir_str:
        output_dir = Path(output_dir_str)
    else:
        target_name = ctx.profile.target.name if ctx.profile else "unknown"
        output_dir = Path(f"outputs/web_bridge_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    output_dir.mkdir(parents=True, exist_ok=True)

    result = ctx.result
    if result is None:
        print("  无攻击结果可输出")
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
        print(f"  Markdown 报告: {md_path}")
    except Exception as e:
        logger.error(f"输出 Markdown 报告失败: {e}")
        # Fallback: 简单文本输出
        txt_path = output_dir / "attack_result.txt"
        txt_path.write_text(str(result), encoding="utf-8")
        print(f"  文本结果 (fallback): {txt_path}")

    ctx.output_dir = output_dir

    # G-09: 桥接到主 pipeline 的证据收集和报告体系
    try:
        from pipeline.integrations.web_bridge import (
            collect_web_bridge_evidence,
            create_shared_output_manager,
            generate_web_bridge_report,
        )

        shared_mgr = create_shared_output_manager(
            timestamp=datetime.now().strftime("%Y%m%d_%H%M%S"),
        )
        target_name = ctx.profile.target.name if ctx.profile else "unknown"

        evidence = collect_web_bridge_evidence(
            ctx,
            shared_mgr,
            model_name=f"web_{target_name}",
        )
        if evidence:
            report_path = generate_web_bridge_report(ctx, shared_mgr, evidence=evidence)
            if report_path:
                print(f"  [G-09] 主 pipeline 报告: {report_path}")
                logger.info(f"G-09 bridge: report saved to {report_path}")
    except (ImportError, OSError, ValueError) as e:
        logger.debug(f"G-09 bridge skipped: {e}")
        print(f"  [提示] 主 pipeline 集成跳过: {e}")

    print("\n" + "=" * 70)
    print("端到端流程完成")
    print("=" * 70)
    print(f"  报告目录: {output_dir}")

    logger.info(f"Stage 5: output saved to {output_dir}")
