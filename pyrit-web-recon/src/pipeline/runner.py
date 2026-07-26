# -*- coding: utf-8 -*-
"""
Pipeline Runner
===============

串行执行所有 Pipeline 阶段，并友好展示执行结果。
"""

from __future__ import annotations

import logging
import sys
from typing import List, Optional

from .base import PipelineStage
from .context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class PipelineRunner:
    """Pipeline 执行器"""

    def __init__(self, stages: List[PipelineStage], verbose: bool = False):
        self.stages = stages
        self.verbose = verbose

    async def run(self, context: PipelineContext) -> PipelineContext:
        """执行所有阶段"""
        self._print_header(context)

        for idx, stage in enumerate(self.stages, start=1):
            print(f"\n[阶段 {idx}/{len(self.stages)}] {stage.name}: {stage.description}")
            result = await stage.execute(context)
            context.add_result(result)
            self._print_result(result)

            # 阶段失败且未标记跳过，则终止流水线
            if not result.success and not result.skipped:
                print("\n❌ Pipeline 因阶段失败而终止。")
                break

        self._print_footer(context)
        return context

    def _print_header(self, context: PipelineContext) -> None:
        """打印流水线头部"""
        print("\n" + "=" * 70)
        print("  🎯 LLM Web 应用侦察 Pipeline")
        print("=" * 70)
        print(f"  目标 URL:  {context.target_url}")
        print(f"  目标类型:  {context.target_type}")
        print(f"  无头模式:  {context.headless}")
        print("=" * 70)

    def _print_result(self, result: StageResult) -> None:
        """友好打印单个阶段结果"""
        if result.skipped:
            icon = "⏭️"
            status = "跳过"
        elif result.success:
            icon = "✅"
            status = "成功"
        else:
            icon = "❌"
            status = "失败"

        print(f"  {icon} {result.stage_name}: {status} ({result.duration_ms}ms)")
        if result.message:
            print(f"     {result.message}")

        if self.verbose and result.data:
            for key, value in result.data.items():
                print(f"     - {key}: {value}")

    def _print_footer(self, context: PipelineContext) -> None:
        """打印流水线尾部"""
        success_count = sum(1 for r in context.stage_results if r.success and not r.skipped)
        skipped_count = sum(1 for r in context.stage_results if r.skipped)
        failed_count = sum(1 for r in context.stage_results if not r.success and not r.skipped)
        total = len(context.stage_results)

        print("\n" + "=" * 70)
        print(f"  Pipeline 执行完成: 成功 {success_count} / 跳过 {skipped_count} / 失败 {failed_count} / 总计 {total}")
        print("=" * 70)
