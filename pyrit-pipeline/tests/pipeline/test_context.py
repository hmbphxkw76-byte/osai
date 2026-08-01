# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_context — PipelineContext 状态容器单元测试。.

> **日期**: 2026-8-1
"""

from __future__ import annotations

import argparse

from pipeline.context import PipelineContext


class TestPipelineContext:
    """PipelineContext 单元测试。."""

    def test_default_values(self) -> None:
        """默认值正确。."""
        ctx = PipelineContext()
        assert ctx.args is None
        assert ctx.config is None
        assert ctx.scenario is None
        assert ctx.objective_scorer is None
        assert ctx.result is None
        assert ctx.asr_per_technique == {}
        assert ctx.overall_asr == 0
        assert ctx.output_dir is None
        assert ctx.metadata == {}

    def test_with_args(self) -> None:
        """传入 args。."""
        args = argparse.Namespace(datasets=["harmbench"])
        ctx = PipelineContext(args=args)
        assert ctx.args is args

    def test_metadata_mutable(self) -> None:
        """Metadata 字段可变。."""
        ctx = PipelineContext()
        ctx.metadata["key"] = "value"
        assert ctx.metadata["key"] == "value"

    def test_asr_per_technique_mutable(self) -> None:
        """asr_per_technique 字段可变。."""
        ctx = PipelineContext()
        ctx.asr_per_technique["many_shot"] = 85.0
        assert ctx.asr_per_technique["many_shot"] == 85.0

    def test_metadata_isolated(self) -> None:
        """不同实例的 metadata 独立。."""
        ctx1 = PipelineContext()
        ctx2 = PipelineContext()
        ctx1.metadata["key"] = "value1"
        assert "key" not in ctx2.metadata

    def test_asr_per_technique_isolated(self) -> None:
        """不同实例的 asr_per_technique 独立。."""
        ctx1 = PipelineContext()
        ctx2 = PipelineContext()
        ctx1.asr_per_technique["many_shot"] = 85.0
        assert "many_shot" not in ctx2.asr_per_technique
