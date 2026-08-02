# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_init — Stage 1 原生初始化单元测试。.

覆盖:
  - FileNotFoundError: 配置文件不存在
  - 正常初始化流程 (mock)

> **日期**: 2026-8-1
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pipeline.context import PipelineContext


@pytest.mark.asyncio
class TestStageInit:
    """Stage 1: stage_init.run 单元测试。."""

    async def test_config_not_found_raises(self, mock_args: pytest.fixture) -> None:
        """配置文件不存在时引发 FileNotFoundError。."""
        mock_args.config_file = "nonexistent_conf.yaml"
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_init import run as stage_init

        with pytest.raises(FileNotFoundError, match="配置文件不存在"):
            await stage_init(ctx)

    async def test_successful_init(self, mock_args: pytest.fixture, tmp_path: Path) -> None:
        """正常初始化流程 (mock ConfigurationLoader + per-run DB 初始化)."""
        # 创建临时配置文件
        config_path = tmp_path / "test_conf.yaml"
        config_path.write_text("memory_db_type: in_memory\nsilent: true\n", encoding="utf-8")
        mock_args.config_file = str(config_path)
        ctx = PipelineContext(args=mock_args)

        # Mock ConfigurationLoader — 对齐 _initialize_with_per_run_db() 调用链
        mock_config = MagicMock()
        mock_config.memory_db_type = "in_memory"
        mock_config.silent = True
        mock_config.env_akv_ref = None
        mock_config._MEMORY_DB_TYPE_MAP = {"in_memory": "InMemory", "sqlite": "SQLite"}
        mock_config.resolve_initializers = MagicMock(return_value={})
        mock_config.resolve_initialization_scripts = MagicMock(return_value=[])
        mock_config.resolve_env_files = MagicMock(return_value=[])

        with (
            patch("pipeline.stages.stage_init.ConfigurationLoader") as mock_loader_cls,
            patch("pipeline.stages.stage_init._core_initialize_pyrit", new_callable=AsyncMock) as mock_init,
            patch("pipeline.stages.stage_init.TargetRegistry"),
            patch("pipeline.stages.stage_init.ScorerRegistry"),
            patch("pipeline.stages.stage_init.AttackTechniqueRegistry"),
            patch(
                "pipeline.stages.stage_init._load_local_datasets_async",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            mock_loader_cls.load_with_overrides = MagicMock(return_value=mock_config)

            from pipeline.stages.stage_init import run as stage_init

            await stage_init(ctx)

            # 验证 _core_initialize_pyrit 被调用 (对齐 per-run DB 初始化)
            mock_init.assert_called_once()

        assert ctx.config is mock_config
