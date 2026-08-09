# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_init — Stage 1 原生初始化单元测试。.

覆盖:
  - FileNotFoundError: 配置文件不存在
  - 正常初始化流程 (mock)
  - Resume 机制增强: _find_db_for_srid + _initialize_with_per_run_db resume 模式

> **日期**: 2026-8-1
"""

from __future__ import annotations

import sqlite3
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
            patch(
                "pipeline.stages.stage_init._preflight_check",
                new_callable=AsyncMock,
            ),
        ):
            mock_loader_cls.load_with_overrides = MagicMock(return_value=mock_config)

            from pipeline.stages.stage_init import run as stage_init

            await stage_init(ctx)

            # 验证 _core_initialize_pyrit 被调用 (对齐 per-run DB 初始化)
            mock_init.assert_called_once()

        assert ctx.config is mock_config

    async def test_skip_preflight_skips_check(self, mock_args: pytest.fixture, tmp_path: Path) -> None:
        """默认跳过预检 (不调用 _preflight_check)."""
        config_path = tmp_path / "test_conf.yaml"
        config_path.write_text("memory_db_type: in_memory\nsilent: true\n", encoding="utf-8")
        mock_args.config_file = str(config_path)
        mock_args.skip_preflight = True
        mock_args.run_preflight = False
        ctx = PipelineContext(args=mock_args)

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
            patch("pipeline.stages.stage_init._core_initialize_pyrit", new_callable=AsyncMock),
            patch("pipeline.stages.stage_init.TargetRegistry"),
            patch("pipeline.stages.stage_init.ScorerRegistry"),
            patch("pipeline.stages.stage_init.AttackTechniqueRegistry"),
            patch(
                "pipeline.stages.stage_init._load_local_datasets_async",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "pipeline.stages.stage_init._preflight_check",
                new_callable=AsyncMock,
            ) as mock_preflight,
        ):
            mock_loader_cls.load_with_overrides = MagicMock(return_value=mock_config)

            from pipeline.stages.stage_init import run as stage_init

            await stage_init(ctx)

            # skip_preflight=True 时 _preflight_check 不应被调用
            mock_preflight.assert_not_called()


# ──────────────────────────────────────────────────────────────────
# Resume 机制增强: _find_db_for_srid 单元测试
# ──────────────────────────────────────────────────────────────────


class TestFindDbForSrid:
    """_find_db_for_srid 单元测试 — SRID 数据库查找。."""

    def test_find_db_for_srid_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SRID 存在于某个数据库中时, 返回该数据库路径。."""
        from pipeline.stages.stage_init import _find_db_for_srid

        srid = "550e8400-e29b-41d4-a716-446655440000"

        # 创建模拟的 outputs/db 目录
        db_dir = tmp_path / "outputs" / "db"
        db_dir.mkdir(parents=True)

        # 创建一个包含 SRID 的数据库
        db_file = db_dir / "redteam_20260803_120000.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE ScenarioResultEntries (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO ScenarioResultEntries (id) VALUES (?)", (srid,))
        conn.commit()
        conn.close()

        # 创建一个不含 SRID 的数据库
        other_db = db_dir / "redteam_20260802_100000.db"
        conn = sqlite3.connect(str(other_db))
        conn.execute("CREATE TABLE ScenarioResultEntries (id TEXT PRIMARY KEY)")
        conn.execute(
            "INSERT INTO ScenarioResultEntries (id) VALUES (?)", ("other-srid-1234",)
        )
        conn.commit()
        conn.close()

        # chdir 到 tmp_path 使 Path("outputs/db") 解析到 tmp_path/outputs/db
        monkeypatch.chdir(tmp_path)

        result = _find_db_for_srid(srid)

        assert result is not None
        assert result.name == "redteam_20260803_120000.db"

    def test_find_db_for_srid_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SRID 不存在于任何数据库中时, 返回 None。."""
        from pipeline.stages.stage_init import _find_db_for_srid

        srid = "nonexistent-srid-0000"

        db_dir = tmp_path / "outputs" / "db"
        db_dir.mkdir(parents=True)

        # 创建一个不含目标 SRID 的数据库
        db_file = db_dir / "redteam_20260803_120000.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE ScenarioResultEntries (id TEXT PRIMARY KEY)")
        conn.execute(
            "INSERT INTO ScenarioResultEntries (id) VALUES (?)", ("other-srid-1234",)
        )
        conn.commit()
        conn.close()

        monkeypatch.chdir(tmp_path)

        result = _find_db_for_srid(srid)

        assert result is None

    def test_find_db_for_srid_no_db_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """outputs/db 目录不存在时, 返回 None。."""
        from pipeline.stages.stage_init import _find_db_for_srid

        # tmp_path 下不创建 outputs/db 目录
        monkeypatch.chdir(tmp_path)

        result = _find_db_for_srid("any-srid")

        assert result is None

    def test_find_db_for_srid_multiple_dbs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """多个数据库中搜索, 返回包含 SRID 的那个。."""
        from pipeline.stages.stage_init import _find_db_for_srid

        target_srid = "target-srid-abcd"

        db_dir = tmp_path / "outputs" / "db"
        db_dir.mkdir(parents=True)

        # 创建 3 个数据库, 只有第 2 个包含目标 SRID
        for i, srid_in_db in enumerate(["srid-1", target_srid, "srid-3"]):
            db_file = db_dir / f"redteam_2026080{i + 1}_120000.db"
            conn = sqlite3.connect(str(db_file))
            conn.execute("CREATE TABLE ScenarioResultEntries (id TEXT PRIMARY KEY)")
            conn.execute(
                "INSERT INTO ScenarioResultEntries (id) VALUES (?)", (srid_in_db,)
            )
            conn.commit()
            conn.close()

        monkeypatch.chdir(tmp_path)

        result = _find_db_for_srid(target_srid)

        assert result is not None
        # 确保返回的数据库确实包含目标 SRID
        conn = sqlite3.connect(str(result))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM ScenarioResultEntries WHERE id = ?", (target_srid,)
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_find_db_for_srid_corrupt_db_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """损坏的数据库文件被跳过, 不影响搜索。."""
        from pipeline.stages.stage_init import _find_db_for_srid

        srid = "good-srid-1234"

        db_dir = tmp_path / "outputs" / "db"
        db_dir.mkdir(parents=True)

        # 创建一个损坏的文件 (非 SQLite)
        corrupt_file = db_dir / "redteam_corrupt.db"
        corrupt_file.write_text("not a database", encoding="utf-8")

        # 创建一个正常的数据库包含 SRID
        good_file = db_dir / "redteam_good.db"
        conn = sqlite3.connect(str(good_file))
        conn.execute("CREATE TABLE ScenarioResultEntries (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO ScenarioResultEntries (id) VALUES (?)", (srid,))
        conn.commit()
        conn.close()

        monkeypatch.chdir(tmp_path)

        result = _find_db_for_srid(srid)

        assert result is not None
        assert result.name == "redteam_good.db"


@pytest.mark.asyncio
class TestResumeDbLoading:
    """_initialize_with_per_run_db resume 模式测试。."""

    async def test_resume_uses_old_db(
        self, mock_args: pytest.fixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--resume 指定时, 加载包含 SRID 的旧数据库而非创建新数据库。."""
        srid = "resume-srid-abcd"
        mock_args.resume = srid

        # 创建模拟的旧数据库
        db_dir = tmp_path / "outputs" / "db"
        db_dir.mkdir(parents=True)
        old_db = db_dir / "redteam_20260803_120000.db"
        conn = sqlite3.connect(str(old_db))
        conn.execute("CREATE TABLE ScenarioResultEntries (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO ScenarioResultEntries (id) VALUES (?)", (srid,))
        conn.commit()
        conn.close()

        monkeypatch.chdir(tmp_path)

        from pipeline.stages.stage_init import _initialize_with_per_run_db

        ctx = PipelineContext(args=mock_args)
        ctx.output_manager = MagicMock()
        ctx.output_manager.db_path = tmp_path / "outputs" / "db" / "redteam_new.db"

        mock_config = MagicMock()
        mock_config.memory_db_type = "sqlite"
        mock_config.silent = True
        mock_config.env_akv_ref = None
        mock_config._MEMORY_DB_TYPE_MAP = {"sqlite": "SQLite"}
        mock_config.resolve_initializers = MagicMock(return_value={})
        mock_config.resolve_initialization_scripts = MagicMock(return_value=[])
        mock_config.resolve_env_files = MagicMock(return_value=[])

        with patch(
            "pipeline.stages.stage_init._core_initialize_pyrit",
            new_callable=AsyncMock,
        ) as mock_init:
            await _initialize_with_per_run_db(ctx, mock_config)

            # 验证传给 initialize_pyrit 的 db_path 是旧数据库路径
            call_kwargs = mock_init.call_args
            assert Path(call_kwargs.kwargs["db_path"]).resolve() == old_db.resolve()

    async def test_resume_srid_not_found_uses_new_db(
        self, mock_args: pytest.fixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--resume 指定但 SRID 未找到时, 回退到新数据库。."""
        mock_args.resume = "nonexistent-srid-0000"

        monkeypatch.chdir(tmp_path)

        from pipeline.stages.stage_init import _initialize_with_per_run_db

        ctx = PipelineContext(args=mock_args)
        new_db_path = tmp_path / "outputs" / "db" / "redteam_new_test.db"
        ctx.output_manager = MagicMock()
        ctx.output_manager.db_path = new_db_path

        mock_config = MagicMock()
        mock_config.memory_db_type = "sqlite"
        mock_config.silent = True
        mock_config.env_akv_ref = None
        mock_config._MEMORY_DB_TYPE_MAP = {"sqlite": "SQLite"}
        mock_config.resolve_initializers = MagicMock(return_value={})
        mock_config.resolve_initialization_scripts = MagicMock(return_value=[])
        mock_config.resolve_env_files = MagicMock(return_value=[])

        with (
            patch(
                "pipeline.stages.stage_init._core_initialize_pyrit",
                new_callable=AsyncMock,
            ) as mock_init,
            patch("pipeline.stages.stage_init._find_db_for_srid", return_value=None),
        ):
            await _initialize_with_per_run_db(ctx, mock_config)

            # 验证传给 initialize_pyrit 的 db_path 是新数据库路径
            call_kwargs = mock_init.call_args
            assert call_kwargs.kwargs["db_path"] == str(new_db_path)

    async def test_no_resume_uses_new_db(
        self, mock_args: pytest.fixture, tmp_path: Path
    ) -> None:
        """无 --resume 时, 使用新创建的 per-run 数据库。."""
        mock_args.resume = None

        from pipeline.stages.stage_init import _initialize_with_per_run_db

        ctx = PipelineContext(args=mock_args)
        new_db_path = Path("outputs/db/redteam_fresh.db")
        ctx.output_manager = MagicMock()
        ctx.output_manager.db_path = new_db_path

        mock_config = MagicMock()
        mock_config.memory_db_type = "sqlite"
        mock_config.silent = True
        mock_config.env_akv_ref = None
        mock_config._MEMORY_DB_TYPE_MAP = {"sqlite": "SQLite"}
        mock_config.resolve_initializers = MagicMock(return_value={})
        mock_config.resolve_initialization_scripts = MagicMock(return_value=[])
        mock_config.resolve_env_files = MagicMock(return_value=[])

        with patch(
            "pipeline.stages.stage_init._core_initialize_pyrit",
            new_callable=AsyncMock,
        ) as mock_init:
            await _initialize_with_per_run_db(ctx, mock_config)

            # 验证传给 initialize_pyrit 的 db_path 是新数据库路径
            call_kwargs = mock_init.call_args
            assert call_kwargs.kwargs["db_path"] == str(new_db_path)
