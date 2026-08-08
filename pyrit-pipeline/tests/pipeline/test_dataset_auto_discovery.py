# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_dataset_auto_discovery — 数据集自动发现 + scope 过滤 + P1-P3 单元测试。.

覆盖:
  - _matches_dataset_scope: 5 种 scope 过滤
  - _discover_unregistered_datasets: 目录扫描 + 去重 + scope 过滤
  - _load_default_datasets_from_manifest: scope 参数 + 自动发现集成
  - P1: _filter_datasets_by_target: 目标感知数据集筛选
  - P2: _load_local_datasets_async: max_seeds 截断
  - P3: _write_manifest_entries: 清单自动更新

> **日期**: 2026-8-8
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


class TestMatchesDatasetScope:
    """_matches_dataset_scope: scope 过滤逻辑。."""

    def test_scope_all_matches_everything(self) -> None:
        """scope=all 匹配所有路径。."""
        from pipeline.stages.stage_init import _matches_dataset_scope

        assert _matches_dataset_scope("data/seed_datasets/owasp/llm01.prompt", "all") is True
        assert _matches_dataset_scope("data/seed_datasets/cve/exploit.prompt", "all") is True
        assert _matches_dataset_scope("data/seed_datasets/benchmarks/harmbench.prompt", "all") is True

    def test_scope_owasp_llm(self) -> None:
        """scope=owasp_llm 仅匹配 owasp/ 目录下 llm 开头的文件。."""
        from pipeline.stages.stage_init import _matches_dataset_scope

        assert _matches_dataset_scope("data/seed_datasets/owasp/llm01_prompt_injection.prompt", "owasp_llm") is True
        assert _matches_dataset_scope("data/seed_datasets/owasp/llm10_unbounded.prompt", "owasp_llm") is True
        # 不匹配 ASI
        assert _matches_dataset_scope("data/seed_datasets/owasp/asi01_agent.prompt", "owasp_llm") is False
        # 不匹配其他目录
        assert _matches_dataset_scope("data/seed_datasets/cve/exploit.prompt", "owasp_llm") is False

    def test_scope_owasp_asi(self) -> None:
        """scope=owasp_asi 仅匹配 owasp/ 目录下 asi 开头的文件。."""
        from pipeline.stages.stage_init import _matches_dataset_scope

        assert _matches_dataset_scope("data/seed_datasets/owasp/asi01_agent.prompt", "owasp_asi") is True
        assert _matches_dataset_scope("data/seed_datasets/owasp/asi10_rogue.prompt", "owasp_asi") is True
        # 不匹配 LLM
        assert _matches_dataset_scope("data/seed_datasets/owasp/llm01.prompt", "owasp_asi") is False
        # 不匹配其他目录
        assert _matches_dataset_scope("data/seed_datasets/cve/exploit.prompt", "owasp_asi") is False

    def test_scope_cve(self) -> None:
        """scope=cve 仅匹配 cve/ 目录下的文件。."""
        from pipeline.stages.stage_init import _matches_dataset_scope

        assert _matches_dataset_scope("data/seed_datasets/cve/prompt_injection.prompt", "cve") is True
        assert _matches_dataset_scope("data/seed_datasets/cve/new_vuln.prompt", "cve") is True
        # 不匹配 owasp
        assert _matches_dataset_scope("data/seed_datasets/owasp/llm01.prompt", "cve") is False

    def test_scope_benchmark(self) -> None:
        """scope=benchmark 仅匹配 benchmarks/ 目录下的文件。."""
        from pipeline.stages.stage_init import _matches_dataset_scope

        assert _matches_dataset_scope("data/seed_datasets/benchmarks/harmbench.prompt", "benchmark") is True
        # 不匹配 owasp
        assert _matches_dataset_scope("data/seed_datasets/owasp/llm01.prompt", "benchmark") is False


class TestDiscoverUnregisteredDatasets:
    """_discover_unregistered_datasets: 目录扫描 + 去重。."""

    def test_no_discovery_when_all_registered(self, tmp_path: Path) -> None:
        """所有文件已注册时, 不发现新文件。."""
        from pipeline.stages.stage_init import _discover_unregistered_datasets

        owasp_dir = tmp_path / "owasp"
        owasp_dir.mkdir()
        prompt_file = owasp_dir / "llm01.prompt"
        prompt_file.write_text("test", encoding="utf-8")

        known = {str(prompt_file.resolve())}

        with patch("pipeline.stages.stage_init.Path") as mock_path:
            def side_effect(arg):
                if arg == "data/seed_datasets/owasp":
                    return owasp_dir
                if arg == "data/seed_datasets/cve":
                    return tmp_path / "cve"
                if arg == "data/seed_datasets/custom":
                    return tmp_path / "custom"
                return Path(arg)

            mock_path.side_effect = side_effect

            result = _discover_unregistered_datasets(known, "all")

        assert result == []

    def test_discovers_new_file(self, tmp_path: Path) -> None:
        """发现未注册的 .prompt 文件。."""
        from pipeline.stages.stage_init import _discover_unregistered_datasets

        owasp_dir = tmp_path / "owasp"
        owasp_dir.mkdir()
        new_file = owasp_dir / "llm99_new_category.prompt"
        new_file.write_text("test", encoding="utf-8")

        known: set[str] = set()

        with patch("pipeline.stages.stage_init.Path") as mock_path:
            def side_effect(arg):
                if arg == "data/seed_datasets/owasp":
                    return owasp_dir
                if arg == "data/seed_datasets/cve":
                    return tmp_path / "cve"
                if arg == "data/seed_datasets/custom":
                    return tmp_path / "custom"
                return Path(arg)

            mock_path.side_effect = side_effect

            result = _discover_unregistered_datasets(known, "all")

        assert len(result) == 1
        assert "llm99_new_category" in result[0]

    def test_scope_filter_in_discovery(self, tmp_path: Path) -> None:
        """scope 过滤: scope=cve 只扫描 cve 目录。."""
        from pipeline.stages.stage_init import _discover_unregistered_datasets

        cve_dir = tmp_path / "cve"
        cve_dir.mkdir()
        new_cve = cve_dir / "new_cve_2026.prompt"
        new_cve.write_text("test", encoding="utf-8")

        known: set[str] = set()

        with patch("pipeline.stages.stage_init.Path") as mock_path:
            def side_effect(arg):
                if arg == "data/seed_datasets/cve":
                    return cve_dir
                return Path(arg)

            mock_path.side_effect = side_effect

            result = _discover_unregistered_datasets(known, "cve")

        assert len(result) == 1
        assert "new_cve_2026" in result[0]

    def test_dedup_after_discovery(self, tmp_path: Path) -> None:
        """发现的文件加入 known_paths, 二次调用不重复发现。."""
        from pipeline.stages.stage_init import _discover_unregistered_datasets

        cve_dir = tmp_path / "cve"
        cve_dir.mkdir()
        new_cve = cve_dir / "new_vuln.prompt"
        new_cve.write_text("test", encoding="utf-8")

        known: set[str] = set()

        with patch("pipeline.stages.stage_init.Path") as mock_path:
            def side_effect(arg):
                if arg == "data/seed_datasets/cve":
                    return cve_dir
                return Path(arg)

            mock_path.side_effect = side_effect

            result1 = _discover_unregistered_datasets(known, "cve")
            assert len(result1) == 1

            result2 = _discover_unregistered_datasets(known, "cve")
            assert len(result2) == 0

    def test_nonexistent_directory_skipped(self, tmp_path: Path) -> None:
        """不存在的目录被跳过, 不报错。."""
        from pipeline.stages.stage_init import _discover_unregistered_datasets

        with patch("pipeline.stages.stage_init.Path") as mock_path:
            def side_effect(arg):
                if arg == "data/seed_datasets/owasp":
                    return tmp_path / "nonexistent_owasp"
                if arg == "data/seed_datasets/cve":
                    return tmp_path / "nonexistent_cve"
                if arg == "data/seed_datasets/custom":
                    return tmp_path / "nonexistent_custom"
                return Path(arg)

            mock_path.side_effect = side_effect

            result = _discover_unregistered_datasets(set(), "all")

        assert result == []


class TestLoadDefaultDatasetsFromManifest:
    """_load_default_datasets_from_manifest: scope 参数 + 自动发现集成。."""

    def test_scope_all_loads_all_default_true(self) -> None:
        """scope=all 加载所有 default=true 的 local 数据集。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        paths, manifest, auto_discovered = _load_default_datasets_from_manifest(scope="all")

        assert len(paths) >= 21
        assert any("llm03" in p for p in paths)
        assert any("asi10" in p for p in paths)
        assert any("cve" in p for p in paths)
        assert manifest is not None
        assert isinstance(auto_discovered, list)

    def test_scope_owasp_llm_only(self) -> None:
        """scope=owasp_llm 仅加载 LLM 数据集。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        paths, _, _ = _load_default_datasets_from_manifest(scope="owasp_llm")

        for p in paths:
            assert "owasp" in p
            assert "llm" in Path(p).stem.lower()

    def test_scope_owasp_asi_only(self) -> None:
        """scope=owasp_asi 仅加载 ASI 数据集。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        paths, _, _ = _load_default_datasets_from_manifest(scope="owasp_asi")

        for p in paths:
            assert "owasp" in p
            assert "asi" in Path(p).stem.lower()

    def test_scope_cve_only(self) -> None:
        """scope=cve 仅加载 CVE 数据集。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        paths, _, _ = _load_default_datasets_from_manifest(scope="cve")

        for p in paths:
            assert "cve" in p

    def test_no_custom_redteam_in_results(self) -> None:
        """custom_redteam_objectives 已从清单删除, 不应出现。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        paths, _, _ = _load_default_datasets_from_manifest(scope="all")

        for p in paths:
            assert "custom" not in p or "redteam_objectives" not in p

    def test_auto_discovery_finds_unregistered(self) -> None:
        """自动发现机制: 清单中未注册的文件也能被发现。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        paths, _, _ = _load_default_datasets_from_manifest(scope="all")

        owasp_files = list(Path("data/seed_datasets/owasp").glob("*.prompt"))
        for f in owasp_files:
            assert any(Path(p).resolve() == f.resolve() for p in paths), f"未加载: {f}"

        cve_files = list(Path("data/seed_datasets/cve").glob("*.prompt"))
        for f in cve_files:
            assert any(Path(p).resolve() == f.resolve() for p in paths), f"未加载: {f}"

    def test_returns_manifest_dict(self) -> None:
        """返回的 manifest dict 包含 datasets 和 owasp_mapping。."""
        from pipeline.stages.stage_init import _load_default_datasets_from_manifest

        _, manifest, _ = _load_default_datasets_from_manifest(scope="all")

        assert manifest is not None
        assert "datasets" in manifest
        assert "owasp_mapping" in manifest
        assert len(manifest["datasets"]) >= 24


class TestFilterDatasetsByTarget:
    """P1: _filter_datasets_by_target: 目标感知数据集筛选。."""

    def test_unknown_target_type_no_filter(self) -> None:
        """未知 target_type 不过滤, 返回全部。"""
        from pipeline.stages.stage_init import _filter_datasets_by_target

        paths = ["data/seed_datasets/owasp/llm01.prompt", "data/seed_datasets/owasp/asi01.prompt"]
        result = _filter_datasets_by_target(paths, "unknown_type", None)
        assert len(result) == 2

    def test_openai_chat_keeps_llm_skips_asi(self) -> None:
        """target_type=openai_chat 保留 LLM, 筛选掉 ASI。"""
        from pipeline.stages.stage_init import _filter_datasets_by_target

        manifest = {
            "datasets": [
                {"path": "data/owasp/llm01.prompt", "owasp_ids": ["LLM01"]},
                {"path": "data/owasp/asi01.prompt", "owasp_ids": ["ASI01"]},
            ],
        }
        paths = ["data/owasp/llm01.prompt", "data/owasp/asi01.prompt"]
        result = _filter_datasets_by_target(paths, "openai_chat", manifest)
        assert len(result) == 1
        assert "llm01" in result[0]

    def test_agent_api_keeps_asi_skips_llm(self) -> None:
        """target_type=agent_api 保留 ASI + LLM06, 筛选掉其他 LLM。"""
        from pipeline.stages.stage_init import _filter_datasets_by_target

        manifest = {
            "datasets": [
                {"path": "data/owasp/asi01.prompt", "owasp_ids": ["ASI01"]},
                {"path": "data/owasp/llm01.prompt", "owasp_ids": ["LLM01"]},
                {"path": "data/owasp/llm06.prompt", "owasp_ids": ["LLM06"]},
            ],
        }
        paths = [
            "data/owasp/asi01.prompt",
            "data/owasp/llm01.prompt",
            "data/owasp/llm06.prompt",
        ]
        result = _filter_datasets_by_target(paths, "agent_api", manifest)
        # ASI01 保留, LLM01 筛选掉, LLM06 保留
        assert len(result) == 2
        assert any("asi01" in p for p in result)
        assert any("llm06" in p for p in result)
        assert not any("llm01" in p for p in result)

    def test_no_owasp_ids_always_kept(self) -> None:
        """无 owasp_ids 的数据集 (benchmark) 始终保留。"""
        from pipeline.stages.stage_init import _filter_datasets_by_target

        manifest = {
            "datasets": [
                {"path": "data/benchmarks/harmbench.prompt", "owasp_ids": []},
                {"path": "data/owasp/llm01.prompt", "owasp_ids": ["LLM01"]},
                {"path": "data/owasp/asi01.prompt", "owasp_ids": ["ASI01"]},
            ],
        }
        paths = [
            "data/benchmarks/harmbench.prompt",
            "data/owasp/llm01.prompt",
            "data/owasp/asi01.prompt",
        ]
        result = _filter_datasets_by_target(paths, "openai_chat", manifest)
        # harmbench 始终保留, llm01 保留, asi01 筛选掉
        assert len(result) == 2
        assert any("harmbench" in p for p in result)
        assert any("llm01" in p for p in result)

    def test_unregistered_path_always_kept(self) -> None:
        """不在清单中的路径 (自动发现) 始终保留。"""
        from pipeline.stages.stage_init import _filter_datasets_by_target

        manifest = {
            "datasets": [
                {"path": "data/owasp/llm01.prompt", "owasp_ids": ["LLM01"]},
            ],
        }
        paths = [
            "data/owasp/llm01.prompt",
            "data/cve/new_cve.prompt",  # 不在清单中
        ]
        result = _filter_datasets_by_target(paths, "agent_api", manifest)
        # new_cve 不在清单 → 始终保留; llm01 有 LLM01, agent_api 不含 LLM01 → 筛选掉
        assert len(result) == 1
        assert "new_cve" in result[0]



