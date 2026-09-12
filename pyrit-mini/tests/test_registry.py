"""tests/test_registry.py - ComponentRegistry 单元测试（REQ-153）。

覆盖：空注册表降级 / YAML 加载 / 按标签反查 / 坏文件隔离 / 字段安全缺省。
"""

from __future__ import annotations

from pathlib import Path

from core.registry import ComponentRegistry


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestComponentRegistry:
    """注册表行为验证（W0：空注册表不得影响既有行为）。"""

    def test_missing_dir_is_empty_registry(self, tmp_path: Path) -> None:
        reg = ComponentRegistry(tmp_path / "nope")
        assert reg.is_empty is True
        assert reg.names() == []
        assert reg.get("mcp") is None

    def test_load_yaml_components(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "mcp.yaml",
            "id: mcp\nlabels: [mcp, tool_surface]\nseeds: ['data/seeds/mcp/*']\n"
            "scorer: mcp_tool_poisoning\ncleanup: [unregister_tool]\n",
        )
        reg = ComponentRegistry(tmp_path)
        assert reg.is_empty is False
        assert "mcp" in reg.names()

        comp = reg.get("mcp")
        assert comp is not None
        assert "tool_surface" in comp["labels"]

    def test_by_label_and_resolve(self, tmp_path: Path) -> None:
        _write(tmp_path / "a.yaml", "id: mcp\nlabels: [mcp, tool_surface]\n")
        _write(tmp_path / "b.yaml", "id: rag\nlabels: [rag]\n")
        reg = ComponentRegistry(tmp_path)

        assert [c["id"] for c in reg.by_label("mcp")] == ["mcp"]
        assert reg.resolve("rag") == ["rag"]
        assert reg.by_label("nonexistent") == []

    def test_get_field_default(self, tmp_path: Path) -> None:
        _write(tmp_path / "mcp.yaml", "id: mcp\nscorer: mcp_tool_poisoning\n")
        reg = ComponentRegistry(tmp_path)

        assert reg.get_field("mcp", "scorer") == "mcp_tool_poisoning"
        assert reg.get_field("mcp", "playbooks", []) == []
        assert reg.get_field("missing", "scorer", "fallback") == "fallback"

    def test_broken_yaml_is_isolated(self, tmp_path: Path) -> None:
        _write(tmp_path / "good.yaml", "id: good\nlabels: [web]\n")
        _write(tmp_path / "bad.yaml", "id: bad\nlabels: [broken\n  - unclosed\n")
        reg = ComponentRegistry(tmp_path)

        # 坏文件不应导致整个注册表不可用
        assert "good" in reg.names()

    def test_non_dict_yaml_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path / "list.yaml", "- a\n- b\n")
        reg = ComponentRegistry(tmp_path)
        assert reg.is_empty is True

    def test_id_defaults_to_filename(self, tmp_path: Path) -> None:
        _write(tmp_path / "a2a.yaml", "labels: [a2a]\n")
        reg = ComponentRegistry(tmp_path)
        assert "a2a" in reg.names()
