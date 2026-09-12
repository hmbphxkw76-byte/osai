"""I13 副作用清理回归测试（BL-064）。

覆盖：动作注册表、preflight 的三种判定（dry-run / 已实装 / 未实装）、
文档标识黑盒推断、无文档时的清理短路。
"""

from __future__ import annotations

import pytest

from strike.multimodal_upload.cleanup import (
    CLEANUP_ACTIONS,
    declared_cleanup_actions,
    extract_doc_id,
    preflight_cleanup,
    run_side_effect_cleanup,
)


class _Args:
    dry_run = False


class _Ctx:
    args = _Args()


@pytest.fixture
def ctx() -> _Ctx:
    return _Ctx()


class TestRegistry:
    def test_declared_action_is_registered(self) -> None:
        for action in declared_cleanup_actions("multimodal_upload"):
            assert action in CLEANUP_ACTIONS

    def test_unimplemented_component_declared_but_missing(self) -> None:
        # mcp 声明了 cleanup 但尚未实装任何动作 —— preflight 必须据此拒绝
        declared = declared_cleanup_actions("mcp_tool_poisoning")
        assert declared, "fixture 前提：mcp.yaml 声明了 cleanup"
        assert all(a not in CLEANUP_ACTIONS for a in declared)


class TestPreflight:
    def test_dry_run_skips_cleanup(self, ctx: _Ctx) -> None:
        result = preflight_cleanup(ctx, "multimodal_upload", dry_run=True)
        assert result["allowed"] is True
        assert result["status"] == "skipped_dry_run"

    def test_implemented_action_allows_execution(self, ctx: _Ctx) -> None:
        result = preflight_cleanup(ctx, "multimodal_upload", dry_run=False)
        assert result["allowed"] is True
        assert result["missing"] == []

    def test_unimplemented_action_blocks_execution(self, ctx: _Ctx) -> None:
        result = preflight_cleanup(ctx, "mcp_tool_poisoning", dry_run=False)
        assert result["allowed"] is False
        assert result["status"] == "blocked"
        assert result["missing"] == declared_cleanup_actions("mcp_tool_poisoning")

    def test_undeclared_component_blocks_execution(self, ctx: _Ctx) -> None:
        result = preflight_cleanup(ctx, "does_not_exist_component", dry_run=False)
        assert result["allowed"] is False
        assert result["status"] == "blocked"


class TestExtractDocId:
    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ({"doc_id": "abc"}, "abc"),
            ({"document_id": "d1"}, "d1"),
            ({"file_id": 7}, "7"),
            ({"id": "x1"}, "x1"),
            ({"result": {"id": 42}}, "42"),
            ([{"doc_id": "in-list"}], "in-list"),
            ("plain-text", None),
            ({}, None),
        ],
    )
    def test_extract(self, body: object, expected: str | None) -> None:
        assert extract_doc_id(body) == expected


class TestRunSideEffectCleanup:
    @pytest.mark.asyncio
    async def test_dry_run_does_not_execute(self, ctx: _Ctx) -> None:
        result = await run_side_effect_cleanup(ctx, "multimodal_upload", {}, dry_run=True)
        assert result["status"] == "skipped_dry_run"
        assert "actions" not in result

    @pytest.mark.asyncio
    async def test_blocked_when_action_missing(self, ctx: _Ctx) -> None:
        result = await run_side_effect_cleanup(ctx, "mcp_tool_poisoning", {}, dry_run=False)
        assert result["allowed"] is False
        assert result["status"] == "blocked"

    @pytest.mark.asyncio
    async def test_no_documents_short_circuits(self, ctx: _Ctx) -> None:
        result = await run_side_effect_cleanup(
            ctx,
            "multimodal_upload",
            {"target_url": "http://127.0.0.1:1", "upload_endpoint": "/upload", "doc_ids": []},
            dry_run=False,
        )
        assert result["status"] == "ok"
        action = result["actions"]["delete_uploaded_document"]
        assert action["skipped"] is True
