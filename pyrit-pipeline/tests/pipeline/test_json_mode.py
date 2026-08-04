# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""JSON Mode 兼容性检测单元测试。.

测试 ``_disable_json_mode_for_third_party_endpoints`` 函数:
- 自动检测第三方端点 (非 OpenAI/Azure) 并禁用 JSON mode
- ``--disable-json-mode`` flag 强制禁用
- Monkey-patch ``_build_response_format`` 返回 None
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from pipeline.context import PipelineContext

# ──────────────────────────────────────────────────────────────────
# _is_json_mode_supported 单元测试
# ──────────────────────────────────────────────────────────────────


class TestIsJsonModeSupported:
    """``_is_json_mode_supported`` 端点检测测试。."""

    def test_openai_endpoint_supported(self) -> None:
        """OpenAI 原生端点支持 JSON mode。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported("https://api.openai.com/v1") is True

    def test_azure_endpoint_supported(self) -> None:
        """Azure OpenAI 端点支持 JSON mode。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported("https://myresource.openai.azure.com/") is True

    def test_siliconflow_endpoint_not_supported(self) -> None:
        """SiliconFlow 端点不支持 JSON mode。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported("https://api.siliconflow.cn/v1") is False

    def test_openrouter_endpoint_not_supported(self) -> None:
        """OpenRouter 端点不支持 JSON mode。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported("https://openrouter.ai/api/v1") is False

    def test_empty_endpoint_not_supported(self) -> None:
        """空端点不支持 JSON mode。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported("") is False

    def test_none_endpoint_not_supported(self) -> None:
        """None 端点不支持 JSON mode。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported(None) is False  # type: ignore[arg-type]

    def test_case_insensitive(self) -> None:
        """端点检测大小写不敏感。."""
        from pipeline.stages.stage_init import _is_json_mode_supported

        assert _is_json_mode_supported("https://API.OPENAI.COM/v1") is True


# ──────────────────────────────────────────────────────────────────
# Mock 辅助类
# ──────────────────────────────────────────────────────────────────


class _MockChatTarget:
    """模拟的 OpenAIChatTarget 实例 (不自动创建 inner_target 属性)。."""

    def __init__(
        self,
        endpoint: str = "https://api.siliconflow.cn/v1",
        model_name: str = "stepfun-ai/Step-3.5-Flash",
    ) -> None:
        self._endpoint = endpoint
        self._model_name = model_name
        self._build_response_format = self._default_response_format

    def _default_response_format(self, json_config: Any) -> Any:
        return {"type": "json_object"}


class _MockRateLimitedTarget:
    """模拟的 RateLimitedTarget 包装器。."""

    def __init__(self, inner: _MockChatTarget) -> None:
        self._inner_target = inner

    @property
    def inner_target(self) -> _MockChatTarget:
        return self._inner_target


class _MockRegistryEntry:
    """模拟的 TargetRegistry entry。."""

    def __init__(
        self,
        target: Any,
        name: str = "adversarial_chat",
        tags: list[str] | None = None,
    ) -> None:
        self.instance = target
        self.name = name
        self.tags = tags or []


# ──────────────────────────────────────────────────────────────────
# _disable_json_mode_for_third_party_endpoints 单元测试
# ──────────────────────────────────────────────────────────────────


class TestDisableJsonMode:
    """``_disable_json_mode_for_third_party_endpoints`` 功能测试。."""

    def test_auto_disable_siliconflow(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """自动检测 SiliconFlow 端点并禁用 JSON mode。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)
        mock_target = _MockChatTarget(
            endpoint="https://api.siliconflow.cn/v1",
            model_name="stepfun-ai/Step-3.5-Flash",
        )
        mock_entry = _MockRegistryEntry(mock_target)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "已禁用" in captured.out

    def test_auto_disable_openrouter(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """自动检测 OpenRouter 端点并禁用 JSON mode。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)
        mock_target = _MockChatTarget(
            endpoint="https://openrouter.ai/api/v1",
            model_name="anthropic/claude-3-opus",
        )
        mock_entry = _MockRegistryEntry(mock_target)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "已禁用" in captured.out

    def test_no_disable_openai_endpoint(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OpenAI 原生端点不禁用 JSON mode。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)
        mock_target = _MockChatTarget(
            endpoint="https://api.openai.com/v1",
            model_name="gpt-4o",
        )
        mock_entry = _MockRegistryEntry(mock_target)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "无需禁用" in captured.out

    def test_no_disable_azure_endpoint(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Azure OpenAI 端点不禁用 JSON mode。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)
        mock_target = _MockChatTarget(
            endpoint="https://myresource.openai.azure.com/",
            model_name="gpt-4o",
        )
        mock_entry = _MockRegistryEntry(mock_target)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "无需禁用" in captured.out

    def test_force_disable_all(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--disable-json-mode 强制禁用所有目标 (包括 OpenAI 端点)。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        mock_args.disable_json_mode = True
        ctx = PipelineContext(args=mock_args)

        mock_target = _MockChatTarget(
            endpoint="https://api.openai.com/v1",
            model_name="gpt-4o",
        )
        mock_entry = _MockRegistryEntry(mock_target)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "全局禁用" in captured.out
        assert "已禁用" in captured.out

    def test_empty_registry_no_error(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """空 TargetRegistry 不报错。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = []
            _disable_json_mode_for_third_party_endpoints(ctx)

        # 不应抛出异常
        captured = capsys.readouterr()
        assert "第三方端点兼容性检测" in captured.out

    def test_rate_limited_target_unwrapped(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """RateLimitedTarget 包装的目标被正确解包。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)

        inner_target = _MockChatTarget(
            endpoint="https://api.siliconflow.cn/v1",
            model_name="stepfun-ai/Step-3.5-Flash",
        )
        rate_limited = _MockRateLimitedTarget(inner_target)
        mock_entry = _MockRegistryEntry(rate_limited)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "已禁用" in captured.out

    def test_non_chat_target_skipped(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """非 ChatTarget (无 _build_response_format) 被跳过。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)

        # 没有 _build_response_format 属性的目标
        class _NonChatTarget:
            def __init__(self) -> None:
                self._endpoint = "https://api.siliconflow.cn/v1"
                self._model_name = "some-model"

        mock_entry = _MockRegistryEntry(_NonChatTarget())

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "无需禁用" in captured.out

    def test_multiple_targets_mixed(
        self, mock_args: pytest.fixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """混合端点: OpenAI 不禁用, SiliconFlow 禁用。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)

        openai_target = _MockChatTarget(
            endpoint="https://api.openai.com/v1",
            model_name="gpt-4o",
        )
        siliconflow_target = _MockChatTarget(
            endpoint="https://api.siliconflow.cn/v1",
            model_name="stepfun-ai/Step-3.5-Flash",
        )

        openai_entry = _MockRegistryEntry(openai_target, name="openai_chat")
        sf_entry = _MockRegistryEntry(siliconflow_target, name="adversarial_chat")

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [
                openai_entry,
                sf_entry,
            ]
            _disable_json_mode_for_third_party_endpoints(ctx)

        captured = capsys.readouterr()
        assert "共 1 个目标" in captured.out
        assert "adversarial_chat" in captured.out

    def test_disable_json_mode_default_false(
        self, mock_args: pytest.fixture
    ) -> None:
        """默认情况下 disable_json_mode 为 False (自动检测模式)。."""
        ctx = PipelineContext(args=mock_args)
        assert ctx.args.disable_json_mode is False

    def test_patched_method_returns_none(
        self, mock_args: pytest.fixture
    ) -> None:
        """Patched _build_response_format 返回 None。."""
        from pipeline.stages.stage_init import _disable_json_mode_for_third_party_endpoints

        ctx = PipelineContext(args=mock_args)
        mock_target = _MockChatTarget(
            endpoint="https://api.siliconflow.cn/v1",
            model_name="stepfun-ai/Step-3.5-Flash",
        )
        mock_entry = _MockRegistryEntry(mock_target)

        with patch(
            "pyrit.registry.TargetRegistry.get_registry_singleton"
        ) as mock_registry:
            mock_registry.return_value.instances.get_all_instances.return_value = [mock_entry]
            _disable_json_mode_for_third_party_endpoints(ctx)

        # 验证 patched 方法返回 None
        result = mock_target._build_response_format(json_config=MagicMock())
        assert result is None
