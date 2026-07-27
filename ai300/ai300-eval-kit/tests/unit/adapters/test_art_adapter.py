# -*- coding: utf-8 -*-
"""
ARTAdapter 单元测试
"""

from unittest.mock import MagicMock, patch

from ai300_eval_kit.adapters.art_adapter import ARTAdapter
from ai300_eval_kit.adapters.base import EvalStrategy
from ai300_schemas import PyRITTargetConfig


def test_art_adapter_is_available_when_installed():
    """ART 可导入时，is_available 返回 True"""
    adapter = ARTAdapter({})
    with patch.object(adapter, "_load_art", return_value=MagicMock()):
        assert adapter.is_available() is True


def test_art_adapter_is_unavailable_when_missing():
    """ART 未安装时，is_available 返回 False"""
    adapter = ARTAdapter({})
    with patch.object(adapter, "_load_art", side_effect=RuntimeError("not installed")):
        assert adapter.is_available() is False


def test_art_adapter_run_returns_stub_finding():
    """ART 已安装时 run 返回占位发现"""
    adapter = ARTAdapter({})
    fake_art = MagicMock()
    fake_art.__version__ = "1.18.0"
    with patch.object(adapter, "_load_art", return_value=fake_art):
        result = adapter.run(
            PyRITTargetConfig(endpoint="https://example.com/v1/chat"),
            EvalStrategy(name="robustness"),
        )
    assert result.success is True
    assert result.adapter == "art"
    assert len(result.findings) == 1
    assert result.findings[0].source_tool == "art"
    assert result.findings[0].severity == "info"
