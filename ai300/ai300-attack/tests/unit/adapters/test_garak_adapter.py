# -*- coding: utf-8 -*-
"""
GarakAdapter 单元测试
"""

from unittest.mock import MagicMock, patch

import pytest

from ai300_attack.adapters.base import AttackStrategy
from ai300_attack.adapters.garak_adapter import GarakAdapter
from ai300_schemas import PyRITTargetConfig


def test_garak_adapter_is_available_when_command_exists():
    """当 garak 命令存在时，is_available 返回 True"""
    adapter = GarakAdapter({})
    with patch("ai300_attack.adapters.garak_adapter.shutil.which", return_value="/usr/bin/garak"):
        assert adapter.is_available() is True


def test_garak_adapter_is_unavailable_when_command_missing():
    """当 garak 命令不存在时，is_available 返回 False"""
    adapter = GarakAdapter({})
    with patch("ai300_attack.adapters.garak_adapter.shutil.which", return_value=None):
        assert adapter.is_available() is False


def test_garak_adapter_run_returns_error_when_missing():
    """garak 不存在时返回错误结果"""
    adapter = GarakAdapter({})
    with patch("ai300_attack.adapters.garak_adapter.shutil.which", return_value=None):
        result = adapter.run(
            PyRITTargetConfig(endpoint="https://example.com/v1/chat"),
            AttackStrategy(name="jailbreak_direct"),
        )
    assert result.success is False
    assert "garak command not found" in result.error


def test_infer_garak_model_type():
    """根据 target 推断 Garak model_type"""
    adapter = GarakAdapter({})
    assert adapter._infer_garak_model_type(PyRITTargetConfig(api_type="openai_compatible")) == "openai.OpenAICompatible"
    assert adapter._infer_garak_model_type(PyRITTargetConfig(target_type="AzureOpenAITarget")) == "azure"
    assert adapter._infer_garak_model_type(PyRITTargetConfig(endpoint="http://127.0.0.1:8000/v1/chat/completions")) == "openai.OpenAICompatible"
