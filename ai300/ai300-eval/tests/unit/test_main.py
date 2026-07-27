# -*- coding: utf-8 -*-
"""
主入口单元测试
"""

import pytest

from ai300_eval.adapters import ARTAdapter, GiskardAdapter
from ai300_eval.config import EvalConfig
from ai300_eval.main import get_adapter


def test_get_adapter_returns_giskard():
    """get_adapter('giskard') 返回 GiskardAdapter 实例"""
    config = EvalConfig()
    adapter = get_adapter("giskard", config)
    assert isinstance(adapter, GiskardAdapter)


def test_get_adapter_returns_art():
    """get_adapter('art') 返回 ARTAdapter 实例"""
    config = EvalConfig()
    adapter = get_adapter("art", config)
    assert isinstance(adapter, ARTAdapter)


def test_get_adapter_unknown_raises():
    """未知适配器名称抛出 ValueError"""
    config = EvalConfig()
    with pytest.raises(ValueError, match="Unknown adapter"):
        get_adapter("unknown", config)
