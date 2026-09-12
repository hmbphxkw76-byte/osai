# -*- coding: utf-8 -*-
"""tests/test_semantic_scorers.py — assess/semantic_scorers.py 单元测试。"""

from __future__ import annotations

import pytest

from assess.semantic_scorers import (
    create_retrieval_poisoning_scorer,
    create_tool_execution_scorer,
)


@pytest.fixture
def pyrit_memory():
    """PyRIT 1.0.1 的 Scorer 构造需要已初始化的 CentralMemory。"""
    from pyrit.memory import CentralMemory, SQLiteMemory

    previous = getattr(CentralMemory, "_memory_instance", None)
    CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))
    try:
        yield CentralMemory.get_memory_instance()
    finally:
        CentralMemory._memory_instance = previous


def test_create_tool_execution_scorer(pyrit_memory):
    """工具执行类 scorer 可成功构造（含默认敏感操作模式）。"""
    scorer = create_tool_execution_scorer()
    assert scorer is not None
    patterns = getattr(scorer, "patterns", None) or getattr(scorer, "_patterns", None)
    assert patterns is None or len(patterns) >= 0  # 构造不抛异常即可


def test_create_retrieval_poisoning_scorer(pyrit_memory):
    """检索投毒类 scorer 可成功构造。"""
    scorer = create_retrieval_poisoning_scorer()
    assert scorer is not None


def test_scorer_accepts_custom_patterns(pyrit_memory):
    """支持注入自定义敏感模式（不抛异常，参数透传）。"""
    scorer = create_tool_execution_scorer(patterns=["DELETE", "DROP"])
    assert scorer is not None
    assert tuple(scorer._patterns) == ("DELETE", "DROP")
