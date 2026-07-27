# -*- coding: utf-8 -*-
"""
GiskardAdapter 单元测试
"""

from unittest.mock import MagicMock, patch

import pytest

from ai300_eval.adapters.base import EvalStrategy
from ai300_eval.adapters.giskard_adapter import GiskardAdapter
from ai300_schemas import PyRITTargetConfig


def test_giskard_adapter_is_available_when_installed():
    """Giskard 可导入时，is_available 返回 True"""
    adapter = GiskardAdapter({})
    # 模拟 _load_giskard 成功返回一个对象
    with patch.object(adapter, "_load_giskard", return_value=MagicMock()):
        assert adapter.is_available() is True


def test_giskard_adapter_is_unavailable_when_missing():
    """Giskard 未安装时，is_available 返回 False"""
    adapter = GiskardAdapter({})
    with patch.object(
        adapter,
        "_load_giskard",
        side_effect=RuntimeError("not installed"),
    ):
        assert adapter.is_available() is False


def test_giskard_adapter_run_returns_error_when_missing():
    """Giskard 未安装时 run 返回错误结果"""
    adapter = GiskardAdapter({})
    with patch.object(
        adapter,
        "_load_giskard",
        side_effect=RuntimeError("Giskard is not installed"),
    ):
        result = adapter.run(
            PyRITTargetConfig(endpoint="https://example.com/v1/chat"),
            EvalStrategy(name="robustness"),
        )
    assert result.success is False
    assert "Giskard is not installed" in result.error


def test_call_endpoint_parses_openai_response():
    """_call_endpoint 正确解析 OpenAI 兼容响应"""
    adapter = GiskardAdapter({})
    target = PyRITTargetConfig(
        endpoint="https://example.com/v1/chat/completions",
        model_name="gpt-4",
        api_key="sk-test",
    )
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "Paris",
                },
            }
        ]
    }

    with patch("ai300_eval.adapters.giskard_adapter.httpx.post", return_value=mock_response) as mock_post:
        output = adapter._call_endpoint(target, "What is the capital of France?")

    assert output == "Paris"
    # 确认请求构造正确
    call_args = mock_post.call_args
    assert call_args.kwargs["json"]["model"] == "gpt-4"
    assert call_args.kwargs["headers"]["Authorization"] == "Bearer sk-test"


def test_parse_scan_report_extracts_issues():
    """_parse_scan_report 从 Giskard 报告对象中提取 issue 并转换为发现"""
    adapter = GiskardAdapter({})

    fake_issue = MagicMock()
    fake_issue.category = MagicMock()
    fake_issue.category.name = "robustness"
    fake_issue.description = "Model is vulnerable to prompt injection."
    fake_issue.title = "Prompt injection issue"
    fake_issue.examples = None
    fake_issue.meta = {"scan_category": "robustness"}

    fake_report = MagicMock()
    fake_report.issues = [fake_issue]

    target = PyRITTargetConfig(endpoint="https://example.com/v1/chat/completions")
    findings = adapter._parse_scan_report(fake_report, target)

    assert len(findings) == 1
    assert findings[0].source_tool == "giskard"
    assert findings[0].category == "robustness"
    assert findings[0].owasp_llm_id == "LLM01:2025"
