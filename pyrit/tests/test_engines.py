"""
===============================================================================
OffSec AI-300 — engines 模块单元测试
===============================================================================
运行: python -m pytest tests/test_engines.py -v
===============================================================================
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines import (
    classify_case,
    _calc_success_rate,
    _resolve_template,
    PAYLOAD_VARS,
)


class TestClassifyCase:
    """用例分类测试。"""

    def test_probe_case(self):
        case = {"id": "PROBE_01_roleplay_defense", "objective": "test"}
        assert classify_case(case) == "probe"

    def test_probe_case_lowercase(self):
        case = {"id": "probe_01_roleplay_defense", "objective": "test"}
        assert classify_case(case) == "probe"

    def test_crescendo_case(self):
        case = {"id": "multi_crescendo_shell", "multi_turn_objectives": ["step 1", "step 2"]}
        assert classify_case(case) == "crescendo"

    def test_crescendo_empty_multi_turn(self):
        case = {"id": "CAP_001", "multi_turn_objectives": []}
        assert classify_case(case) == "single"

    def test_single_case(self):
        case = {"id": "single_reverse_shell", "objective": "write code"}
        assert classify_case(case) == "single"

    def test_no_multi_turn_key(self):
        case = {"id": "CAP_001_social", "objective": "test"}
        assert classify_case(case) == "single"


class TestCalcSuccessRate:
    """成功率计算测试。"""

    def test_empty_results(self):
        assert _calc_success_rate([]) == 0.0

    def test_all_success(self):
        results = [{"status": "SUCCESS"}, {"status": "SUCCESS"}, {"status": "SUCCESS"}]
        assert _calc_success_rate(results) == 1.0

    def test_mixed_results(self):
        results = [
            {"status": "SUCCESS"},
            {"status": "FAILURE"},
            {"status": "SUCCESS"},
            {"status": "ERROR"},
        ]
        assert _calc_success_rate(results) == 0.5

    def test_no_success(self):
        results = [{"status": "FAILURE"}, {"status": "FAILURE"}, {"status": "ERROR"}]
        assert _calc_success_rate(results) == 0.0


class TestResolveTemplate:
    """模板变量解析测试。"""

    def test_no_placeholders(self):
        assert _resolve_template("hello world") == "hello world"

    def test_empty_string(self):
        assert _resolve_template("") == ""

    def test_none_input(self):
        assert _resolve_template(None) is None

    def test_simple_placeholder(self):
        PAYLOAD_VARS.clear()
        PAYLOAD_VARS["name"] = "Alice"
        assert _resolve_template("Hello {name}!") == "Hello Alice!"

    def test_unmatched_placeholder(self):
        PAYLOAD_VARS.clear()
        assert _resolve_template("Hello {unknown}!") == "Hello {unknown}!"

    def test_multiple_placeholders(self):
        PAYLOAD_VARS.clear()
        PAYLOAD_VARS["a"] = "1"
        PAYLOAD_VARS["b"] = "2"
        assert _resolve_template("{a} + {b} = 3") == "1 + 2 = 3"

    def test_extra_vars_override(self):
        PAYLOAD_VARS.clear()
        PAYLOAD_VARS["x"] = "default"
        assert _resolve_template("x={x}", extra_vars={"x": "override"}) == "x=override"

    def test_json_braces_not_resolved(self):
        PAYLOAD_VARS.clear()
        text = '{"key": "value", "nested": {"inner": 1}}'
        assert _resolve_template(text) == text
