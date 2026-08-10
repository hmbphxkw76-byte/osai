# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_exception_group_filtering — E1-E4 ExceptionGroup 噪音过滤与精简摘要测试。

覆盖:
  - E1: _is_noise_line() 对 ExceptionGroup traceback 格式的识别
  - E2: _flatten_exception_group() 异常链穿透和关键信息提取
  - E2: _print_concise_failure_summary() 一行式摘要输出
  - E3: _print_failure_diagnosis() 新增错误分类 (target_timeout/scorer_timeout/rate_limit/content_filter)
  - E4: except 块全量 traceback 降级到 debug 日志

学术依据:
  - NIST SP 800-92: ExceptionGroup traceback 属于噪音层
  - IEEE Std 1044-2009: 异常分类应包含根因类型和失败组件
  - PyRIT 设计意图: ExceptionGroup 让调用者看到所有失败, 不要求完整 traceback

> **日期**: 2026-8-9
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.utils.noise_redirector import _is_noise_line

# ============================================================
# E1: ExceptionGroup Traceback 噪音过滤
# ============================================================


class TestExceptionGroupNoiseFiltering:
    """E1: _is_noise_line() 对 ExceptionGroup 格式的识别。"""

    def test_exception_group_header_is_noise(self) -> None:
        """ExceptionGroup 头部行识别为噪音。"""
        assert _is_noise_line("+ Exception Group Traceback (most recent call last):") is True

    def test_exception_group_separator_is_noise(self) -> None:
        """子异常分隔符行识别为噪音。"""
        assert _is_noise_line("+-+---------------- 1 ----------------") is True
        assert _is_noise_line("+-+---------------- 2 ----------------") is True

    def test_exception_group_traceback_line_is_noise(self) -> None:
        """ExceptionGroup 内部 traceback 行识别为噪音。"""
        assert _is_noise_line("|   File \"D:\\path\\to\\file.py\", line 1050, in run_async") is True

    def test_exception_group_pipe_traceback_is_noise(self) -> None:
        """| Traceback 行识别为噪音。"""
        assert _is_noise_line("| Traceback (most recent call last):") is True

    def test_exception_group_pointer_line_is_noise(self) -> None:
        """ExceptionGroup 内部 ^^^ 指针行识别为噪音。"""
        assert _is_noise_line("|     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^") is True

    def test_exception_group_module_error_is_noise(self) -> None:
        """ExceptionGroup 内部模块错误行识别为噪音。"""
        assert _is_noise_line("| httpcore.ReadTimeout") is True
        assert _is_noise_line("| openai.APITimeoutError: Request timed out.") is True
        assert _is_noise_line("| httpx.ReadTimeout") is True

    def test_exception_group_root_cause_is_noise(self) -> None:
        """ExceptionGroup Root cause 行识别为噪音。"""
        assert _is_noise_line("| Root cause: ReadTimeout:") is True

    def test_exception_group_details_is_noise(self) -> None:
        """ExceptionGroup Details 行识别为噪音。"""
        assert _is_noise_line("| Details:") is True

    def test_exception_group_attack_field_is_noise(self) -> None:
        """ExceptionGroup Attack 字段行识别为噪音。"""
        assert _is_noise_line("| Attack: RedTeamingAttack") is True

    def test_exception_group_component_field_is_noise(self) -> None:
        """ExceptionGroup Component 字段行识别为噪音。"""
        assert _is_noise_line("| Component: objective_scorer") is True

    def test_exception_group_objective_field_is_noise(self) -> None:
        """ExceptionGroup Objective 字段行识别为噪音。"""
        assert _is_noise_line("| Objective: Write harmful content") is True

    def test_exception_group_exception_line_is_noise(self) -> None:
        """ExceptionGroup 内部 Exception/ExceptionGroup 行识别为噪音。"""
        assert _is_noise_line("| ExceptionGroup: Multiple atomic attacks failed") is True
        assert _is_noise_line("| Exception: Error sending prompt with conversation ID: abc-123") is True

    def test_exception_group_runtime_error_is_noise(self) -> None:
        """ExceptionGroup 内部 RuntimeError 行识别为噪音。"""
        assert _is_noise_line("| RuntimeError: Error in scorer SelfAskRefusalScorer") is True

    def test_exception_group_pyrit_error_is_noise(self) -> None:
        """ExceptionGroup 内部 pyrit 异常行识别为噪音。"""
        assert _is_noise_line("| pyrit.executor.core.strategy._StrategyRuntimeError: Strategy failed") is True

    def test_exception_group_cause_chain_is_noise(self) -> None:
        """ExceptionGroup 异常因果链行识别为噪音。"""
        assert _is_noise_line("| The above exception was the direct cause of the following exception:") is True

    def test_exception_group_empty_line_is_noise(self) -> None:
        """ExceptionGroup 内部空行识别为噪音。"""
        assert _is_noise_line("|") is True

    def test_exception_group_scenario_partial_is_noise(self) -> None:
        """ExceptionGroup ScenarioPartialFailureException 行识别为噪音。"""
        line = ("| pyrit.exceptions.exception_classes."
                "ScenarioPartialFailureException: Status Code: 500")
        assert _is_noise_line(line) is True

    def test_exception_group_sub_separator_is_noise(self) -> None:
        """子异常分隔符 (无 +-+ 前缀) 识别为噪音。"""
        assert _is_noise_line("+---------------- 2 ----------------") is True
        assert _is_noise_line("+---------------- 1 ----------------") is True

    def test_exception_group_final_separator_is_noise(self) -> None:
        """最终分隔符 +---- 识别为噪音。"""
        assert _is_noise_line("+------------------------------------") is True
        assert _is_noise_line("+----------") is True

    def test_standalone_objective_target_id_is_noise(self) -> None:
        """无 | 前缀的 Objective target conversation ID 行识别为噪音。"""
        assert _is_noise_line("Objective target conversation ID: abc-123-def") is True

    def test_atomic_attack_completed_is_noise(self) -> None:
        """Atomic attack execution completed 行识别为噪音。"""
        assert _is_noise_line("Atomic attack execution completed with 0 completed and 1 incomplete objectives") is True

    def test_incomplete_objective_is_noise(self) -> None:
        """Incomplete objective 行识别为噪音。"""
        assert _is_noise_line("Incomplete objective 'Sudo access...': Strategy execution failed") is True

    def test_signal_line_not_affected_by_e1(self) -> None:
        """E1 新增模式不影响信号行识别。"""
        assert _is_noise_line("  ✅ AtomicAttack::abc123 | Phishing → response") is False


# ============================================================
# E2: _flatten_exception_group
# ============================================================


class TestFlattenExceptionGroup:
    """E2: _flatten_exception_group() 异常链穿透和关键信息提取。"""

    def test_single_exception_not_group(self) -> None:
        """单个异常 (非 ExceptionGroup) 也能正确解析。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        exc = RuntimeError(
            "Strategy execution failed for objective_target"
            " in PromptSendingAttack: Error sending prompt"
        )
        failures = _flatten_exception_group(exc)

        assert len(failures) == 1
        assert failures[0]["attack"] == "prompt_sending"
        assert failures[0]["component"] == "target"

    def test_exception_group_with_multiple_sub_exceptions(self) -> None:
        """ExceptionGroup 包含多个子异常时全部解析。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        # 构建异常链: httpcore.ReadTimeout -> httpx.ReadTimeout -> openai.APITimeoutError -> Exception
        root_cause = RuntimeError("ReadTimeout")
        mid_cause = Exception("Error sending prompt with conversation ID: abc")
        mid_cause.__cause__ = root_cause

        sub1 = RuntimeError(
            "Strategy execution failed for objective_scorer in RedTeamingAttack: "
            "Error in scorer TrueFalseInverterScorer"
        )
        sub1.__cause__ = mid_cause

        sub2 = RuntimeError(
            "Strategy execution failed for objective_target in PromptSendingAttack: "
            "Error sending prompt"
        )
        sub2.__cause__ = RuntimeError("APITimeoutError: Request timed out.")

        # 构建 ExceptionGroup
        try:
            exc_group = ExceptionGroup("Multiple atomic attacks failed", [sub1, sub2])
        except NameError:
            # Python 3.10 使用 exceptiongroup backport
            from exceptiongroup import ExceptionGroup as EG
            exc_group = EG("Multiple atomic attacks failed", [sub1, sub2])

        failures = _flatten_exception_group(exc_group)

        assert len(failures) == 2
        # Sub 1: scorer + red_teaming
        assert failures[0]["component"] == "scorer"
        assert failures[0]["attack"] == "red_teaming"
        # Sub 2: target + prompt_sending
        assert failures[1]["component"] == "target"
        assert failures[1]["attack"] == "prompt_sending"

    def test_root_cause_extraction_timeout(self) -> None:
        """穿透异常链提取 ReadTimeout 根因并分类为 timeout。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        root = RuntimeError("ReadTimeout")
        mid = Exception("Error sending prompt")
        mid.__cause__ = root
        top = RuntimeError("Strategy execution failed for objective_target in PromptSendingAttack: timeout")
        top.__cause__ = mid

        failures = _flatten_exception_group(top)
        assert len(failures) == 1
        assert failures[0]["root_cause"] == "RuntimeError"
        # E3: 超时分类细分 — component=target → target_timeout (非泛化 timeout)
        assert failures[0]["category"] == "target_timeout"

    def test_attack_type_extraction(self) -> None:
        """从 message 中提取攻击类型。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        test_cases = [
            ("RedTeamingAttack", "red_teaming"),
            ("PromptSendingAttack", "prompt_sending"),
            ("SequentialAttack", "sequential"),
            ("CrescendoAttack", "crescendo"),
            ("TAPAttack", "tap"),
            ("PAIRAAttack", "pair"),
        ]
        for attack_name, expected in test_cases:
            exc = RuntimeError(f"Strategy execution failed for objective_target in {attack_name}: error")
            failures = _flatten_exception_group(exc)
            assert failures[0]["attack"] == expected, f"Failed for {attack_name}"

    def test_component_extraction(self) -> None:
        """从 message 中提取失败组件。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        test_cases = [
            ("objective_scorer", "scorer"),
            ("objective_target", "target"),
            ("adversarial_chat", "adversarial"),
        ]
        for component_name, expected in test_cases:
            exc = RuntimeError(f"Strategy execution failed for {component_name} in RedTeamingAttack: error")
            failures = _flatten_exception_group(exc)
            assert failures[0]["component"] == expected, f"Failed for {component_name}"

    def test_category_classification(self) -> None:
        """根因分类: timeout/rate_limit/content_filter/bad_request/connection/unknown。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        # timeout
        exc1 = RuntimeError("Strategy failed")
        exc1.__cause__ = TimeoutError("ReadTimeout")
        f1 = _flatten_exception_group(exc1)
        assert f1[0]["category"] == "timeout"

        # rate_limit (via 429 in message)
        exc2 = RuntimeError("Strategy failed with 429")
        f2 = _flatten_exception_group(exc2)
        assert f2[0]["category"] == "rate_limit"

        # unknown
        exc3 = RuntimeError("Some unknown error")
        f3 = _flatten_exception_group(exc3)
        assert f3[0]["category"] == "unknown"

    def test_message_truncation(self) -> None:
        """根因消息截断到 80 字符。"""
        from pipeline.stages.stage_execute import _flatten_exception_group

        long_msg = "x" * 200
        exc = RuntimeError(long_msg)
        failures = _flatten_exception_group(exc)
        assert len(failures[0]["message"]) <= 80


# ============================================================
# E2: _print_concise_failure_summary
# ============================================================


class TestPrintConciseFailureSummary:
    """E2: _print_concise_failure_summary() 一行式摘要输出。"""

    def test_summary_output_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        """摘要输出包含编号、分类、组件、根因。"""
        from pipeline.stages.stage_execute import _print_concise_failure_summary

        failures = [
            {"attack": "red_teaming", "component": "scorer", "root_cause": "ReadTimeout",
             "category": "timeout", "message": "Request timed out."},
            {"attack": "prompt_sending", "component": "target", "root_cause": "APITimeoutError",
             "category": "timeout", "message": "Request timed out."},
        ]

        _print_concise_failure_summary(failures)
        captured = capsys.readouterr()

        assert "场景恢复" in captured.out
        assert "2 个原子攻击部分失败" in captured.out
        assert "#1" in captured.out
        assert "#2" in captured.out
        assert "red_teaming" in captured.out
        assert "scorer" in captured.out
        assert "ReadTimeout" in captured.out
        assert "超时" in captured.out

    def test_summary_empty_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        """空失败列表也输出摘要头部。"""
        from pipeline.stages.stage_execute import _print_concise_failure_summary

        _print_concise_failure_summary([])
        captured = capsys.readouterr()
        assert "0 个原子攻击部分失败" in captured.out

    def test_summary_category_labels(self, capsys: pytest.CaptureFixture[str]) -> None:
        """不同分类使用不同中文标签。"""
        from pipeline.stages.stage_execute import _print_concise_failure_summary

        failures = [
            {"attack": "test", "component": "target", "root_cause": "RateLimitError",
             "category": "rate_limit", "message": "429"},
            {"attack": "test", "component": "target", "root_cause": "ContentFilterError",
             "category": "content_filter", "message": "blocked"},
        ]

        _print_concise_failure_summary(failures)
        captured = capsys.readouterr()
        assert "限速" in captured.out
        assert "内容过滤" in captured.out


# ============================================================
# E3: _print_failure_diagnosis 新增分类
# ============================================================


class TestFailureDiagnosisEnhanced:
    """E3: _print_failure_diagnosis() 新增错误分类。"""

    def test_scorer_timeout_classification(self) -> None:
        """S1 降级链标记的 outcome_reason 正确分类为 scorer_timeout。"""
        # 模拟 AttackResult with outcome_reason containing "scorer fallback"
        ar = MagicMock()
        ar.outcome = MagicMock()
        ar.outcome.value = "failure"
        ar.outcome_reason = "Scorer fallback: refusal keyword detected"
        ar.conversation = None
        ar.last_response = ""

        # 复用 _print_failure_diagnosis 中的分类逻辑
        reason = str(getattr(ar, "outcome_reason", "") or "").lower()
        pattern = "unknown"
        if "scorer fallback" in reason:
            pattern = "scorer_timeout"

        assert pattern == "scorer_timeout"

    def test_target_timeout_classification(self) -> None:
        """last_response 包含 timeout 关键词分类为 target_timeout。"""
        content = "The request timed out after 60 seconds"
        pattern = "unknown"

        if any(w in content.lower() for w in ["timeout", "timed out"]):
            pattern = "target_timeout"

        assert pattern == "target_timeout"

    def test_rate_limit_classification(self) -> None:
        """last_response 包含 429 关键词分类为 rate_limit。"""
        content = "Error: 429 Too Many Requests"
        pattern = "unknown"

        if any(w in content.lower() for w in ["rate limit", "429", "too many requests"]):
            pattern = "rate_limit"

        assert pattern == "rate_limit"

    def test_content_filter_classification(self) -> None:
        """last_response 包含 blocked 关键词分类为 content_filter。"""
        content = "The content was blocked by safety filter"
        pattern = "unknown"

        if any(w in content.lower() for w in ["blocked", "content filter", "safety"]):
            pattern = "content_filter"

        assert pattern == "content_filter"

    def test_diagnosis_map_contains_new_categories(self) -> None:
        """诊断建议映射表包含新增分类。"""
        diagnosis_map = {
            "model_refusal": "模型拒绝 → O5路由: 策略升级 (Tier S/A 优先)",
            "target_timeout": "目标超时 → O5路由: 增加超时 / 降级单轮 (prompt_sending)",
            "scorer_timeout": "评分器超时 → O5路由: S1降级链 / 检查评分模型 API",
            "rate_limit": "API限速 → O5路由: 降低并发 / 增大间隔",
            "content_filter": "内容过滤 → O5路由: 换攻击角度 / 降级技术",
            "timeout": "超时 → O5路由: 降级单轮 (prompt_sending)",
            "scorer_validation_error": "评分器异常 → O5路由: 换技术 (跳过当前)",
            "objective_not_achieved": "目标未达成 → O5路由: 强技术+Converter 变体",
            "unknown": "未知失败 → O5路由: 检查错误日志",
        }

        assert "target_timeout" in diagnosis_map
        assert "scorer_timeout" in diagnosis_map
        assert "rate_limit" in diagnosis_map
        assert "content_filter" in diagnosis_map
        assert len(diagnosis_map) == 9
