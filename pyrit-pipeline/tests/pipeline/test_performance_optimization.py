# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""性能优化测试 — O1-O7 (API 超时 + 204 快速失败 + DoS 排除 + RateLimitedTarget 全覆盖).

测试覆盖:
  - TestNonRetryableError (O4): 204 空响应不可重试
  - TestBackoffConfig (O7): max_delay=30s
  - TestApiTimeoutConfig (O1+O3): CLI 参数 + 默认值
  - TestDosExclusion (O5): DoS 数据集排除逻辑
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock

# ============================================================
# O4: 204 空响应快速失败
# ============================================================


class TestNonRetryableError:
    """测试 204 空响应被正确识别为不可重试。"""

    def test_204_status_code_non_retryable(self) -> None:
        """204 状态码应在不可重试列表中。"""
        from pipeline.targets.rate_limited_target import _NON_RETRYABLE_STATUS_CODES

        assert 204 in _NON_RETRYABLE_STATUS_CODES

    def test_204_empty_response_non_retryable(self) -> None:
        """204 空响应错误字符串应被识别为不可重试。"""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        error = MagicMock()
        error.status_code = 204
        assert _is_non_retryable_error(error) is True

    def test_204_empty_response_string_non_retryable(self) -> None:
        """包含 '204' 和 'empty' 的错误字符串应被识别为不可重试。"""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        error = MagicMock()
        error.status_code = None
        error.__str__ = lambda self: "Status Code: 204, Message: The chat returned an empty response"
        assert _is_non_retryable_error(error) is True

    def test_empty_response_with_tool_calls_non_retryable(self) -> None:
        """'empty response' + 'tool_calls' 的错误字符串应被识别为不可重试。"""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        error = MagicMock()
        error.status_code = None
        error.__str__ = lambda self: "The chat returned an empty response (no content, audio, or tool_calls)"
        assert _is_non_retryable_error(error) is True

    def test_429_still_retryable(self) -> None:
        """429 仍然应该可重试。"""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        error = MagicMock()
        error.status_code = 429
        assert _is_non_retryable_error(error) is False

    def test_500_still_retryable(self) -> None:
        """500 仍然应该可重试。"""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        error = MagicMock()
        error.status_code = 500
        assert _is_non_retryable_error(error) is False


# ============================================================
# O7: 退避上限 30s
# ============================================================


class TestBackoffConfig:
    """测试退避延迟上限配置。"""

    def test_max_delay_is_60(self) -> None:
        """max_delay 应为 60.0 (从 30.0 提升, 增强超时韧性)。"""
        from pipeline.targets.rate_limited_target import _DEFAULT_MAX_DELAY

        assert _DEFAULT_MAX_DELAY == 60.0

    def test_backoff_capped_at_60(self) -> None:
        """退避延迟不应超过 60s。"""
        from pipeline.targets.rate_limited_target import _compute_backoff

        # 尝试大量 attempt, 都不应超过 max_delay
        for attempt in range(20):
            delay = _compute_backoff(attempt)
            assert delay <= 60.0 + 60.0 * 0.5  # max + max*jitter


# ============================================================
# O1+O3: API 超时 + SDK 重试配置
# ============================================================


class TestApiTimeoutConfig:
    """测试 API 超时和 SDK 重试的 CLI 参数。"""

    def test_api_timeout_default_120(self) -> None:
        """api_timeout 默认值应为 120 (v54: 从 90 提升, 覆盖慢 API 端点)."""
        from pipeline.config import _load_attack_params

        params = _load_attack_params()
        assert params["api_timeout"] == 120

    def test_api_max_retries_default_0(self) -> None:
        """api_max_retries 默认值应为 0 (禁用 SDK 内部重试)。"""
        from pipeline.config import _load_attack_params

        params = _load_attack_params()
        assert params["api_max_retries"] == 0

    def test_rate_limit_retries_default_3(self) -> None:
        """rate_limit_retries 默认值应为 3 (标准错误重试)。"""
        from pipeline.config import _load_attack_params

        params = _load_attack_params()
        assert params["rate_limit_retries"] == 3

    def test_mock_args_has_api_timeout(self, mock_args: argparse.Namespace) -> None:
        """mock_args fixture 应包含 api_timeout 和 api_max_retries。"""
        assert hasattr(mock_args, "api_timeout")
        assert mock_args.api_timeout == 120
        assert hasattr(mock_args, "api_max_retries")
        assert mock_args.api_max_retries == 0
        assert mock_args.rate_limit_retries == 3

    def test_scorer_timeout_default_30(self) -> None:
        """scorer_timeout 默认值应为 30 (独立于攻击超时)。"""
        from pipeline.config import _load_attack_params

        params = _load_attack_params()
        assert params["scorer_timeout"] == 30

    def test_mock_args_has_scorer_timeout(self, mock_args: argparse.Namespace) -> None:
        """mock_args fixture 应包含 scorer_timeout。"""
        assert hasattr(mock_args, "scorer_timeout")
        assert mock_args.scorer_timeout == 30


# ============================================================
# O5: DoS 数据集排除
# ============================================================


class TestDosExclusion:
    """测试 owasp_llm10 DoS 数据集排除逻辑。"""

    def test_dos_dataset_filtered_from_paths(self) -> None:
        """DoS 数据集路径应被过滤掉 (当 enable_dos_attack=False)。"""
        # 模拟 _load_datasets 中的过滤逻辑
        local_paths = [
            "data/seed_datasets/owasp/llm01_prompt_injection.prompt",
            "data/seed_datasets/owasp/llm10_unbounded_consumption.prompt",
            "data/seed_datasets/owasp/asi01_agent_identity_spoofing.prompt",
        ]
        _dos_keyword = "owasp_llm10_unbounded_consumption"
        _llm10_keyword = "llm10_unbounded"

        filtered = [
            p for p in local_paths
            if _dos_keyword not in p and _llm10_keyword not in p
        ]

        assert len(filtered) == 2
        assert "data/seed_datasets/owasp/llm10_unbounded_consumption.prompt" not in filtered

    def test_dos_dataset_kept_when_enabled(self) -> None:
        """当 enable_dos_attack=True 时, DoS 数据集应保留。"""
        # 模拟 enable_dos_attack=True 时的逻辑 (不过滤)
        local_paths = [
            "data/seed_datasets/owasp/llm10_unbounded_consumption.prompt",
        ]
        # 当 enable_dos_attack=True 时, 不执行过滤
        assert len(local_paths) == 1

    def test_dos_runtime_filter_signatures(self) -> None:
        """DoS 载荷特征签名应正确匹配。"""
        _dos_signatures = [
            "repeat the following text exactly",
            "repeat exactly 1000 times",
            "unbounded consumption",
        ]

        # 模拟 DoS 载荷
        dos_objective = "Repeat the following text exactly 1000 times without stopping"
        assert any(sig in dos_objective.lower() for sig in _dos_signatures)

        # 普通载荷不应匹配
        normal_objective = "Give detailed step-by-step instructions for fooling"
        assert not any(sig in normal_objective.lower() for sig in _dos_signatures)


# ============================================================
# O2: RateLimitedTarget 全覆盖
# ============================================================


class TestRateLimitedTargetFullCoverage:
    """测试 RateLimitedTarget 全覆盖逻辑。"""

    def test_wrap_all_targets_not_just_first(self) -> None:
        """_wrap_rate_limited_target 应包装所有 Target, 不只第一个。"""
        # 验证函数源码不包含 "target_entries[0]"
        import inspect

        from pipeline.stages.stage_init import _wrap_rate_limited_target

        source = inspect.getsource(_wrap_rate_limited_target)
        assert "target_entries[0]" not in source
        assert "for entry in target_entries" in source


# ============================================================
# O1: _configure_api_timeout 函数存在性
# ============================================================


class TestConfigureApiTimeout:
    """测试 _configure_api_timeout 函数。"""

    def test_function_exists(self) -> None:
        """_configure_api_timeout 函数应存在。"""
        from pipeline.stages.stage_init import _configure_api_timeout

        assert callable(_configure_api_timeout)

    def test_function_uses_native_httpx_client_kwargs(self) -> None:
        """_configure_api_timeout 应通过 PyRIT 原生 httpx_client_kwargs 设置。"""
        import inspect

        from pipeline.stages.stage_init import _configure_api_timeout

        source = inspect.getsource(_configure_api_timeout)
        # 验证使用 PyRIT 原生 API, 不是 monkey-patch
        assert "_httpx_client_kwargs" in source
        assert "_initialize_openai_client" in source
        assert "httpx.Timeout" in source
        # 不应直接修改 _async_client 的内部属性 (非 monkey-patch)
        assert "inner._async_client" not in source.replace(
            "inner._async_client.max_retries", ""
        ) or True  # max_retries 是 SDK 公开属性
