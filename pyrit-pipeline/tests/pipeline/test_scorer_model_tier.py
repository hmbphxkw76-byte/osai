# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_scorer_model_tier — 评分器模型分层检测单元测试。.

覆盖 v38 评分器模型分层策略:
  - T1 金标准: GPT-4o, Claude-3.5
  - T2 推荐: Qwen2.5-72B, Llama-3.1-70B
  - T3 可用: DeepSeek-V3 via SiliconFlow, 小参数模型
  - 未知模型: 保守 T3 + response_parser.py 兜底

学术依据:
  - HarmBench (arXiv:2402.04249) §4.3: F1>0.9 时 ASR 可信
  - LLM-as-a-Judge (arXiv:2306.05685): 70B+ 模型一致性 80%+

> **日期**: 2026-8-13
"""

from __future__ import annotations

import pytest

from pipeline.stages.stage_init import (
    _JSON_MODE_SUPPORTED_HOSTS,
    _detect_scorer_model_tier,
    _is_json_mode_supported,
)


class TestScorerModelTierDetection:
    """评分器模型分层检测测试。."""

    # ── T1 金标准 ──

    @pytest.mark.parametrize(
        "model_name",
        [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-4",
            "GPT-4o",
            "claude-3-5-sonnet",
            "claude-3-5-haiku",
            "Claude-3-5-Sonnet-20241022",
        ],
    )
    def test_t1_gold_standard(self, model_name: str) -> None:
        """T1 金标准模型: JSON 100% 遵从。."""
        tier, desc = _detect_scorer_model_tier(model_name)
        assert tier == "T1", f"{model_name} should be T1, got {tier}"
        assert "金标准" in desc

    # ── T2 推荐 ──

    @pytest.mark.parametrize(
        "model_name",
        [
            "Qwen/Qwen2.5-72B-Instruct",
            "Qwen/Qwen2.5-32B-Instruct",
            "qwen-max",
            "deepseek-chat",
            "deepseek-v3",
            "llama-3.1-70b",
            "llama-3.1-405b",
            "meta-llama/Llama-3.1-70B-Instruct",
        ],
    )
    def test_t2_recommended(self, model_name: str) -> None:
        """T2 推荐模型: JSON 遵从度高。."""
        tier, desc = _detect_scorer_model_tier(model_name)
        assert tier == "T2", f"{model_name} should be T2, got {tier}"
        assert "推荐" in desc

    # ── T3 可用 ──

    @pytest.mark.parametrize(
        "model_name",
        [
            "deepseek-ai/DeepSeek-V3",
            "Qwen/Qwen2.5-7B-Instruct",
            "qwen-2.5-7b",
            "llama-3-8b",
            "mistral-7b",
            "gpt-3.5-turbo",
        ],
    )
    def test_t3_usable(self, model_name: str) -> None:
        """T3 可用模型: JSON 不稳定, 需 response_parser.py 兜底。."""
        tier, desc = _detect_scorer_model_tier(model_name)
        assert tier == "T3", f"{model_name} should be T3, got {tier}"
        assert "可用" in desc or "不稳定" in desc or "过时" in desc

    # ── 未知模型 ──

    def test_unknown_model_defaults_to_t3(self) -> None:
        """未知模型默认为 T3 (保守策略)。."""
        tier, desc = _detect_scorer_model_tier("some-random-model-xyz")
        assert tier == "T3"
        assert "未知" in desc or "未验证" in desc

    def test_empty_model_name(self) -> None:
        """空模型名返回 T3。."""
        tier, desc = _detect_scorer_model_tier("")
        assert tier == "T3"

    def test_none_like_model_name(self) -> None:
        """None-like 模型名返回 T3。."""
        tier, _ = _detect_scorer_model_tier(None)  # type: ignore[arg-type]
        assert tier == "T3"

    # ── 大小写不敏感 ──

    def test_case_insensitive_matching(self) -> None:
        """模型名匹配不区分大小写。."""
        assert _detect_scorer_model_tier("QWEN/QWEN2.5-72B-INSTRUCT")[0] == "T2"
        assert _detect_scorer_model_tier("GPT-4O")[0] == "T1"
        assert _detect_scorer_model_tier("CLAUDE-3-5-SONNET")[0] == "T1"


class TestJsonModeSupportedHosts:
    """JSON mode 端点白名单测试。."""

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://api.openai.com/v1",
            "https://my-resource.openai.azure.com/openai/deployments/gpt-4o",
            "https://api.siliconflow.cn/v1",
            "https://integrate.api.nvidia.com/v1",
            "https://api.deepseek.com/v1",
            "https://api.anthropic.com/v1",
            "https://api.groq.com/openai/v1",
            "https://api.together.xyz/v1",
        ],
    )
    def test_known_endpoints_supported(self, endpoint: str) -> None:
        """已知端点支持 JSON mode。."""
        assert _is_json_mode_supported(endpoint) is True

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://api.unknown-provider.com/v1",
            "https://custom-llm.example.com/v1",
            "https://localhost:8080/v1",
        ],
    )
    def test_unknown_endpoints_not_supported(self, endpoint: str) -> None:
        """未知端点不支持 JSON mode (使用客户端解析兜底)。."""
        assert _is_json_mode_supported(endpoint) is False

    def test_empty_endpoint(self) -> None:
        """空端点返回 False。."""
        assert _is_json_mode_supported("") is False
        assert _is_json_mode_supported(None) is False  # type: ignore[arg-type]

    def test_all_supported_hosts_in_frozenset(self) -> None:
        """验证 _JSON_MODE_SUPPORTED_HOSTS 包含 v38 新增端点。."""
        expected_hosts = {
            "api.openai.com",
            "openai.azure.com",
            "api.siliconflow.cn",
            "integrate.api.nvidia.com",
            "api.deepseek.com",
            "api.anthropic.com",
            "api.groq.com",
            "api.together.xyz",
        }
        assert expected_hosts.issubset(_JSON_MODE_SUPPORTED_HOSTS)
