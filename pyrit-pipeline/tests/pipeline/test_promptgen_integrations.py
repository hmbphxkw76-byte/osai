# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tests for fuzzer_integration.py + gcg_integration.py — 攻击载荷生成器.

测试覆盖:
  - FuzzerGenerationResult: to_seed_groups 转换
  - FuzzerPayloadGenerator: 初始化、_build_converters、generate_async (mock)
  - GCGGenerationResult: to_seed_groups 转换
  - GCGSuffixGenerator: 初始化 (generate_async 需要 torch, 仅测参数)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pipeline.promptgen.fuzzer_integration import (
    FuzzerGenerationResult,
    FuzzerPayloadGenerator,
)
from pipeline.promptgen.gcg_integration import (
    GCGGenerationResult,
    GCGSuffixGenerator,
)


class TestFuzzerGenerationResult:
    """FuzzerGenerationResult 数据类测试."""

    def test_to_seed_groups_empty(self) -> None:
        """空结果转换为空列表."""
        result = FuzzerGenerationResult()
        assert result.to_seed_groups() == []

    def test_to_seed_groups_with_prompts(self) -> None:
        """有变异 prompt 时转换为 AttackSeedGroup 列表."""
        result = FuzzerGenerationResult(
            original_seeds=["seed1"],
            mutated_prompts=["mutated1", "mutated2"],
            rewards=[0.8, 0.6],
        )
        groups = result.to_seed_groups()
        assert len(groups) == 2
        assert len(groups[0].seeds) == 1

    def test_default_values(self) -> None:
        """默认值测试."""
        result = FuzzerGenerationResult()
        assert result.original_seeds == []
        assert result.mutated_prompts == []
        assert result.rewards == []


class TestFuzzerPayloadGenerator:
    """FuzzerPayloadGenerator 单元测试."""

    def test_init_defaults(self) -> None:
        """默认参数初始化."""
        mock_target = MagicMock()
        mock_scorer = MagicMock()
        gen = FuzzerPayloadGenerator(
            target=mock_target,
            scorer=mock_scorer,
        )
        assert gen._target is mock_target
        assert gen._scorer is mock_scorer
        assert gen._max_iterations == 50
        assert gen._min_reward == 0.5

    def test_init_custom_params(self) -> None:
        """自定义参数."""
        mock_target = MagicMock()
        mock_scorer = MagicMock()
        gen = FuzzerPayloadGenerator(
            target=mock_target,
            scorer=mock_scorer,
            max_iterations=100,
            min_reward=0.8,
            frequency_weight=2.0,
            reward_penalty=0.5,
            non_leaf_node_probability=0.1,
        )
        assert gen._max_iterations == 100
        assert gen._min_reward == 0.8

    def test_init_with_custom_converters(self) -> None:
        """自定义 Converter 列表."""
        mock_target = MagicMock()
        mock_scorer = MagicMock()
        custom_converters = [MagicMock(), MagicMock()]
        gen = FuzzerPayloadGenerator(
            target=mock_target,
            scorer=mock_scorer,
            converters=custom_converters,
        )
        assert gen._build_converters() is custom_converters

    @pytest.mark.asyncio
    async def test_generate_async_returns_result(self) -> None:
        """generate_async 返回 FuzzerGenerationResult."""
        mock_target = MagicMock()
        mock_scorer = MagicMock()

        # Mock FuzzerGenerator 类
        mock_fuzzer_instance = MagicMock()
        mock_fuzzer_instance._mcts_explorer = MagicMock()
        mock_node = MagicMock()
        mock_node.template = "mutated prompt"
        mock_node.rewards = 0.9
        mock_fuzzer_instance._mcts_explorer._initial_nodes = [mock_node]
        mock_fuzzer_instance.execute_async = AsyncMock()

        gen = FuzzerPayloadGenerator(
            target=mock_target,
            scorer=mock_scorer,
            max_iterations=5,
        )
        # Mock _build_converters to avoid PyRIT converter_target requirement
        gen._converters = [MagicMock()]

        with patch(
            "pyrit.executor.promptgen.fuzzer.FuzzerGenerator",
            return_value=mock_fuzzer_instance,
        ):
            result = await gen.generate_async(seeds=["original seed"])

        assert len(result.original_seeds) == 1
        assert result.original_seeds[0] == "original seed"
        assert len(result.mutated_prompts) == 1
        assert result.mutated_prompts[0] == "mutated prompt"

    @pytest.mark.asyncio
    async def test_generate_async_fallback_to_seeds(self) -> None:
        """MCTS 提取失败时回退到原始种子."""
        mock_target = MagicMock()
        mock_scorer = MagicMock()

        mock_fuzzer_instance = MagicMock()
        mock_fuzzer_instance._mcts_explorer = MagicMock()
        mock_fuzzer_instance._mcts_explorer._initial_nodes = []
        mock_fuzzer_instance.execute_async = AsyncMock()

        gen = FuzzerPayloadGenerator(
            target=mock_target,
            scorer=mock_scorer,
            max_iterations=5,
        )
        # Mock _build_converters to avoid PyRIT converter_target requirement
        gen._converters = [MagicMock()]

        with patch(
            "pyrit.executor.promptgen.fuzzer.FuzzerGenerator",
            return_value=mock_fuzzer_instance,
        ):
            result = await gen.generate_async(seeds=["fallback seed"])

        assert result.mutated_prompts == ["fallback seed"]
        assert result.rewards == [0.0]


class TestGCGGenerationResult:
    """GCGGenerationResult 数据类测试."""

    def test_to_seed_groups_empty(self) -> None:
        """空结果转换为空列表."""
        result = GCGGenerationResult()
        assert result.to_seed_groups() == []

    def test_to_seed_groups_with_prompts(self) -> None:
        """有组合 prompt 时转换为 AttackSeedGroup 列表."""
        result = GCGGenerationResult(
            goals=["goal1"],
            targets=["target1"],
            suffixes=["suffix1"],
            combined_prompts=["goal1 suffix1"],
        )
        groups = result.to_seed_groups()
        assert len(groups) == 1

    def test_default_values(self) -> None:
        """默认值测试."""
        result = GCGGenerationResult()
        assert result.goals == []
        assert result.targets == []
        assert result.suffixes == []
        assert result.combined_prompts == []


class TestGCGSuffixGenerator:
    """GCGSuffixGenerator 单元测试."""

    def test_init_defaults(self) -> None:
        """默认参数初始化."""
        gen = GCGSuffixGenerator()
        assert gen._model_name == "meta-llama/Llama-2-7b-chat-hf"
        assert gen._device == "cuda:0"
        assert gen._n_steps == 100
        assert gen._batch_size == 128
        assert gen._topk == 256

    def test_init_custom_params(self) -> None:
        """自定义参数."""
        gen = GCGSuffixGenerator(
            model_name="meta-llama/Llama-2-13b-chat-hf",
            device="cpu",
            n_steps=500,
            batch_size=512,
            topk=128,
            control_init="### ### ###",
            hf_token="hf_test_token",
        )
        assert gen._model_name == "meta-llama/Llama-2-13b-chat-hf"
        assert gen._device == "cpu"
        assert gen._n_steps == 500
        assert gen._batch_size == 512
        assert gen._hf_token == "hf_test_token"
