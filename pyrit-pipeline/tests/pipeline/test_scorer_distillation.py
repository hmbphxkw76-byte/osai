# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""P8: 评分器量化蒸馏框架单元测试.

测试覆盖:
  - DistillationConfig: 默认配置
  - export_training_data: 训练数据导出
  - prepare_distillation_config: 配置生成
  - load_distilled_scorer: 惰性加载
  - DistilledScorerWrapper: PyRIT Score 接口兼容
  - DistilledScore: Score 接口

学术依据:
  - Hinton et al. (arXiv:1503.02531): 知识蒸馏
  - FrugalGPT (arXiv:2305.02415): 级联路由 + 小模型

> **日期**: 2026-8-16
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pipeline.scoring.scorer_distillation import (
    DistillationConfig,
    DistilledScore,
    DistilledScorerWrapper,
    export_training_data,
    load_distilled_scorer,
    prepare_distillation_config,
)

# ============================================================
# DistillationConfig 测试
# ============================================================


class TestDistillationConfig:
    """P8: DistillationConfig 默认配置测试."""

    def test_default_config(self) -> None:
        """默认配置值正确."""
        config = DistillationConfig()
        assert config.base_model == "Qwen/Qwen3-0.5B"
        assert config.lora_r == 8
        assert config.lora_alpha == 16
        assert config.lora_dropout == 0.05
        assert config.epochs == 5
        assert config.learning_rate == 2e-4
        assert config.batch_size == 8
        assert config.max_length == 1024
        assert config.min_confidence_threshold == 0.85

    def test_custom_config(self) -> None:
        """自定义配置覆盖默认值."""
        config = DistillationConfig(
            base_model="microsoft/Phi-3-mini",
            lora_r=16,
            epochs=10,
        )
        assert config.base_model == "microsoft/Phi-3-mini"
        assert config.lora_r == 16
        assert config.epochs == 10
        # 未覆盖的保持默认
        assert config.lora_alpha == 16
        assert config.batch_size == 8


class TestPrepareDistillationConfig:
    """P8: prepare_distillation_config 配置生成测试."""

    def test_default_preparation(self) -> None:
        """默认配置生成."""
        config = prepare_distillation_config()
        assert isinstance(config, DistillationConfig)
        assert config.base_model == "Qwen/Qwen3-0.5B"

    def test_custom_preparation(self) -> None:
        """自定义参数覆盖."""
        config = prepare_distillation_config(
            "microsoft/Phi-3-mini",
            lora_r=32,
            learning_rate=1e-4,
        )
        assert config.base_model == "microsoft/Phi-3-mini"
        assert config.lora_r == 32
        assert config.learning_rate == 1e-4

    def test_invalid_kwargs_ignored(self) -> None:
        """无效 kwargs 被忽略."""
        config = prepare_distillation_config(
            "Qwen/Qwen3-0.5B",
            invalid_param="test",
        )
        assert isinstance(config, DistillationConfig)


# ============================================================
# export_training_data 测试
# ============================================================


class TestExportTrainingData:
    """P8: export_training_data 训练数据导出测试."""

    def test_export_no_evidence_dir(self, tmp_path: Path) -> None:
        """evidence 目录不存在时返回空结果."""
        result = export_training_data(
            evidence_dir=tmp_path / "nonexistent",
            output_dir=tmp_path / "output",
        )
        assert result["total_samples"] == 0
        assert result["output_path"] == ""

    def test_export_empty_evidence_dir(self, tmp_path: Path) -> None:
        """evidence 目录为空时返回空结果."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        result = export_training_data(
            evidence_dir=evidence_dir,
            output_dir=tmp_path / "output",
        )
        assert result["total_samples"] == 0

    def test_export_with_samples(self, tmp_path: Path) -> None:
        """有足够样本时导出 JSONL 文件."""
        evidence_dir = tmp_path / "evidence"
        run_dir = evidence_dir / "redteam_test_001"
        scores_dir = run_dir / "scores"
        scores_dir.mkdir(parents=True)

        # 创建 60 个测试样本 (30 成功 + 30 失败)
        samples = []
        for i in range(30):
            samples.append({
                "response": f"This is a successful response number {i} with enough text. " * 3,
                "score_value": True,
                "confidence": 0.90,
                "rationale": "Test success",
                "objective": "test objective",
            })
        for i in range(30):
            samples.append({
                "response": f"I cannot help with that request number {i}. " * 3,
                "score_value": False,
                "confidence": 0.90,
                "rationale": "Test refusal",
                "objective": "test objective",
            })

        score_file = scores_dir / "scores.json"
        score_file.write_text(
            json.dumps(samples, ensure_ascii=False),
            encoding="utf-8",
        )

        result = export_training_data(
            evidence_dir=evidence_dir,
            output_dir=tmp_path / "output",
            min_confidence=0.85,
        )
        assert result["total_samples"] == 60
        assert result["success_samples"] == 30
        assert result["failure_samples"] == 30
        assert result["output_path"] != ""

        # 验证 JSONL 文件
        output_path = Path(result["output_path"])
        assert output_path.exists()
        lines = output_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 60

        # 验证第一行格式
        first_sample = json.loads(lines[0])
        assert "response" in first_sample
        assert "objective" in first_sample
        assert "label" in first_sample
        assert "confidence" in first_sample

    def test_export_filters_low_confidence(self, tmp_path: Path) -> None:
        """低置信度样本被过滤."""
        evidence_dir = tmp_path / "evidence"
        run_dir = evidence_dir / "redteam_test_002"
        scores_dir = run_dir / "scores"
        scores_dir.mkdir(parents=True)

        samples = [
            {
                "response": "High confidence success response with enough text. " * 3,
                "score_value": True,
                "confidence": 0.95,
            },
            {
                "response": "Low confidence refusal response with enough text. " * 3,
                "score_value": False,
                "confidence": 0.50,
            },
        ]

        score_file = scores_dir / "scores.json"
        score_file.write_text(
            json.dumps(samples, ensure_ascii=False),
            encoding="utf-8",
        )

        result = export_training_data(
            evidence_dir=evidence_dir,
            output_dir=tmp_path / "output",
            min_confidence=0.85,
        )
        assert result["total_samples"] == 1  # 只有高置信度样本
        assert result["success_samples"] == 1
        assert result["failure_samples"] == 0

    def test_export_insufficient_samples(self, tmp_path: Path) -> None:
        """样本不足时返回空路径."""
        evidence_dir = tmp_path / "evidence"
        run_dir = evidence_dir / "redteam_test_003"
        scores_dir = run_dir / "scores"
        scores_dir.mkdir(parents=True)

        # 只有 10 个样本 (< 50)
        samples = []
        for i in range(10):
            samples.append({
                "response": f"Short response {i}. ",
                "score_value": True,
                "confidence": 0.90,
            })

        score_file = scores_dir / "scores.json"
        score_file.write_text(
            json.dumps(samples, ensure_ascii=False),
            encoding="utf-8",
        )

        result = export_training_data(
            evidence_dir=evidence_dir,
            output_dir=tmp_path / "output",
            min_confidence=0.85,
        )
        assert result["total_samples"] < 50
        assert result["output_path"] == ""


# ============================================================
# load_distilled_scorer 测试
# ============================================================


class TestLoadDistilledScorer:
    """P8: load_distilled_scorer 惰性加载测试."""

    def setup_method(self) -> None:
        """重置模块级缓存."""
        import pipeline.scoring.scorer_distillation as sd

        sd._distilled_model = None
        sd._distilled_model_loaded = False

    def teardown_method(self) -> None:
        """重置模块级缓存."""
        import pipeline.scoring.scorer_distillation as sd

        sd._distilled_model = None
        sd._distilled_model_loaded = False

    def test_load_nonexistent_model(self, tmp_path: Path) -> None:
        """模型路径不存在时返回 None."""
        result = load_distilled_scorer(str(tmp_path / "nonexistent_model"))
        assert result is None

    def test_load_transformers_not_installed(self, tmp_path: Path) -> None:
        """transformers 未安装时返回 None."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        # Mock transformers 导入失败
        with patch("builtins.__import__", side_effect=ImportError("No module")):
            result = load_distilled_scorer(str(model_dir))
        assert result is None

    def test_load_cached_after_first_call(self, tmp_path: Path) -> None:
        """第二次调用使用缓存."""
        # 第一次调用 (返回 None)
        load_distilled_scorer(str(tmp_path / "nonexistent"))
        # 模块标记为已加载
        import pipeline.scoring.scorer_distillation as sd

        assert sd._distilled_model_loaded is True

        # 第二次调用直接返回缓存
        result = load_distilled_scorer(str(tmp_path / "nonexistent"))
        assert result is None


# ============================================================
# DistilledScore 测试
# ============================================================


class TestDistilledScore:
    """P8: DistilledScore PyRIT Score 接口兼容测试."""

    def test_get_value_true(self) -> None:
        """get_value 返回 True."""
        score = DistilledScore(
            score_value=True,
            score_rationale="Test success",
        )
        assert score.get_value() is True
        assert score.score_value is True
        assert score.score_rationale == "Test success"
        assert score.confidence == 0.85
        assert score.score_type == "true_false"

    def test_get_value_false(self) -> None:
        """get_value 返回 False."""
        score = DistilledScore(
            score_value=False,
            score_rationale="Test refusal",
            confidence=0.40,
        )
        assert score.get_value() is False
        assert score.score_value is False
        assert score.confidence == 0.40

    def test_metadata_default(self) -> None:
        """metadata 默认为空字典."""
        score = DistilledScore(
            score_value=True,
            score_rationale="Test",
        )
        assert isinstance(score.score_metadata, dict)
        assert len(score.score_metadata) == 0


# ============================================================
# DistilledScorerWrapper 测试
# ============================================================


class TestDistilledScorerWrapper:
    """P8: DistilledScorerWrapper PyRIT Scorer 接口兼容测试."""

    def test_get_identifier(self) -> None:
        """get_identifier 返回正确标识."""
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        wrapper = DistilledScorerWrapper(
            model=mock_model,
            tokenizer=mock_tokenizer,
            model_path="/test/path",
        )
        assert wrapper.get_identifier() == "DistilledScorerWrapper"

    def test_extract_text_string(self) -> None:
        """_extract_text 从字符串直接返回."""
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        wrapper = DistilledScorerWrapper(
            model=mock_model,
            tokenizer=mock_tokenizer,
            model_path="/test",
        )
        assert wrapper._extract_text("hello") == "hello"

    def test_extract_text_from_object(self) -> None:
        """_extract_text 从对象提取文本."""
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        wrapper = DistilledScorerWrapper(
            model=mock_model,
            tokenizer=mock_tokenizer,
            model_path="/test",
        )

        class MockResponse:
            response = "test response"
        obj = MockResponse()
        assert wrapper._extract_text(obj) == "test response"

    def test_build_prompt(self) -> None:
        """_build_prompt 包含 response 和 objective."""
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        wrapper = DistilledScorerWrapper(
            model=mock_model,
            tokenizer=mock_tokenizer,
            model_path="/test",
        )
        prompt = wrapper._build_prompt("test response", "test objective")
        assert "test response" in prompt
        assert "test objective" in prompt
        assert "true/false" in prompt.lower()

    @pytest.mark.asyncio
    async def test_score_async_returns_list(self) -> None:
        """score_async 返回包含 DistilledScore 的列表."""
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        wrapper = DistilledScorerWrapper(
            model=mock_model,
            tokenizer=mock_tokenizer,
            model_path="/test",
        )
        # Mock _infer 返回成功结果
        wrapper._infer = MagicMock(return_value={
            "label": True,
            "rationale": "Distilled model: true",
            "confidence": 0.85,
        })
        result = await wrapper.score_async(
            request_response="test response",
            task="test objective",
        )
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], DistilledScore)
        assert result[0].get_value() is True
        assert result[0].confidence == 0.85

    @pytest.mark.asyncio
    async def test_score_async_false_result(self) -> None:
        """score_async 返回 False 结果."""
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        wrapper = DistilledScorerWrapper(
            model=mock_model,
            tokenizer=mock_tokenizer,
            model_path="/test",
        )
        wrapper._infer = MagicMock(return_value={
            "label": False,
            "rationale": "Distilled model: false",
            "confidence": 0.85,
        })
        result = await wrapper.score_async(
            request_response="refusal response",
            task="test objective",
        )
        assert result[0].get_value() is False
