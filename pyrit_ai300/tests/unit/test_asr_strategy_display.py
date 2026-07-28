"""
ASR-Guided Strategy Display + 学术载荷下载器 单元测试
"""

from unittest.mock import MagicMock



# ============================================================
# Plan D Display 测试
# ============================================================


class TestPlanDDisplayAnalysis:
    """[3/9] 分析阶段展示测试"""

    def test_display_analysis_stage_default(self, capsys):
        from src.scenarios.asr_strategy_display import display_analysis_stage

        result = display_analysis_stage("gpt-4o")
        captured = capsys.readouterr()

        assert "ASR策略" in captured.out
        assert "策略模式" in captured.out
        assert "academic" in captured.out
        assert "gpt-4o" in captured.out
        assert result["strategy_mode"] == "academic"
        assert result["model_name"] == "gpt-4o"
        assert result["model_tier"] == "strong"

    def test_display_analysis_stage_weak_model(self, capsys):
        from src.scenarios.asr_strategy_display import display_analysis_stage

        result = display_analysis_stage("vicuna-13b")
        assert result["model_tier"] == "weak"

    def test_display_analysis_stage_moderate_model(self, capsys):
        from src.scenarios.asr_strategy_display import display_analysis_stage

        result = display_analysis_stage("llama-3.1-70b")
        assert result["model_tier"] == "moderate"

    def test_display_analysis_stage_with_recon_result(self, capsys):
        from src.scenarios.asr_strategy_display import display_analysis_stage
        from unittest.mock import MagicMock

        mock_recon = MagicMock()
        mock_recon.model_tier = "strong"
        mock_recon.model_tier_probe_detail = {"benign": {"success": True}}

        result = display_analysis_stage("some-model", recon_result=mock_recon)
        assert result["model_tier"] == "strong"
        captured = capsys.readouterr()
        assert "动态探针" in captured.out

    def test_display_analysis_stage_unknown_model(self, capsys):
        from src.scenarios.asr_strategy_display import display_analysis_stage

        result = display_analysis_stage("some-unknown-model")
        assert result["model_tier"] == "unknown"

    def test_display_analysis_stage_exam_mode(self, capsys, monkeypatch):
        from src.scenarios.asr_strategy_display import display_analysis_stage

        monkeypatch.setenv("STRATEGY_MODE", "exam")
        result = display_analysis_stage("gpt-4o")
        assert result["strategy_mode"] == "exam"

    def test_model_tier_inference(self):
        from src.scenarios.asr_strategy_display import _infer_model_tier

        assert _infer_model_tier("gpt-4o") == "strong"
        assert _infer_model_tier("gpt-4-turbo") == "strong"
        assert _infer_model_tier("claude-3.5-sonnet") == "strong"
        assert _infer_model_tier("o1-preview") == "strong"
        assert _infer_model_tier("gpt-3.5-turbo") == "weak"
        assert _infer_model_tier("llama-3.1-70b") == "moderate"
        assert _infer_model_tier("qwen3:0.6b") == "weak"
        assert _infer_model_tier("mistral-large") == "moderate"
        assert _infer_model_tier("deepseek-v3") == "moderate"
        assert _infer_model_tier("longcat-2.0") == "moderate"
        assert _infer_model_tier("some-unknown-model") == "unknown"


class TestPlanDDisplaySelection:
    """[5/9] 选择阶段展示测试"""

    def test_display_selection_stage_empty(self, capsys):
        from src.scenarios.asr_strategy_display import display_selection_stage

        display_selection_stage(selected_groups=[], model_name="gpt-4o")
        # 空列表不应输出 Tier 信息
        captured = capsys.readouterr()
        assert "Tier" not in captured.out or "ASR策略" not in captured.out

    def test_display_selection_stage_with_groups(self, capsys):
        from src.scenarios.asr_strategy_display import display_selection_stage

        # 模拟种子组
        mock_seed = MagicMock()
        mock_seed.metadata = {"technique": "crescendo"}
        mock_group = MagicMock()
        mock_group.seeds = [mock_seed]

        display_selection_stage(
            selected_groups=[mock_group],
            model_name="gpt-4o",
            strategy_mode="academic",
        )
        captured = capsys.readouterr()
        assert "ASR策略" in captured.out
        assert "crescendo" in captured.out
        assert "Tier S" in captured.out

    def test_display_selection_stage_tier_grouping(self, capsys):
        from src.scenarios.asr_strategy_display import display_selection_stage

        # 多技术不同 Tier (v4.0: 统一阈值 S>=70% A>=40% B>=15% C>=5% D<5%)
        seeds = [
            MagicMock(metadata={"technique": "crescendo"}),           # Tier S (ASR ~0.82)
            MagicMock(metadata={"technique": "pair"}),                # Tier A (ASR ~0.53)
            MagicMock(metadata={"technique": "persuasion_authority"}), # Tier B (ASR ~0.35)
            MagicMock(metadata={"technique": "prompt_sending"}),       # Tier D (ASR ~0.02)
        ]
        mock_group = MagicMock()
        mock_group.seeds = seeds

        display_selection_stage(
            selected_groups=[mock_group],
            model_name="gpt-4o",
        )
        captured = capsys.readouterr()
        assert "Tier S" in captured.out
        assert "Tier A" in captured.out
        assert "Tier B" in captured.out
        # v4.0: prompt_sending ASR < 5% → Tier D (不再是 C)
        assert "Tier D" in captured.out


class TestPlanDDisplayExecution:
    """[6/9] 执行阶段展示测试"""

    def test_display_execution_stage_basic(self, capsys):
        from src.scenarios.asr_strategy_display import display_execution_stage

        display_execution_stage(
            target_type="openai_chat",
            model_name="gpt-4o",
            strategy_mode="academic",
            attack_plans=[],
        )
        captured = capsys.readouterr()
        assert "ASR策略" in captured.out
        assert "失败类型路由策略" in captured.out

    def test_display_execution_stage_with_plans(self, capsys):
        from src.scenarios.asr_strategy_display import display_execution_stage

        mock_plan = MagicMock()
        mock_plan.attack_technique = "crescendo"

        display_execution_stage(
            target_type="",
            model_name="gpt-4o",
            strategy_mode="academic",
            attack_plans=[mock_plan],
        )
        captured = capsys.readouterr()
        assert "crescendo" in captured.out
        assert "ASR" in captured.out

    def test_display_execution_stage_exam_mode(self, capsys):
        from src.scenarios.asr_strategy_display import display_execution_stage

        mock_plan1 = MagicMock()
        mock_plan1.attack_technique = "crescendo"
        mock_plan2 = MagicMock()
        mock_plan2.attack_technique = "encoding_bypass"

        display_execution_stage(
            target_type="",
            model_name="gpt-4o",
            strategy_mode="exam",
            attack_plans=[mock_plan1, mock_plan2],
        )
        captured = capsys.readouterr()
        # exam 模式：低 ASR 优先
        encoding_pos = captured.out.find("encoding_bypass")
        crescendo_pos = captured.out.find("crescendo")
        assert encoding_pos < crescendo_pos


class TestPlanDDisplayPostExecution:
    """[6/9] 执行后展示测试"""

    def test_display_post_execution_none(self, capsys):
        from src.scenarios.asr_strategy_display import display_post_execution

        display_post_execution(adaptive_result=None)
        # 不应崩溃

    def test_display_post_execution_with_results(self, capsys):
        from src.scenarios.asr_strategy_display import display_post_execution

        mock_result = MagicMock()
        mock_result.outcome = "success"
        mock_result.identifier = MagicMock()
        mock_result.identifier.attack_technique = "crescendo"
        mock_result.identifier.children = {}

        mock_batch = MagicMock()
        mock_batch.results = [mock_result]

        mock_adaptive = MagicMock()
        mock_adaptive.batch_result = mock_batch
        mock_adaptive.failure_type_distribution = {"model_refusal": 3}
        mock_adaptive.most_common_failure_type = "model_refusal"

        display_post_execution(
            adaptive_result=mock_adaptive,
            model_name="gpt-4o",
        )
        captured = capsys.readouterr()
        assert "ASR策略" in captured.out
        assert "实测 ASR" in captured.out
        assert "model_refusal" in captured.out


# ============================================================
# Payload Downloader 测试
# ============================================================


class TestPayloadDownloaderTier:
    """Tier 分类测试"""

    def test_get_tier_s(self):
        from src.payloads.payload_downloader import _get_tier_for_technique

        assert _get_tier_for_technique("crescendo") == "S"
        assert _get_tier_for_technique("red_teaming") == "S"

    def test_get_tier_a(self):
        from src.payloads.payload_downloader import _get_tier_for_technique

        assert _get_tier_for_technique("tap") == "A"
        assert _get_tier_for_technique("pair") == "A"
        assert _get_tier_for_technique("many_shot") == "A"

    def test_get_tier_b(self):
        from src.payloads.payload_downloader import _get_tier_for_technique

        assert _get_tier_for_technique("persuasion_authority") == "B"
        assert _get_tier_for_technique("context_compliance") == "B"

    def test_get_tier_c_returns_none(self):
        from src.payloads.payload_downloader import _get_tier_for_technique

        assert _get_tier_for_technique("prompt_sending") is None
        assert _get_tier_for_technique("rot13") is None
        assert _get_tier_for_technique("base64") is None

    def test_get_tier_unknown_defaults_b(self):
        from src.payloads.payload_downloader import _get_tier_for_technique

        assert _get_tier_for_technique("unknown_technique") == "B"


class TestPayloadDownloaderASR:
    """ASR 查询测试"""

    def test_get_asr_known_technique(self):
        from src.payloads.payload_downloader import _get_asr_for_technique

        asr = _get_asr_for_technique("crescendo", "gpt-4o")
        assert asr == 0.82

    def test_get_asr_unknown_technique(self):
        from src.payloads.payload_downloader import _get_asr_for_technique

        asr = _get_asr_for_technique("unknown", "gpt-4o")
        assert 0.0 < asr < 1.0


class TestPayloadDownloaderClassify:
    """种子分类测试"""

    def test_classify_seed_by_metadata(self):
        from src.payloads.payload_downloader import _classify_seed

        mock_seed = MagicMock()
        mock_seed.metadata = {"technique": "crescendo"}
        assert _classify_seed(mock_seed) == "crescendo"

    def test_classify_seed_by_technique_group(self):
        from src.payloads.payload_downloader import _classify_seed

        mock_seed = MagicMock()
        mock_seed.metadata = {"technique_group": "pair"}
        assert _classify_seed(mock_seed) == "pair"

    def test_classify_seed_by_value_keyword(self):
        from src.payloads.payload_downloader import _classify_seed

        mock_seed = MagicMock()
        mock_seed.metadata = {}
        mock_seed.value = "Use crescendo technique to bypass"
        assert _classify_seed(mock_seed) == "crescendo"

    def test_classify_seed_default(self):
        from src.payloads.payload_downloader import _classify_seed

        mock_seed = MagicMock()
        mock_seed.metadata = {}
        mock_seed.value = "Some random prompt"
        assert _classify_seed(mock_seed) == "prompt_sending"


class TestPayloadDownloaderListLocal:
    """本地载荷列表测试"""

    def test_list_local_empty(self, tmp_path):
        from src.payloads.payload_downloader import list_local_academic_payloads

        result = list_local_academic_payloads(tmp_path)
        assert result == []

    def test_list_local_with_yaml(self, tmp_path):
        import yaml

        from src.payloads.payload_downloader import list_local_academic_payloads

        # 创建测试 YAML（对齐 OWASP 格式，technique/tier 在 seed metadata 中）
        data = {
            "dataset_name": "academic_jailbreakbench_crescendo",
            "name": "Academic Jailbreakbench crescendo (Tier S)",
            "description": "Academic payload from jailbreakbench",
            "source": "jailbreakbench",
            "authors": ["jailbreakbench"],
            "groups": ["academic"],
            "harm_categories": ["other"],
            "data_type": "text",
            "seed_type": "prompt",
            "seeds": [{
                "value": "test",
                "role": "user",
                "data_type": "text",
                "metadata": {
                    "technique": "crescendo",
                    "technique_group": "crescendo",
                    "attack_mode": "multi_turn",
                    "academic_tier": "S",
                    "asr_baseline": {"gpt_4o": 0.82, "source": "jailbreakbench"},
                },
            }],
        }
        yaml_file = tmp_path / "tier_s_crescendo.yaml"
        with open(yaml_file, "w") as f:
            yaml.dump(data, f)

        result = list_local_academic_payloads(tmp_path)
        assert len(result) == 1
        assert result[0]["source"] == "jailbreakbench"
        assert result[0]["technique"] == "crescendo"
        assert result[0]["tier"] == "S"
        assert result[0]["seed_count"] == 1


class TestPayloadDownloaderSaveYAML:
    """YAML 保存测试"""

    def test_save_yaml_creates_file(self, tmp_path):
        from src.payloads.payload_downloader import _save_yaml

        seeds = [
            {"value": "test prompt", "role": "user", "data_type": "text", "metadata": {}},
        ]
        output_path = tmp_path / "test" / "tier_s_crescendo.yaml"
        count = _save_yaml(seeds, output_path, "jailbreakbench", "crescendo", "S")

        assert count == 1
        assert output_path.exists()

        import yaml
        with open(output_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert data["dataset_name"] == "academic_jailbreakbench_crescendo"
        assert data["source"] == "jailbreakbench"
        assert data["name"] == "Academic Jailbreakbench crescendo (Tier S)"
        assert data["authors"] == ["jailbreakbench"]
        assert data["groups"] == ["academic"]
        assert data["data_type"] == "text"
        assert data["seed_type"] == "prompt"
        assert len(data["seeds"]) == 1

    def test_save_yaml_empty_seeds(self, tmp_path):
        from src.payloads.payload_downloader import _save_yaml

        count = _save_yaml([], tmp_path / "test.yaml", "test", "test", "S")
        assert count == 0


class TestPayloadDownloaderSeedToYAML:
    """种子转 YAML 字典测试"""

    def test_seed_to_yaml_dict(self):
        from src.payloads.payload_downloader import _seed_to_yaml_dict

        mock_seed = MagicMock()
        mock_seed.value = "test prompt"
        mock_seed.role = "user"
        mock_seed.data_type = "text"
        mock_seed.metadata = {"owasp_id": "LLM01"}

        result = _seed_to_yaml_dict(mock_seed, "crescendo", 0.82, "S", "jailbreakbench")
        assert result["value"] == "test prompt"
        assert result["role"] == "user"
        assert result["metadata"]["technique"] == "crescendo"
        assert result["metadata"]["attack_mode"] == "multi_turn"
        assert result["metadata"]["asr_baseline"]["gpt_4o"] == 0.82
        assert result["metadata"]["academic_tier"] == "S"
        assert result["metadata"]["owasp_id"] == "LLM01"


# ============================================================
# DatasetManager academic 集成测试
# ============================================================


class TestDatasetManagerAcademic:
    """DatasetManager 学术载荷加载测试"""

    def test_load_datasets_signature_has_academic(self):
        """验证 load_datasets 签名包含 academic 参数"""
        import inspect

        from src.payloads.dataset_manager import DatasetManager

        sig = inspect.signature(DatasetManager.load_datasets)
        assert "academic" in sig.parameters
        assert not sig.parameters["academic"].default

    def test_load_academic_datasets_method_exists(self):
        from src.payloads.dataset_manager import DatasetManager

        assert hasattr(DatasetManager, "load_academic_datasets")
