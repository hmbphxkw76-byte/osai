"""Unit tests for Stage 1: Recon (目标侦察)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from pipeline.stage1_recon import Stage1Recon


class TestStage1Recon:
    """Unit tests for Stage1Recon."""

    def test_initialisation(self, sample_target: dict, temp_artifacts_dir: Path) -> None:
        """Test that Stage1Recon initialises correctly."""
        stage = Stage1Recon(
            target=sample_target,
            mode="standard",
            artifacts_dir=temp_artifacts_dir,
        )
        assert stage.target == sample_target
        assert stage.mode == "standard"
        assert stage.out_dir.exists()
        assert stage.out_dir.name.startswith("01_recon")

    def test_connectivity_success(
        self, sample_target: dict, temp_artifacts_dir: Path, mock_openai_client
    ) -> None:
        """Test connectivity test returns ok on success."""
        stage = Stage1Recon(
            target=sample_target,
            mode="standard",
            artifacts_dir=temp_artifacts_dir,
        )
        result = stage._test_connectivity()
        assert result["ok"] is True
        assert "latency_ms" in result
        assert "available_models" in result

    def test_connectivity_auth_failure(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test connectivity handles authentication failure."""
        import openai

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = openai.AuthenticationError(
                "Invalid API key",
                response=MagicMock(),
                body=None,
            )

            stage = Stage1Recon(
                target=sample_target,
                mode="standard",
                artifacts_dir=temp_artifacts_dir,
            )
            result = stage._test_connectivity()
            assert result["ok"] is False
            assert "认证失败" in result["error"]

    def test_connectivity_connection_error(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test connectivity handles connection failure."""
        import openai

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = openai.APIConnectionError(
                request=MagicMock()
            )

            stage = Stage1Recon(
                target=sample_target,
                mode="standard",
                artifacts_dir=temp_artifacts_dir,
            )
            result = stage._test_connectivity()
            assert result["ok"] is False
            assert "无法连接" in result["error"]

    def test_enumerate_active_probes(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test enumeration of active probes from garak plugin registry."""
        with patch("garak._plugins.enumerate_plugins") as mock_enum:
            with patch("garak._plugins.plugin_info") as mock_info:
                mock_enum.return_value = [
                    ("dan.AutoDANCached", True),
                    ("encoding.InjectBase64", True),
                    ("inactive.SomeProbe", False),
                ]
                mock_info.side_effect = lambda name: {
                    "dan.AutoDANCached": {
                        "description": "DAN probe",
                        "tier": 1,
                        "tags": ["owasp:llm01"],
                        "goal": "bypass alignment",
                        "modality": {"in": ["text"]},
                        "primary_detector": "mitigation.MitigationBypass",
                    },
                    "encoding.InjectBase64": {
                        "description": "Encode injection",
                        "tier": 1,
                        "tags": ["owasp:llm01"],
                        "goal": "bypass filters",
                        "modality": {"in": ["text"]},
                        "primary_detector": "encoding.DecodeMatch",
                    },
                }[name]

                stage = Stage1Recon(
                    target=sample_target,
                    mode="standard",
                    artifacts_dir=temp_artifacts_dir,
                )
                probes = stage._enumerate_active_probes()
                assert len(probes) == 2
                assert probes[0]["name"] == "dan.AutoDANCached"
                assert probes[1]["name"] == "encoding.InjectBase64"
                # Inactive probe should be excluded
                names = [p["name"] for p in probes]
                assert "inactive.SomeProbe" not in names

    def test_classify_probes_by_owasp(
        self, sample_target: dict, temp_artifacts_dir: Path, sample_probes: list[dict]
    ) -> None:
        """Test probe classification by OWASP tags."""
        stage = Stage1Recon(
            target=sample_target,
            mode="standard",
            artifacts_dir=temp_artifacts_dir,
        )
        result = stage._classify_probes(sample_probes)

        owasp = result["owasp"]
        assert "LLM01_Prompt_Injection" in owasp
        assert "LLM06_Sensitive_Information_Disclosure" in owasp
        assert "dan.AutoDANCached" in owasp["LLM01_Prompt_Injection"]
        assert "encoding.InjectBase64" in owasp["LLM01_Prompt_Injection"]
        assert "leakreplay.GuardianCloze" in owasp["LLM06_Sensitive_Information_Disclosure"]

    def test_classify_probes_empty_input(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test probe classification with empty input."""
        stage = Stage1Recon(
            target=sample_target,
            mode="standard",
            artifacts_dir=temp_artifacts_dir,
        )
        result = stage._classify_probes([])
        assert result["owasp"] == {}
        assert result["ai300_topic"] == {}

    def test_filter_probes_by_modality_drops_image_for_text_model(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test that text-only target drops image/audio probes but keeps text."""
        from pipeline.recon_garak import filter_probes_by_modality

        probes = [
            {"name": "text.ProbeA", "modality": {"in": ["text"]}},
            {"name": "vision.ProbeB", "modality": {"in": ["image", "text"]}},
            {"name": "audio.ProbeC", "modality": {"in": ["audio"]}},
            {"name": "no_modality.ProbeD", "modality": {}},  # 视为 text, 保留
            {"name": "empty_in.ProbeE", "modality": {"in": []}},  # 视为 text, 保留
        ]
        result = filter_probes_by_modality(probes, ["text"])
        kept_names = {p["name"] for p in result["kept"]}
        dropped_names = {d["name"] for d in result["dropped"]}

        assert "text.ProbeA" in kept_names
        assert "no_modality.ProbeD" in kept_names
        assert "empty_in.ProbeE" in kept_names
        assert "vision.ProbeB" in dropped_names
        assert "audio.ProbeC" in dropped_names
        assert result["kept_count"] == 3
        assert result["dropped_count"] == 2
        assert result["target_modality"] == ["text"]

    def test_filter_probes_by_modality_keeps_image_for_vision_model(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test that vision target keeps image probes."""
        from pipeline.recon_garak import filter_probes_by_modality

        probes = [
            {"name": "text.ProbeA", "modality": {"in": ["text"]}},
            {"name": "vision.ProbeB", "modality": {"in": ["image", "text"]}},
        ]
        result = filter_probes_by_modality(probes, ["text", "image"])
        kept_names = {p["name"] for p in result["kept"]}
        assert "vision.ProbeB" in kept_names
        assert result["dropped_count"] == 0
        assert set(result["target_modality"]) == {"text", "image"}

    def test_filter_probes_by_modality_unknown_modality_treated_as_text(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test that garak's ambiguous modality keys don't cause false drops."""
        from pipeline.recon_garak import filter_probes_by_modality

        probes = [
            {"name": "weird.Probe", "modality": {"in": ["xyz-unknown"]}},
        ]
        result = filter_probes_by_modality(probes, ["text"])
        # 未知模态键按 text 处理，应保留（保守策略）
        assert result["kept_count"] == 1
        assert result["dropped_count"] == 0

    def test_run_creates_filtered_candidates_on_success(
        self, sample_target: dict, temp_artifacts_dir: Path, sample_probes: list[dict]
    ) -> None:
        """Test run() emits probe_candidates_filtered.json in addition to full set."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            with patch.object(Stage1Recon, "_enumerate_active_probes") as mock_enum:
                with patch.object(Stage1Recon, "_detect_model_modality") as mock_mod:
                    mock_conn.return_value = {
                        "ok": True,
                        "latency_ms": 100,
                        "available_models": ["LongCat-2.0"],
                    }
                    mock_enum.return_value = sample_probes
                    # 强制 text-only（LongCat 为纯文本模型）
                    mock_mod.return_value = {
                        "in": {"text"},
                        "out": {"text"},
                        "supports_multiple_generations": False,
                    }

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage.run()

                    assert result["success"] is True
                    # 全量 + 过滤后两份清单都应存在
                    assert (stage.out_dir / f"probe_candidates_{stage.run_id}.json").exists()
                    filtered_path = (
                        stage.out_dir / f"probe_candidates_filtered_{stage.run_id}.json"
                    )
                    assert filtered_path.exists()
                    import json
                    with open(filtered_path, encoding="utf-8") as f:
                        filtered = json.load(f)
                    # sample_probes 全为 text → 过滤后数量不变
                    assert len(filtered) == len(sample_probes)
                    # target_profile 应记录 modality_filter 段
                    prof_path = stage.out_dir / f"target_profile_{stage.run_id}.json"
                    with open(prof_path, encoding="utf-8") as f:
                        prof = json.load(f)
                    assert "modality_filter" in prof
                    assert prof["modality_filter"]["target_modality_in"] == ["text"]
                    assert "attack_surface_dual" in prof

    def test_save_json(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test JSON file saving."""
        stage = Stage1Recon(
            target=sample_target,
            mode="standard",
            artifacts_dir=temp_artifacts_dir,
        )
        data = {"test": "value", "number": 42}
        stage._save_json("test_output.json", data)

        # 文件名含 _date_time_
        saved_path = stage.out_dir / f"test_output_{stage.run_id}.json"
        assert saved_path.exists()
        with open(saved_path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded == data

    def test_run_with_connectivity_failure(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test run() propagates connectivity failure."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            mock_conn.return_value = {"ok": False, "error": "Connection refused"}

            stage = Stage1Recon(
                target=sample_target,
                mode="standard",
                artifacts_dir=temp_artifacts_dir,
            )
            result = stage.run()
            assert result["success"] is False
            assert "Connection refused" in result["error"]

    def test_run_creates_artifacts_on_success(
        self, sample_target: dict, temp_artifacts_dir: Path, sample_probes: list[dict]
    ) -> None:
        """Test run() creates all expected artifacts on success."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            with patch.object(Stage1Recon, "_enumerate_active_probes") as mock_enum:
                mock_conn.return_value = {
                    "ok": True,
                    "latency_ms": 100,
                    "available_models": ["LongCat-2.0"],
                }
                mock_enum.return_value = sample_probes

                stage = Stage1Recon(
                    target=sample_target,
                    mode="standard",
                    artifacts_dir=temp_artifacts_dir,
                )
                result = stage.run()

                assert result["success"] is True
                # 验证产物文件名含 _date_time_
                assert (stage.out_dir / f"connectivity_test_{stage.run_id}.json").exists()
                assert (stage.out_dir / f"target_profile_{stage.run_id}.json").exists()
                assert (stage.out_dir / f"probe_candidates_{stage.run_id}.json").exists()
                assert "target_profile" in result["state"]
                assert "active_probes" in result["state"]
