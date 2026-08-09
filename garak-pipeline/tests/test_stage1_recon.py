"""Unit tests for Stage 1: Recon (目标侦察)."""

import json
import sys
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
        assert result["status"] == "ok"
        assert result["method"] == "sdk_models"

    def test_connectivity_auth_failure(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test connectivity handles authentication failure (cascading to raw/POST)."""
        import openai

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = openai.AuthenticationError(
                "Invalid API key",
                response=MagicMock(),
                body=None,
            )
            # 级联探测：SDK 失败后会尝试 raw HTTP 和 POST，也需 mock
            with patch("requests.get") as mock_get:
                mock_get.return_value = MagicMock(status_code=401)
                with patch("requests.post") as mock_post:
                    mock_post.return_value = MagicMock(status_code=401)

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage._test_connectivity()
                    assert result["ok"] is False
                    assert result["status"] == "failed"
                    assert "认证失败" in result["error"]

    def test_connectivity_connection_error(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test connectivity handles connection failure (cascading, all levels fail)."""
        import openai
        import requests

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = openai.APIConnectionError(
                request=MagicMock()
            )
            with patch("requests.get") as mock_get:
                mock_get.side_effect = requests.ConnectionError("refused")
                with patch("requests.post") as mock_post:
                    mock_post.side_effect = requests.ConnectionError("refused")

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage._test_connectivity()
                    assert result["ok"] is False
                    assert result["status"] == "failed"
                    assert "Connection Error" in result["error"]

    def test_connectivity_post_success(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test POST-based connectivity succeeds when SDK and raw fail (non-OpenAI endpoint)."""
        import openai

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            # SDK level: 404 (no /models endpoint)
            mock_instance.models.list.side_effect = openai.APIStatusError(
                "Not found",
                response=MagicMock(status_code=404),
                body=None,
            )
            with patch("requests.get") as mock_get:
                # Raw HTTP level: also 404
                mock_get.return_value = MagicMock(status_code=404)
                with patch("requests.post") as mock_post:
                    # POST level: success (endpoint accepts chat POST)
                    mock_post.return_value = MagicMock(status_code=200)

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage._test_connectivity()
                    assert result["ok"] is True
                    assert result["status"] == "degraded"
                    assert result["method"] == "post_chat"

    def test_connectivity_post_with_openai_compatible_response(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test POST connectivity detects OpenAI-compatible response structure."""
        import openai

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = openai.APIStatusError(
                "Not found",
                response=MagicMock(status_code=404),
                body=None,
            )
            with patch("requests.get") as mock_get:
                mock_get.return_value = MagicMock(status_code=404)
                with patch("requests.post") as mock_post:
                    # POST level: 200 with OpenAI-compatible body
                    mock_resp = MagicMock(status_code=200)
                    mock_resp.json.return_value = {
                        "choices": [
                            {"message": {"content": "Hello!"}}
                        ]
                    }
                    mock_resp.headers = {"content-type": "application/json"}
                    mock_post.return_value = mock_resp

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage._test_connectivity()
                    assert result["ok"] is True
                    assert result["status"] == "degraded"
                    assert result["method"] == "post_chat"
                    assert result["response_format"] == "openai_compatible"

    def test_connectivity_per_level_results(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test _test_connectivity returns _levels with per-level breakdown."""
        import openai

        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = openai.APIStatusError(
                "Not found",
                response=MagicMock(status_code=404),
                body=None,
            )
            with patch("requests.get") as mock_get:
                mock_get.return_value = MagicMock(status_code=404)
                with patch("requests.post") as mock_post:
                    mock_post.return_value = MagicMock(status_code=200)

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage._test_connectivity()
                    # _levels 字段应包含三级结果
                    assert "_levels" in result
                    levels = result["_levels"]
                    assert "sdk" in levels
                    assert "raw" in levels
                    assert "post" in levels
                    # SDK 失败
                    assert levels["sdk"]["ok"] is False
                    # raw 失败
                    assert levels["raw"]["ok"] is False
                    # POST 成功
                    assert levels["post"]["ok"] is True

    def test_connectivity_sdk_attribute_error_fallback(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test SDK AttributeError triggers raw HTTP fallback (non-standard /models response)."""
        with patch("openai.OpenAI") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            mock_instance.models.list.side_effect = AttributeError("str has no attribute")
            with patch("requests.get") as mock_get:
                # Raw HTTP returns 200 (non-standard but reachable)
                mock_get.return_value = MagicMock(status_code=200)

                stage = Stage1Recon(
                    target=sample_target,
                    mode="standard",
                    artifacts_dir=temp_artifacts_dir,
                )
                result = stage._test_connectivity()
                assert result["ok"] is True
                assert result["status"] == "ok"
                assert result["method"] == "raw_models"

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
                        "status": "ok",
                        "method": "sdk_models",
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
                    assert result["state"]["degraded_mode"] is False
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
                    assert prof["connectivity_status"] == "ok"
                    assert prof["degraded_mode"] is False
                    # G3 验证: recon_coverage 字段存在且值正确
                    assert "recon_coverage" in prof
                    assert prof["recon_coverage"]["connectivity"] == "ok"
                    assert prof["recon_coverage"]["probe_enumeration"] == "ok"
                    assert prof["recon_coverage"]["modality_detection"] == "ok"
                    assert prof["recon_coverage"]["classification"] == "ok"

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

    # ------------------------------------------------------------------
    # 降级模式测试（连通性失败仍枚举探针）
    # ------------------------------------------------------------------

    def test_run_degraded_mode_on_connectivity_failure(
        self, sample_target: dict, temp_artifacts_dir: Path, sample_probes: list[dict]
    ) -> None:
        """Test run() enters degraded mode when connectivity fails, still enumerates probes."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            with patch.object(Stage1Recon, "_enumerate_active_probes") as mock_enum:
                with patch.object(Stage1Recon, "_detect_model_modality") as mock_mod:
                    mock_conn.return_value = {
                        "ok": False,
                        "status": "failed",
                        "method": None,
                        "error": "级联探测全部失败 → SDK: Connection Error | HTTP: ...",
                    }
                    mock_enum.return_value = sample_probes
                    mock_mod.return_value = {
                        "in": {"text"},
                        "out": {"text"},
                        "supports_multiple_generations": None,
                    }

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage.run()

                    # 降级模式下 success=True（探针枚举成功）
                    assert result["success"] is True
                    assert result["state"]["degraded_mode"] is True
                    assert result["state"]["connectivity_status"] == "failed"
                    assert len(result["state"]["warnings"]) >= 2

                    # 所有产物文件仍应生成
                    assert (stage.out_dir / f"connectivity_test_{stage.run_id}.json").exists()
                    assert (stage.out_dir / f"probe_candidates_{stage.run_id}.json").exists()
                    assert (stage.out_dir / f"probe_candidates_filtered_{stage.run_id}.json").exists()
                    assert (stage.out_dir / f"target_profile_{stage.run_id}.json").exists()

                    # target_profile 应记录降级模式
                    prof_path = stage.out_dir / f"target_profile_{stage.run_id}.json"
                    with open(prof_path, encoding="utf-8") as f:
                        prof = json.load(f)
                    assert prof["degraded_mode"] is True
                    assert prof["connectivity_status"] == "failed"
                    assert len(prof["warnings"]) >= 2
                    # 探针仍被枚举和分类
                    assert prof["total_active_probes"] == len(sample_probes)
                    # G3 验证: recon_coverage 在降级模式下
                    assert prof["recon_coverage"]["connectivity"] == "failed"
                    assert prof["recon_coverage"]["probe_enumeration"] == "ok"
                    assert prof["recon_coverage"]["modality_detection"] == "heuristic"
                    assert prof["recon_coverage"]["classification"] == "ok"

    def test_run_degraded_mode_post_connectivity(
        self, sample_target: dict, temp_artifacts_dir: Path, sample_probes: list[dict]
    ) -> None:
        """Test run() with POST-only connectivity (degraded but reachable)."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            with patch.object(Stage1Recon, "_enumerate_active_probes") as mock_enum:
                with patch.object(Stage1Recon, "_detect_model_modality") as mock_mod:
                    mock_conn.return_value = {
                        "ok": True,
                        "status": "degraded",
                        "method": "post_chat",
                        "latency_ms": 500,
                        "available_models": [],
                        "_note": "POST 对话探测成功",
                    }
                    mock_enum.return_value = sample_probes
                    mock_mod.return_value = {
                        "in": {"text"},
                        "out": {"text"},
                        "supports_multiple_generations": None,
                    }

                    stage = Stage1Recon(
                        target=sample_target,
                        mode="standard",
                        artifacts_dir=temp_artifacts_dir,
                    )
                    result = stage.run()

                    assert result["success"] is True
                    # POST 连通成功：degraded_mode=False（端点可达），但 status="degraded"
                    assert result["state"]["connectivity_status"] == "degraded"
                    # 仍应有 warnings（非标准 API 提示）
                    assert len(result["state"]["warnings"]) >= 1

    def test_run_creates_artifacts_on_success(
        self, sample_target: dict, temp_artifacts_dir: Path, sample_probes: list[dict]
    ) -> None:
        """Test run() creates all expected artifacts on success."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            with patch.object(Stage1Recon, "_enumerate_active_probes") as mock_enum:
                mock_conn.return_value = {
                    "ok": True,
                    "status": "ok",
                    "method": "sdk_models",
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

    # ------------------------------------------------------------------
    # G1 测试: 异常路径保存部分产物
    # ------------------------------------------------------------------

    def test_run_saves_partial_artifacts_on_exception(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test run() saves partial artifacts when _enumerate_active_probes throws."""
        with patch.object(Stage1Recon, "_test_connectivity") as mock_conn:
            with patch.object(Stage1Recon, "_enumerate_active_probes") as mock_enum:
                mock_conn.return_value = {
                    "ok": True,
                    "status": "ok",
                    "method": "sdk_models",
                    "latency_ms": 50,
                    "available_models": ["test-model"],
                }
                # 探针枚举抛出异常（模拟 garak 未安装）
                mock_enum.side_effect = ImportError("garak not installed")

                stage = Stage1Recon(
                    target=sample_target,
                    mode="standard",
                    artifacts_dir=temp_artifacts_dir,
                )
                result = stage.run()

                # 异常路径: success=False
                assert result["success"] is False
                assert "garak not installed" in result["error"]

                # G1 验证: 仍保存了 connectivity_test 和最小 target_profile
                assert (stage.out_dir / f"connectivity_test_{stage.run_id}.json").exists()
                prof_path = stage.out_dir / f"target_profile_{stage.run_id}.json"
                assert prof_path.exists()
                with open(prof_path, encoding="utf-8") as f:
                    prof = json.load(f)
                assert prof["connectivity_status"] == "ok"
                assert prof["degraded_mode"] is False
                # recon_coverage 应反映异常位置
                assert prof["recon_coverage"]["connectivity"] == "ok"
                assert prof["recon_coverage"]["probe_enumeration"] == "pending"
                # 应包含错误信息
                assert "error" in prof
                assert "garak not installed" in prof["error"]

    # ------------------------------------------------------------------
    # G2 测试: skip_generator 参数
    # ------------------------------------------------------------------

    def test_detect_model_modality_skip_generator(
        self, sample_target: dict, temp_artifacts_dir: Path
    ) -> None:
        """Test _detect_model_modality with skip_generator=True skips garak load."""
        stage = Stage1Recon(
            target=sample_target,
            mode="standard",
            artifacts_dir=temp_artifacts_dir,
        )
        # skip_generator=True 应跳过 garak import，直接走启发式
        result = stage._detect_model_modality(skip_generator=True)
        # LongCat-2.0 不匹配多模态关键词 → text-only
        assert "text" in result["in"]
        assert "text" in result["out"]
        # 不应有 supports_multiple_generations（未加载 generator）
        assert "supports_multiple_generations" not in result or \
               result["supports_multiple_generations"] is None

    # ------------------------------------------------------------------
    # G5 测试: _classify_post_response 辅助方法
    # ------------------------------------------------------------------

    def test_classify_post_response_openai_compatible(self) -> None:
        """Test _classify_post_response detects OpenAI-compatible JSON."""
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Hello!"}}]
        }
        fmt = Stage1Recon._classify_post_response(mock_resp)
        assert fmt == "openai_compatible"

    def test_classify_post_response_non_standard_json(self) -> None:
        """Test _classify_post_response detects non-standard JSON."""
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"result": "some text"}
        fmt = Stage1Recon._classify_post_response(mock_resp)
        assert fmt == "json_non_standard"

    def test_classify_post_response_sse_stream(self) -> None:
        """Test _classify_post_response detects SSE stream as OpenAI-compatible."""
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/event-stream"}
        fmt = Stage1Recon._classify_post_response(mock_resp)
        assert fmt == "openai_compatible"

    def test_classify_post_response_html(self) -> None:
        """Test _classify_post_response detects HTML as non_json."""
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.json.side_effect = Exception("not JSON")
        fmt = Stage1Recon._classify_post_response(mock_resp)
        assert fmt == "non_json"


class TestPreflightCheck:
    """Tests for stage3_execute.preflight_check (imported with garak mocked)."""

    @staticmethod
    def _import_preflight_check():
        """Import preflight_check from stage3_execute with garak modules mocked."""
        import importlib
        garak_mock = MagicMock()
        for mod_name in [
            "garak", "garak._config", "garak._plugins", "garak.command",
            "garak.evaluators", "garak.evaluators.base",
        ]:
            sys.modules[mod_name] = garak_mock
        try:
            # 确保从干净状态导入
            if "pipeline.stage3_execute" in sys.modules:
                del sys.modules["pipeline.stage3_execute"]
            mod = importlib.import_module("pipeline.stage3_execute")
            return mod.preflight_check
        finally:
            for mod_name in [
                "garak", "garak._config", "garak._plugins", "garak.command",
                "garak.evaluators", "garak.evaluators.base",
            ]:
                sys.modules.pop(mod_name, None)
            sys.modules.pop("pipeline.stage3_execute", None)

    def test_preflight_all_ok(self) -> None:
        """Test preflight_check returns no warnings when everything is ok."""
        fn = self._import_preflight_check()
        warnings = fn(
            target={"endpoint": "https://api.example.com/v1", "model": "gpt-4"},
            probe_names=["dan.AutoDANCached"],
            conn_status="ok",
        )
        assert len(warnings) == 0

    def test_preflight_failed_connectivity(self) -> None:
        """Test preflight_check warns on failed connectivity."""
        fn = self._import_preflight_check()
        warnings = fn(
            target={"endpoint": "https://api.example.com/v1", "model": "gpt-4"},
            probe_names=["dan.AutoDANCached"],
            conn_status="failed",
        )
        assert len(warnings) == 1
        assert "连通性测试未通过" in warnings[0]

    def test_preflight_unknown_model(self) -> None:
        """Test preflight_check warns on unknown-model placeholder."""
        fn = self._import_preflight_check()
        warnings = fn(
            target={"endpoint": "https://api.example.com/v1", "model": "unknown-model"},
            probe_names=["dan.AutoDANCached"],
            conn_status="degraded",
        )
        # Should warn about unknown model + degraded connectivity
        assert len(warnings) >= 2
        assert any("unknown-model" in w for w in warnings)
        assert any("降级模式" in w for w in warnings)

    def test_preflight_empty_probes(self) -> None:
        """Test preflight_check warns on empty probe list."""
        fn = self._import_preflight_check()
        warnings = fn(
            target={"endpoint": "https://api.example.com/v1", "model": "gpt-4"},
            probe_names=[],
            conn_status="ok",
        )
        assert len(warnings) == 1
        assert "探针列表为空" in warnings[0]

    def test_preflight_missing_endpoint(self) -> None:
        """Test preflight_check warns on missing endpoint."""
        fn = self._import_preflight_check()
        warnings = fn(
            target={"endpoint": "", "model": "gpt-4"},
            probe_names=["dan.AutoDANCached"],
            conn_status="ok",
        )
        assert len(warnings) == 1
        assert "endpoint" in warnings[0]
