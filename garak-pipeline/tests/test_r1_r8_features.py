"""R9: R1-R8 补全测试 — 新增功能模块的单元测试

覆盖:
- R1: garak 0.16 兼容层 (recon_garak)
- R2: token 计费 (token_counter)
- R4: batch 对比 HTML (batch_runner._generate_batch_comparison_html)
- R5: API 鉴权 (api._verify_api_key)
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# R1: garak 0.16 兼容层测试
# ---------------------------------------------------------------------------
class TestGarak016Compat:
    """测试 garak 0.16 新探针兼容层"""

    def test_garak_016_map_non_empty(self):
        """GARAK_016_PROBE_OWASP_MAP 包含合理数量的映射"""
        from pipeline.recon_garak import GARAK_016_PROBE_OWASP_MAP
        assert len(GARAK_016_PROBE_OWASP_MAP) >= 20

    def test_garak_016_map_values_are_valid_owasp(self):
        """所有映射值都是有效的 OWASP 类标签"""
        from pipeline.recon_garak import GARAK_016_PROBE_OWASP_MAP, OWASP_CATEGORIES
        valid_labels = set(OWASP_CATEGORIES.values())
        for probe, label in GARAK_016_PROBE_OWASP_MAP.items():
            assert label in valid_labels, f"无效的 OWASP 标签: {label} for {probe}"

    def test_garak_016_map_keys_start_with_probes(self):
        """所有 key 都以 probes. 开头"""
        from pipeline.recon_garak import GARAK_016_PROBE_OWASP_MAP
        for key in GARAK_016_PROBE_OWASP_MAP:
            assert key.startswith("probes."), f"无效的 probe 名称: {key}"

    def test_resolve_probe_owasp_with_native_tag(self):
        """原生 owasp tag 优先于名称映射"""
        from pipeline.recon_garak import resolve_probe_owasp
        result = resolve_probe_owasp(
            "probes.dan.AutoDAN",
            ["owasp:llm01", "jailbreak"],
        )
        assert result == "LLM01_Prompt_Injection"

    def test_resolve_probe_owasp_fallback_to_name_map(self):
        """无 owasp tag 时回退到名称映射表"""
        from pipeline.recon_garak import resolve_probe_owasp
        result = resolve_probe_owasp("probes.dan.AutoDAN", [])
        assert result == "LLM01_Prompt_Injection"

    def test_resolve_probe_owasp_no_match(self):
        """无匹配时返回 None"""
        from pipeline.recon_garak import resolve_probe_owasp
        result = resolve_probe_owasp("probes.unknown.Something", [])
        assert result is None

    def test_resolve_probe_owasp_different_categories(self):
        """不同 OWASP 类别正确映射"""
        from pipeline.recon_garak import resolve_probe_owasp
        assert resolve_probe_owasp("probes.replay.Replay", []) == "LLM06_Sensitive_Information_Disclosure"
        assert resolve_probe_owasp("probes.test.Blank", []) == "LLM04_Model_Denial_of_Service"
        assert resolve_probe_owasp("probes.lmrc.Suicide", []) == "LLM09_Misinformation"

    def test_detect_garak_version(self):
        """detect_garak_version 返回字符串"""
        from pipeline.recon_garak import detect_garak_version
        ver = detect_garak_version()
        assert isinstance(ver, str)
        assert ver != ""


# ---------------------------------------------------------------------------
# R2: token 计费测试
# ---------------------------------------------------------------------------
class TestTokenCounter:
    """测试 token 计费模块"""

    def test_count_tokens_tiktoken_fallback(self):
        """tiktoken 不可用时回退到字符数估算"""
        from pipeline.token_counter import _count_tokens_tiktoken
        # 即使 tiktoken 安装，也应返回 > 0
        result = _count_tokens_tiktoken("hello world", "gpt-4")
        assert result > 0

    def test_count_tokens_empty_string(self):
        """空字符串返回至少 0"""
        from pipeline.token_counter import _count_tokens_tiktoken
        result = _count_tokens_tiktoken("", "gpt-4")
        assert result >= 0

    def test_count_tokens_from_report_nonexistent(self):
        """不存在的报告返回 error"""
        from pipeline.token_counter import count_tokens_from_report
        result = count_tokens_from_report("/nope/report.jsonl", "gpt-4")
        assert "error" in result

    def test_count_tokens_from_report_empty(self, tmp_path):
        """空报告返回零计数"""
        from pipeline.token_counter import count_tokens_from_report
        p = tmp_path / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        result = count_tokens_from_report(str(p), "gpt-4")
        assert result["total_attempts"] == 0
        assert result["input_tokens"] == 0
        assert result["output_tokens"] == 0
        assert result["total_tokens"] == 0
        assert result["estimated_cost_usd"] == 0.0

    def test_count_tokens_from_report_with_attempts(self, tmp_path):
        """包含 attempt 的报告正确计数"""
        from pipeline.token_counter import count_tokens_from_report
        p = tmp_path / "report.jsonl"
        p.write_text(
            json.dumps({"entry_type": "run", "run_id": "test"}) + "\n" +
            json.dumps({
                "entry_type": "attempt",
                "probe": "probes.test.X",
                "prompt": "hello world this is a test prompt",
                "outputs": ["I cannot help with that."],
                "goal": "test",
            }) + "\n",
            encoding="utf-8",
        )
        result = count_tokens_from_report(str(p), "gpt-4")
        assert result["total_attempts"] == 1
        assert result["input_tokens"] > 0
        assert result["output_tokens"] > 0
        assert result["total_tokens"] == result["input_tokens"] + result["output_tokens"]
        assert "probes.test.X" in result["per_probe"]
        assert result["per_probe"]["probes.test.X"]["attempts"] == 1

    def test_count_tokens_multi_output(self, tmp_path):
        """多 outputs 正确计数"""
        from pipeline.token_counter import count_tokens_from_report
        p = tmp_path / "report.jsonl"
        p.write_text(
            json.dumps({
                "entry_type": "attempt",
                "probe": "probes.X",
                "prompt": "test",
                "outputs": ["output1", "output2", "output3"],
                "goal": "test",
            }) + "\n",
            encoding="utf-8",
        )
        result = count_tokens_from_report(str(p), "gpt-4")
        assert result["total_attempts"] == 1
        assert result["output_tokens"] > 0
        assert result["per_probe"]["probes.X"]["total_tokens"] > 0

    def test_count_tokens_dict_output(self, tmp_path):
        """dict 格式的 output 也能计数"""
        from pipeline.token_counter import count_tokens_from_report
        p = tmp_path / "report.jsonl"
        p.write_text(
            json.dumps({
                "entry_type": "attempt",
                "probe": "probes.X",
                "prompt": "test",
                "outputs": [{"text": "dict output text"}],
                "goal": "test",
            }) + "\n",
            encoding="utf-8",
        )
        result = count_tokens_from_report(str(p), "gpt-4")
        assert result["output_tokens"] > 0

    def test_count_tokens_cost_estimation(self, tmp_path):
        """成本估算正确"""
        from pipeline.token_counter import count_tokens_from_report
        p = tmp_path / "report.jsonl"
        p.write_text(
            json.dumps({
                "entry_type": "attempt",
                "probe": "probes.X",
                "prompt": "test prompt here",
                "outputs": ["response here"],
                "goal": "test",
            }) + "\n",
            encoding="utf-8",
        )
        result = count_tokens_from_report(str(p), "gpt-4")
        expected_cost = round(
            (result["input_tokens"] / 1000 * 0.03) + (result["output_tokens"] / 1000 * 0.06), 4
        )
        assert result["estimated_cost_usd"] == expected_cost

    def test_save_token_usage(self, tmp_path):
        """save_token_usage 正确写入文件"""
        from pipeline.token_counter import count_tokens_from_report, save_token_usage
        p = tmp_path / "report.jsonl"
        p.write_text(
            json.dumps({
                "entry_type": "attempt",
                "probe": "probes.X",
                "prompt": "test",
                "outputs": ["ok"],
                "goal": "test",
            }) + "\n",
            encoding="utf-8",
        )
        token_data = count_tokens_from_report(str(p), "gpt-4")
        path = save_token_usage(token_data, str(tmp_path), "test-run")
        assert path is not None
        assert Path(path).exists()
        with open(path, encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["total_tokens"] == token_data["total_tokens"]

    def test_save_token_usage_error_returns_none(self):
        """有 error 字段时返回 None"""
        from pipeline.token_counter import save_token_usage
        result = save_token_usage({"error": "something"}, "/tmp", "test")
        assert result is None

    def test_count_tokens_malformed_json_skipped(self, tmp_path):
        """格式错误的 JSON 行被跳过"""
        from pipeline.token_counter import count_tokens_from_report
        p = tmp_path / "report.jsonl"
        p.write_text(
            '{"entry_type": "attempt", "probe": "probes.X", "prompt": "test", "outputs": ["ok"]}\n'
            '{bad json}\n'
            '{"entry_type": "attempt", "probe": "probes.Y", "prompt": "test2", "outputs": ["ok2"]}\n',
            encoding="utf-8",
        )
        result = count_tokens_from_report(str(p), "gpt-4")
        assert result["total_attempts"] == 2  # 2 valid attempts


# ---------------------------------------------------------------------------
# R4: batch 对比 HTML 测试
# ---------------------------------------------------------------------------
class TestBatchComparisonHTML:
    """测试多目标对比 HTML 生成"""

    def test_generate_html_single_target_returns_none(self, tmp_path):
        """单目标不生成对比 HTML"""
        from pipeline.batch_runner import _generate_batch_comparison_html
        summary = {
            "risk_ranking": [
                {"name": "A", "model": "m1", "defcon": 3, "worst_asr": 10},
            ],
        }
        result = _generate_batch_comparison_html(summary, str(tmp_path))
        assert result is None

    def test_generate_html_multi_target(self, tmp_path):
        """多目标生成对比 HTML"""
        from pipeline.batch_runner import _generate_batch_comparison_html
        summary = {
            "batch_timestamp": "2026-08-09 12:00:00",
            "total_targets": 3,
            "succeeded": 2,
            "failed": 1,
            "risk_ranking": [
                {"name": "A", "model": "m1", "defcon": 2, "worst_asr": 45},
                {"name": "B", "model": "m2", "defcon": 4, "worst_asr": 10},
            ],
        }
        result = _generate_batch_comparison_html(summary, str(tmp_path))
        assert result is not None
        assert Path(result).exists()
        content = Path(result).read_text(encoding="utf-8")
        assert "radarChart" in content
        assert "m1" in content
        assert "m2" in content

    def test_generate_html_with_owasp_coverage(self, tmp_path):
        """包含 OWASP 覆盖数据时正确生成维度"""
        from pipeline.batch_runner import _generate_batch_comparison_html
        summary = {
            "batch_timestamp": "2026-08-09",
            "total_targets": 2,
            "succeeded": 2,
            "failed": 0,
            "risk_ranking": [
                {
                    "name": "A", "model": "m1", "defcon": 2, "worst_asr": 45,
                    "owasp_coverage": {"LLM01_Prompt_Injection": ["probe1"], "LLM09_Misinformation": ["probe2"]},
                },
                {
                    "name": "B", "model": "m2", "defcon": 4, "worst_asr": 10,
                    "owasp_coverage": {"LLM01_Prompt_Injection": ["probe3"]},
                },
            ],
        }
        result = _generate_batch_comparison_html(summary, str(tmp_path))
        assert result is not None
        content = Path(result).read_text(encoding="utf-8")
        assert "LLM01" in content


# ---------------------------------------------------------------------------
# R5: API 鉴权测试
# ---------------------------------------------------------------------------
class TestAPIKeyAuth:
    """测试 REST API Key 鉴权"""

    def test_verify_api_key_dev_mode(self):
        """未配置 API Key 时为 dev 模式（通过）"""
        from pipeline.api import _verify_api_key
        with patch.dict(os.environ, {}, clear=True):
            assert _verify_api_key(None) is True
            assert _verify_api_key("anything") is True

    def test_verify_api_key_correct_key(self):
        """正确的 key 通过验证"""
        from pipeline.api import _verify_api_key
        with patch.dict(os.environ, {"GARAK_PIPELINE_API_KEY": "secret123"}):
            assert _verify_api_key("secret123") is True

    def test_verify_api_key_wrong_key(self):
        """错误的 key 拒绝"""
        from pipeline.api import _verify_api_key
        with patch.dict(os.environ, {"GARAK_PIPELINE_API_KEY": "secret123"}):
            assert _verify_api_key("wrong") is False

    def test_verify_api_key_missing_key(self):
        """缺失 key 拒绝"""
        from pipeline.api import _verify_api_key
        with patch.dict(os.environ, {"GARAK_PIPELINE_API_KEY": "secret123"}):
            assert _verify_api_key(None) is False

    def test_verify_api_key_empty_string(self):
        """空字符串 key 拒绝"""
        from pipeline.api import _verify_api_key
        with patch.dict(os.environ, {"GARAK_PIPELINE_API_KEY": "secret123"}):
            assert _verify_api_key("") is False

    def test_get_configured_api_key_returns_env(self):
        """_get_configured_api_key 从环境变量读取"""
        from pipeline.api import _get_configured_api_key
        with patch.dict(os.environ, {"GARAK_PIPELINE_API_KEY": "my-key"}):
            assert _get_configured_api_key() == "my-key"

    def test_get_configured_api_key_none_when_not_set(self):
        """未设置时返回 None"""
        from pipeline.api import _get_configured_api_key
        with patch.dict(os.environ, {}, clear=True):
            assert _get_configured_api_key() is None
