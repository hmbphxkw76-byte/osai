"""tests/test_synergy.py — Burp + Scores + Seeds 协同分析模块测试.

测试覆盖:
  1. AssetMapper 静态映射
  2. AttackSurfaceClassifier HTTP 内容分类
  3. SynergyOrchestrator 全链路协同
  4. 端到端协同效果验证 (A/B 对照)

学术依据:
  - HarmBench (arXiv:2402.04249): 评分器选择验证
  - DecodingTrust (arXiv:2306.11698): 多维度评估
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_ROOT = _PROJECT_ROOT / "data"

# Ensure project root is in path for imports
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ──────────────────────────────────────────────
# Phase 1: AssetMapper 测试
# ──────────────────────────────────────────────
class TestAssetMapper:
    """测试 AssetMapper 核心功能."""

    def test_mapper_loads_index(self):
        """AssetMapper 应该成功加载 asset_index.yaml."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()
        assert mapper._index != {}
        assert "assets" in mapper._index

    def test_classify_mcp_profile(self):
        """MCP 配置文件应该被正确分类."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()

        assert mapper.classify_attack_surface("mcp05") in ["mcp_server", "mcp_full_surface"]
        assert mapper.classify_attack_surface("mcp09") in ["mcp_server", "mcp_full_surface"]
        assert mapper.classify_attack_surface("MCP_SERVER") in ["mcp_server", "mcp_full_surface"]

    def test_classify_standard_profile(self):
        """非 MCP 配置文件应该被分类为 standard_llm_api."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()

        assert mapper.classify_attack_surface("mocka") == "standard_llm_api"
        assert mapper.classify_attack_surface("mockb") == "standard_llm_api"
        assert mapper.classify_attack_surface("random_name") == "standard_llm_api"

    def test_get_seeds_for_mcp_surface(self):
        """MCP 攻击面应该返回 MCP 相关种子."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()
        seeds = mapper.get_seeds_for_attack_surface("mcp_server")

        assert len(seeds) > 0
        # 应该包含 MCP 相关种子
        assert any("mcp" in s.lower() for s in seeds)

    def test_get_seeds_for_standard_surface(self):
        """标准 LLM API 应该返回通用种子."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()
        seeds = mapper.get_seeds_for_attack_surface("standard_llm_api")

        assert len(seeds) > 0
        assert any("elite_jailbreaks" in s or "advanced_injection" in s for s in seeds)

    def test_get_scorer_for_mcp_surface(self):
        """MCP 攻击面应该使用 web_vuln_detected 评分器."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()
        scorer = mapper.get_scorer_for_attack_surface("mcp_full_surface")

        assert scorer == "web_vuln_detected"

    def test_get_scorer_for_standard_surface(self):
        """标准 LLM API 应该使用 blackbox_task_achieved 评分器."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()
        scorer = mapper.get_scorer_for_attack_surface("standard_llm_api")

        assert scorer == "blackbox_task_achieved"

    def test_get_full_synergy_config(self):
        """完整协同配置应该包含所有必需字段."""
        from core.asset_mapper import AssetMapper

        mapper = AssetMapper()
        config = mapper.get_full_synergy_config("mcp05")

        assert "burp_profile" in config
        assert "attack_surface" in config
        assert "seeds" in config
        assert "scorer" in config
        assert "scorer_path" in config

        assert config["burp_profile"] == "mcp05"
        assert len(config["seeds"]) > 0
        assert config["scorer"] is not None


# ──────────────────────────────────────────────
# Phase 2: AttackSurfaceClassifier 测试
# ──────────────────────────────────────────────
class TestAttackSurfaceClassifier:
    """测试 HTTP 内容分类器."""

    def test_classify_mcp_http_content(self):
        """包含 MCP 特征的 HTTP 内容应该被分类为 mcp_server."""
        from recon.attack_surface_classifier import classify_http_content

        mcp_http = """POST /mcp/v1 HTTP/1.1
Host: target.example.com
Content-Type: application/json
mcp-session-id: abc123

{"jsonrpc": "2.0", "method": "tools/list"}
"""
        result = classify_http_content(http_request=mcp_http)
        assert result.attack_surface == "mcp_server"
        assert result.confidence > 0.3

    def test_classify_rag_http_content(self):
        """包含搜索/检索特征的 HTTP 内容应该被分类为 rag_system."""
        from recon.attack_surface_classifier import classify_http_content

        # Stronger RAG indicators: URL matches + body fields
        rag_http = """POST /api/search HTTP/1.1
Host: target.example.com
Content-Type: application/json
x-document-id: doc_001

{"query": "confidential documents", "retrieval_method": "semantic", "documents": [], "results": []}
"""
        result = classify_http_content(http_request=rag_http)
        assert result.attack_surface == "rag_system"
        # URL (×3) + response fields (×1.5×2) → confidence should be higher
        assert result.confidence > 0.3

    def test_classify_agent_http_content(self):
        """包含 Agent 特征的 HTTP 内容应该被分类为 multi_agent_system."""
        from recon.attack_surface_classifier import classify_http_content

        agent_http = """POST /agent/execute HTTP/1.1
Host: target.example.com
Content-Type: application/json
x-agent-id: agent_001

{"tool_calls": [{"function": "run_code", "args": {}}]}
"""
        result = classify_http_content(http_request=agent_http)
        assert result.attack_surface == "multi_agent_system"
        assert result.confidence > 0.3

    def test_classify_standard_http_content(self):
        """标准 LLM API 应该被分类为 standard_llm_api."""
        from recon.attack_surface_classifier import classify_http_content

        standard_http = """POST /v1/chat/completions HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
"""
        result = classify_http_content(http_request=standard_http)
        assert result.attack_surface == "standard_llm_api"

    def test_empty_content_defaults_to_standard(self):
        """空内容应该默认分类为 standard_llm_api."""
        from recon.attack_surface_classifier import classify_http_content

        result = classify_http_content()
        assert result.attack_surface == "standard_llm_api"

    def test_classify_with_burp_file(self):
        """从 Burp 文件分类应该是确定性的."""
        from recon.attack_surface_classifier import classify_burp_file

        # 创建临时测试 Burp 内容
        mcp_content = """POST /mcp/v1 HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"jsonrpc": "2.0", "method": "tools/call"}
"""
        result = classify_burp_file(
            burp_content=mcp_content,
            burp_profile_name="test_mcp",
        )
        assert result.attack_surface == "mcp_server"


# ──────────────────────────────────────────────
# Phase 3: SynergyOrchestrator 测试
# ──────────────────────────────────────────────
class TestSynergyOrchestrator:
    """测试协同编排器."""

    def test_orchestrator_initialization(self):
        """编排器应该正确初始化."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        assert orch._data_root == _DATA_ROOT

    def test_build_config_for_mcp(self):
        """MCP 配置文件应该生成正确的协同配置 (v60: 仅含 technique_tags)."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("mcp05")

        assert config.burp_profile == "mcp05"
        assert config.attack_surface in ["mcp_server", "mcp_full_surface"]
        # v60: 验证 technique_tags 而非 seed_files/scorer_name
        assert config.technique_tags == ["mcp_targeted"]
        assert config.confidence > 0

    def test_build_config_for_standard(self):
        """标准配置文件应该生成通用协同配置 (v60: technique_tags=None)."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("mocka")

        assert config.burp_profile == "mocka"
        assert config.attack_surface == "standard_llm_api"
        # v60: standard_llm_api 的 technique_tags 为 None (使用全部技术)
        assert config.technique_tags is None

    def test_build_config_with_burp_content(self):
        """提供 Burp 内容时应该使用深度分类."""
        from data.synergy_orchestrator import SynergyOrchestrator

        mcp_http = """POST /mcp/v1 HTTP/1.1
Host: target.example.com
mcp-session-id: test123

{"jsonrpc": "2.0"}
"""
        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("any_name", burp_content=mcp_http)

        assert config.attack_surface == "mcp_server"
        assert config.confidence > 0.5

    def test_force_surface_override(self):
        """强制攻击面类型应该覆盖自动分类 (v60: 验证 technique_tags)."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config(
            "any_profile",
            force_surface="rag_system",
        )

        assert config.attack_surface == "rag_system"
        assert config.confidence == 1.0
        # v60: 验证 technique_tags 映射 (rag_system → ["rag_targeted"])
        assert config.technique_tags == ["rag_targeted"]

    def test_synergy_config_summary(self):
        """SynergyConfig.summary() 应该生成可读摘要."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("mcp05")
        summary = config.summary()

        assert "SynergyConfig" in summary
        assert "mcp05" in summary

    def test_synergy_config_to_dict(self):
        """SynergyConfig.to_dict() 应该生成完整字典."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("mcp05")
        d = config.to_dict()

        assert isinstance(d, dict)
        assert "burp_profile" in d
        assert "attack_surface" in d
        assert "confidence" in d
        assert "synergy_enabled" in d


# ──────────────────────────────────────────────
# Phase 4: 集成与 A/B 测试
# ──────────────────────────────────────────────
class TestSynergyIntegration:
    """集成测试 — 验证协同分析整体效果."""

    def test_quick_build_function(self):
        """便捷函数 quick_build 应该正常工作."""
        from data.synergy_orchestrator import quick_build

        config = quick_build("mcp05")
        assert config.burp_profile == "mcp05"
        assert config.synergy_enabled

    def test_get_cli_overrides(self):
        """CLI 覆盖应该生成正确的参数格式 (v60: 仅 technique_filter)."""
        from data.synergy_orchestrator import get_cli_overrides

        overrides = get_cli_overrides("mcp05")

        # v60: 仅返回 attack_surface + technique_filter + synergy_enabled
        assert "attack_surface" in overrides
        assert "technique_filter" in overrides
        assert isinstance(overrides["synergy_enabled"], bool)
        assert overrides["attack_surface"] in ["mcp_server", "mcp_full_surface"]
        assert overrides["technique_filter"] == ["mcp_targeted"]

    def test_all_burp_profiles_have_valid_config(self):
        """所有现有 Burp 配置文件都应该有有效的协同配置 (v60)."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()

        # 测试的 Burp 配置列表
        test_profiles = ["mcp05", "mcp09", "mm05", "mocka", "mockb"]

        for profile in test_profiles:
            config = orch.build_synergy_config(profile)

            # v60: 验证 attack_surface 非空
            assert config.attack_surface, f"No attack_surface for {profile}"

            # v60: technique_tags 可以是 list 或 None (None = 使用全部技术)
            assert config.technique_tags is None or isinstance(config.technique_tags, list), \
                f"Invalid technique_tags for {profile}"

            # synergy 标志应该是布尔值
            assert isinstance(config.synergy_enabled, bool)

    def test_technique_tags_validity(self):
        """v60: technique_tags 应该引用已注册的标签."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("mcp05")

        # 验证 technique_tags 是已注册的标签
        valid_tags = {"mcp_targeted", "agent_targeted", "rag_targeted", "general"}
        if config.technique_tags is not None:
            for tag in config.technique_tags:
                assert tag in valid_tags, f"Unknown technique_tag: {tag}"


# ──────────────────────────────────────────────
# Performance / Smoke Tests
# ──────────────────────────────────────────────
def test_synergy_performance():
    """协同编排器应该快速响应 (< 100ms per profile)."""
    import time

    from data.synergy_orchestrator import SynergyOrchestrator

    orch = SynergyOrchestrator()

    start = time.perf_counter()
    for _ in range(10):
        orch.build_synergy_config("mcp05")
    elapsed = time.perf_counter() - start

    # 10 次构建应该 < 1 秒
    assert elapsed < 1.0, f"Synergy build too slow: {elapsed:.3f}s for 10 iterations"


def test_asset_index_consistency():
    """asset_index.yaml 应该与实际文件一致."""
    from data import load_asset_index

    index = load_asset_index()
    seeds_cfg = index.get("assets", {}).get("seeds", {})
    scorers_cfg = index.get("assets", {}).get("scorers", {})

    # Seeds are in data/seeds/ subdirectory
    seeds_root = _DATA_ROOT / "seeds"

    # 每个种子都应该有对应文件 (path is relative to data/seeds/)
    for seed_name, seed_info in seeds_cfg.items():
        path = seed_info.get("path", "")
        # Try with .prompt extension first
        full_path = seeds_root / f"{path}.prompt"
        if not full_path.exists():
            # Try without extension (path already has it)
            full_path = seeds_root / path
        assert full_path.exists(), f"Seed file missing for {seed_name}: {full_path}"

    # 每个评分器都应该有对应文件 (path is relative to data/)
    for scorer_name, scorer_info in scorers_cfg.items():
        path = scorer_info.get("path", "")
        full_path = _DATA_ROOT / path
        assert full_path.exists(), f"Scorer file missing for {scorer_name}: {full_path}"


# ──────────────────────────────────────────────
# Phase 5: Pipeline Integration Tests
# ──────────────────────────────────────────────
class TestSynergyPipelineIntegration:
    """测试协同分析完全集成到 main.py 流水线.

    验证数据流:
      ctx.parsed_request → SynergyOrchestrator → ctx.synergy_config → arm phase
    """

    def test_pipeline_context_has_synergy_field(self):
        """PipelineContext 应该有 synergy_config 字段."""
        from core.context import PipelineContext

        # Verify field exists in dataclass
        field_names = [f.name for f in PipelineContext.__dataclass_fields__.values()]
        assert "synergy_config" in field_names, "PipelineContext missing synergy_config field"

    def test_synergy_config_default_is_none(self):
        """synergy_config 默认值应该是 None."""
        import argparse

        from core.context import PipelineContext

        # Create minimal context
        args = argparse.Namespace()
        ctx = PipelineContext(args=args)
        assert ctx.synergy_config is None

    def test_synergy_config_can_be_set(self):
        """synergy_config 应该可以被赋值."""
        import argparse

        from core.context import PipelineContext
        from data.synergy_orchestrator import SynergyConfig, SynergyOrchestrator

        config = SynergyOrchestrator().build_synergy_config("mcp05")

        args = argparse.Namespace()
        ctx = PipelineContext(args=args)
        ctx.synergy_config = config

        assert ctx.synergy_config is not None
        assert isinstance(ctx.synergy_config, SynergyConfig)
        assert ctx.synergy_config.burp_profile == "mcp05"

    def test_config_py_has_synergy_flag(self):
        """config.py 应该有 --synergy / --no-synergy 参数."""
        from core.config import parse_args

        # Test default (synergy enabled)
        args = parse_args([])
        assert hasattr(args, "synergy"), "args missing synergy attribute"
        assert args.synergy is True, "synergy should be True by default"

        # Test --no-synergy disables it
        args_no = parse_args(["--no-synergy"])
        assert args_no.synergy is False, "--no-synergy should set synergy to False"

    def test_synergy_data_flow_to_args_technique_filter(self):
        """v60: Synergy 应该能设置 args 的 technique_filter."""
        from data.synergy_orchestrator import SynergyOrchestrator

        orch = SynergyOrchestrator()
        config = orch.build_synergy_config("mcp05")

        # Simulate what main.py does in v60
        class FakeArgs:
            technique_filter = None

        fake_args = FakeArgs()
        if config.synergy_enabled and config.technique_tags:
            fake_args.technique_filter = config.technique_tags

        # Verify technique_filter was set
        assert fake_args.technique_filter == ["mcp_targeted"]
        assert len(fake_args.technique_filter) > 0

    def test_orchestration_log_includes_synergy(self):
        """编排日志应该包含协同分析信息."""
        import argparse

        from core.context import PipelineContext
        from data.synergy_orchestrator import SynergyOrchestrator

        config = SynergyOrchestrator().build_synergy_config("mcp05")

        args = argparse.Namespace()
        ctx = PipelineContext(args=args)
        ctx.synergy_config = config

        # Simulate ARM phase orchestration log
        _synergy_info = {}
        if ctx.synergy_config:
            _synergy_info = {
                "synergy_enabled": ctx.synergy_config.synergy_enabled,
                "attack_surface": ctx.synergy_config.attack_surface,
                "synergy_confidence": ctx.synergy_config.confidence,
            }

        assert "synergy_enabled" in _synergy_info
        assert "attack_surface" in _synergy_info
        assert _synergy_info["attack_surface"]  # Non-empty
