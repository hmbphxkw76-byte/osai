# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""MCP 攻击载荷 YAML 加载测试 — 验证 YAML 优先 + 硬编码回退逻辑。

测试覆盖:
  - mcp_attack._load_probes_from_yaml() / _get_mcp_probes()
  - advanced_mcp_attacks._load_advanced_probes_from_yaml() / _get_advanced_probes()
  - advanced_mcp_attacks._load_kill_chains_from_yaml() / _get_kill_chains()

> **日期**: 2026-8-5
"""

from __future__ import annotations

from unittest.mock import patch

# ============================================================
# mcp_attack._load_probes_from_yaml / _get_mcp_probes
# ============================================================


class TestLoadMCPProbesFromYAML:
    """``mcp_attack._load_probes_from_yaml`` YAML 加载测试。."""

    def test_yaml_load_success(self) -> None:
        """YAML 文件存在且格式正确时成功加载。."""
        from pipeline.scenarios.mcp_attack import _load_probes_from_yaml

        probes = _load_probes_from_yaml()
        assert probes is not None
        assert len(probes) == 8
        # 验证第一个探针结构
        first = probes[0]
        assert first[0] == "resource_injection"
        assert first[1] == "resource"
        assert isinstance(first[2], str)
        assert "system prompt" in first[3]
        assert first[4] == "critical"

    def test_yaml_returns_none_when_file_missing(self) -> None:
        """YAML 文件不存在时返回 None。."""
        from pipeline.scenarios import mcp_attack

        with patch.object(mcp_attack, "_YAML_PATH") as mock_path:
            mock_path.exists.return_value = False
            result = mcp_attack._load_probes_from_yaml()
            assert result is None

    def test_yaml_returns_none_when_section_empty(self) -> None:
        """YAML 中 mcp_protocol_probes 段为空时返回 None。."""
        from pipeline.scenarios import mcp_attack

        with patch("builtins.open", create=True), \
             patch("yaml.safe_load", return_value={"mcp_protocol_probes": []}), \
             patch.object(mcp_attack, "_YAML_PATH") as mock_path:
            mock_path.exists.return_value = True
            result = mcp_attack._load_probes_from_yaml()
            assert result is None


class TestGetMCPProbes:
    """``mcp_attack._get_mcp_probes`` YAML 优先 + 回退测试。."""

    def test_fallback_to_hardcoded_when_yaml_none(self) -> None:
        """YAML 返回 None 时回退到硬编码 _MCP_ATTACK_PROBES。."""
        from pipeline.scenarios import mcp_attack

        with patch.object(mcp_attack, "_load_probes_from_yaml", return_value=None):
            probes = mcp_attack._get_mcp_probes()
            assert len(probes) == len(mcp_attack._MCP_ATTACK_PROBES)
            assert probes[0][0] == mcp_attack._MCP_ATTACK_PROBES[0][0]

    def test_yaml_takes_priority_over_hardcoded(self) -> None:
        """YAML 返回非 None 时优先于硬编码。."""
        from pipeline.scenarios import mcp_attack

        custom_probes = [("custom_probe", "tool", "payload", ["kw"], "low")]
        with patch.object(mcp_attack, "_load_probes_from_yaml", return_value=custom_probes):
            probes = mcp_attack._get_mcp_probes()
            assert probes == custom_probes


# ============================================================
# advanced_mcp_attacks._load_advanced_probes_from_yaml / _get_advanced_probes
# ============================================================


class TestLoadAdvancedProbesFromYAML:
    """``advanced_mcp_attacks._load_advanced_probes_from_yaml`` 测试。."""

    def test_yaml_load_success(self) -> None:
        """YAML 文件存在且格式正确时成功加载。."""
        from pipeline.scenarios.advanced_mcp_attacks import _load_advanced_probes_from_yaml

        probes = _load_advanced_probes_from_yaml()
        assert probes is not None
        assert len(probes) == 6
        # 验证第一个探针结构
        first = probes[0]
        assert first[0] == "cross_server_trust_chain"
        assert first[1] == "tool"
        assert isinstance(first[2], str)
        assert "whatsapp" in first[3]
        assert first[4] == "critical"
        # 验证 OWASP 代码已转为枚举
        from pipeline.assessment.framework_mapper import OWASPAgenticCode

        assert OWASPAgenticCode.ASI07 in first[5]
        assert OWASPAgenticCode.ASI02 in first[5]
        # 验证 AI-VSS 修饰符已转为枚举
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier

        assert AIVSSModifier.CASCADING in first[6]
        assert AIVSSModifier.STEALTH in first[6]

    def test_yaml_returns_none_when_file_missing(self) -> None:
        """YAML 文件不存在时返回 None。."""
        from pipeline.scenarios import advanced_mcp_attacks

        with patch.object(advanced_mcp_attacks, "_YAML_PATH") as mock_path:
            mock_path.exists.return_value = False
            result = advanced_mcp_attacks._load_advanced_probes_from_yaml()
            assert result is None


class TestGetAdvancedProbes:
    """``advanced_mcp_attacks._get_advanced_probes`` 测试。."""

    def test_fallback_to_hardcoded(self) -> None:
        """YAML 返回 None 时回退到硬编码。."""
        from pipeline.scenarios import advanced_mcp_attacks

        with patch.object(advanced_mcp_attacks, "_load_advanced_probes_from_yaml", return_value=None):
            probes = advanced_mcp_attacks._get_advanced_probes()
            assert len(probes) == len(advanced_mcp_attacks._ADVANCED_MCP_PROBES)


# ============================================================
# advanced_mcp_attacks._load_kill_chains_from_yaml / _get_kill_chains
# ============================================================


class TestLoadKillChainsFromYAML:
    """``advanced_mcp_attacks._load_kill_chains_from_yaml`` 测试。."""

    def test_yaml_load_success(self) -> None:
        """YAML 文件存在且格式正确时成功加载。."""
        from pipeline.scenarios.advanced_mcp_attacks import _load_kill_chains_from_yaml

        chains = _load_kill_chains_from_yaml()
        assert chains is not None
        assert len(chains) == 3
        # 验证第一个 Kill Chain 结构
        first = chains[0]
        assert first["name"] == "DockerDash Full Kill Chain"
        assert len(first["chain_steps"]) == 4
        assert isinstance(first["payload"], str)
        assert "docker_ps" in first["expected_keywords"]
        # 验证 OWASP 代码已转为枚举
        from pipeline.assessment.framework_mapper import OWASPAgenticCode

        assert OWASPAgenticCode.ASI01 in first["owasp_codes"]
        # 验证修饰符已转为枚举
        from pipeline.scoring.ai_vss_scorer import AIVSSModifier

        assert AIVSSModifier.CASCADING in first["modifiers"]

    def test_yaml_returns_none_when_file_missing(self) -> None:
        """YAML 文件不存在时返回 None。."""
        from pipeline.scenarios import advanced_mcp_attacks

        with patch.object(advanced_mcp_attacks, "_YAML_PATH") as mock_path:
            mock_path.exists.return_value = False
            result = advanced_mcp_attacks._load_kill_chains_from_yaml()
            assert result is None


class TestGetKillChains:
    """``advanced_mcp_attacks._get_kill_chains`` 测试。."""

    def test_fallback_to_hardcoded(self) -> None:
        """YAML 返回 None 时回退到硬编码。."""
        from pipeline.scenarios import advanced_mcp_attacks

        with patch.object(advanced_mcp_attacks, "_load_kill_chains_from_yaml", return_value=None):
            chains = advanced_mcp_attacks._get_kill_chains()
            assert len(chains) == len(advanced_mcp_attacks._KILL_CHAINS)
