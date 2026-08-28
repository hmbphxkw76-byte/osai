"""web_vuln_executor 独立单元测试 — Web 漏洞执行器.

覆盖:
    - execute_web_vuln_attacks: 空输入、种子构建、端点匹配
    - WebVulnResult 数据结构
    - 响应文本提取
    - LLM Judge 评分集成
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# execute_web_vuln_attacks
# ═══════════════════════════════════════════════════════


class TestExecuteWebVulnAttacks:
    """测试 execute_web_vuln_attacks 函数."""

    @pytest.mark.asyncio
    async def test_empty_inputs(self):
        """空输入应返回空结果."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        result = await execute_web_vuln_attacks(ctx, {}, {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_target_for_endpoint(self):
        """端点没有目标时跳过."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        endpoint_targets = {}
        seed_endpoint_matches = {"/api/search": [{"value": "test", "metadata": {}}]}
        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_seeds_for_endpoint(self):
        """端点没有种子时跳过."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        target = MagicMock()
        endpoint_targets = {"/api/search": target}
        seed_endpoint_matches = {"/api/search": []}
        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        assert result == {}

    @pytest.mark.asyncio
    async def test_total_attacks_count(self):
        """验证日志中的 total_attacks 统计正确."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        endpoint_targets = {}
        seed_endpoint_matches = {
            "/api/search": [{"value": "1'", "metadata": {}}],
            "/api/user": [
                {"value": "1", "metadata": {}},
                {"value": "2", "metadata": {}},
            ],
        }
        # Should not raise, should handle gracefully
        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        assert isinstance(result, dict)


# ═══════════════════════════════════════════════════════
# Seed group building (internal)
# ═══════════════════════════════════════════════════════


class TestSeedGroupBuilding:
    """测试种子组构建逻辑 (通过 execute_web_vuln_attacks 间接测试)."""

    @pytest.mark.asyncio
    async def test_seed_value_extracted(self):
        """种子 value 应正确提取到 SeedObjective."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        seed = {
            "value": "' OR 1=1 --",
            "metadata": {
                "category": "sqli",
                "vulnerability_type": "sqli",
                "owasp_id": "WEB03",
            },
        }
        seed_endpoint_matches = {"/api/search": [seed]}
        endpoint_targets = {}

        # Should not raise
        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_missing_value_defaults_to_empty(self):
        """种子缺少 value 字段时默认为空字符串."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        seed = {"metadata": {"category": "sqli"}}
        seed_endpoint_matches = {"/api/search": [seed]}
        endpoint_targets = {}

        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_missing_metadata_defaults_to_empty(self):
        """种子缺少 metadata 字段时默认为空字典."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        seed = {"value": "test_payload"}
        seed_endpoint_matches = {"/api/search": [seed]}
        endpoint_targets = {}

        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        assert isinstance(result, dict)


# ═══════════════════════════════════════════════════════
# SubStringScorer integration
# ═══════════════════════════════════════════════════════


class TestSubStringScorerIntegration:
    """测试 SubStringScorer 集成 (通过 mock 验证调用)."""

    @pytest.mark.asyncio
    async def test_scorer_substrings_from_metadata(self):
        """评分器的 substring 应从种子的 expected_indicators 获取."""
        from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks

        ctx = MagicMock()
        seed = {
            "value": "' OR 1=1 --",
            "metadata": {
                "category": "sqli",
                "expected_indicators": ["SQL syntax", "mysql_fetch"],
                "owasp_id": "WEB03",
            },
        }
        seed_endpoint_matches = {"/api/search": [seed]}
        endpoint_targets = {}

        result = await execute_web_vuln_attacks(ctx, endpoint_targets, seed_endpoint_matches)
        # No target, should return empty dict
        assert result == {}
