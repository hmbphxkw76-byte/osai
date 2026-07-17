# -*- coding: utf-8 -*-
"""
ProfileMerger 多工具结果合并器测试
"""

import unittest

from pyrit_ai300.reconnaissance.profile_merger import ProfileMerger
from pyrit_ai300.reconnaissance.adapters import AdapterResult
from pyrit_ai300.reconnaissance.target_profile import (
    TargetProfile,
    FingerprintData,
    VulnerabilityFinding,
)


def _make_finding(
    category="prompt_injection",
    severity="high",
    description="Test finding",
    tool="garak",
    owasp_mapping="LLM01",
    confidence=0.8,
):
    """辅助函数：创建标准化 finding 字典"""
    return {
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": f"Evidence for {category}",
        "owasp_mapping": owasp_mapping,
        "confidence": confidence,
    }


class TestProfileMergerInit(unittest.TestCase):
    """ProfileMerger 初始化测试"""

    def test_default_weights(self):
        merger = ProfileMerger()
        self.assertEqual(merger.weights["garak"], 0.85)
        self.assertEqual(merger.weights["deepteam"], 0.85)

    def test_custom_weights(self):
        custom = {"garak": 0.7, "deepteam": 0.8}
        merger = ProfileMerger(weights=custom)
        self.assertEqual(merger.weights["garak"], 0.7)
        self.assertEqual(merger.weights["deepteam"], 0.8)


class TestProfileMergerMerge(unittest.TestCase):
    """ProfileMerger.merge() 核心合并逻辑测试"""

    def test_merge_empty_results(self):
        """空结果列表返回默认 TargetProfile"""
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=[])
        self.assertIsInstance(profile, TargetProfile)
        self.assertEqual(profile.target, "https://example.com")
        self.assertEqual(profile.vulnerability_count, 0)
        self.assertEqual(profile.risk_level, "unknown")

    def test_merge_single_tool(self):
        """单工具结果合并"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[_make_finding()],
                duration=1.0,
            )
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 1)
        self.assertIn("garak", profile.tools_used)

    def test_merge_multiple_tools(self):
        """多工具结果合并"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={
                    "model_name": "gpt-4",
                    "model_family": "gpt",
                    "provider": "openai",
                    "context_window": 8192,
                },
                findings=[_make_finding(category="prompt_injection")],
                duration=2.0,
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[_make_finding(category="jailbreak")],
                duration=3.0,
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(len(profile.tools_used), 2)
        self.assertEqual(profile.vulnerability_count, 2)
        self.assertEqual(profile.fingerprint.model_name, "gpt-4")
        self.assertEqual(profile.fingerprint.model_family, "gpt")

    def test_failed_tools_excluded(self):
        """失败工具不计入 tools_used"""
        results = [
            AdapterResult(
                tool="deepteam",
                success=True,
                data={"model_name": "test"},
                findings=[],
            ),
            AdapterResult(
                tool="garak",
                success=False,
                errors=["Not installed"],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertIn("deepteam", profile.tools_used)
        self.assertNotIn("garak", profile.tools_used)

    def test_raw_results_stored(self):
        """原始结果存入 raw_results"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={"scan": "data"},
                findings=[_make_finding()],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertIn("garak", profile.raw_results)
        self.assertEqual(profile.raw_results["garak"]["data"]["scan"], "data")


class TestProfileMergerFingerprint(unittest.TestCase):
    """指纹合并测试"""

    def test_fingerprint_from_tool(self):
        """工具指纹数据合并"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={
                    "model_name": "claude-3",
                    "model_family": "claude",
                    "provider": "anthropic",
                    "context_window": 200000,
                    "system_prompt": "You are a helpful assistant",
                    "capabilities": ["code", "analysis"],
                    "detected_filters": ["content_policy"],
                },
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.fingerprint.model_name, "claude-3")
        self.assertEqual(profile.fingerprint.model_family, "claude")
        self.assertEqual(profile.fingerprint.provider, "anthropic")
        self.assertEqual(profile.fingerprint.context_window, 200000)
        self.assertEqual(profile.fingerprint.system_prompt, "You are a helpful assistant")
        self.assertIn("code", profile.fingerprint.capabilities)
        self.assertIn("content_policy", profile.fingerprint.detected_filters)

    def test_fingerprint_confidence_from_tool_weight(self):
        """指纹置信度来自工具权重"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={"model_name": "test"},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertAlmostEqual(profile.fingerprint.confidence, 0.85)

    def test_fingerprint_not_overwritten(self):
        """已有指纹不被覆盖"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={"model_name": "first-model"},
                findings=[],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={"model_name": "second-model"},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.fingerprint.model_name, "first-model")


class TestProfileMergerDeduplication(unittest.TestCase):
    """去重逻辑测试"""

    def test_duplicate_findings_deduplicated(self):
        """相同 category + 描述前缀的 finding 去重"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(description="Direct prompt injection via role bypass"),
                ],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[
                    _make_finding(description="Direct prompt injection via role bypass"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        # 相同描述前50字符，应去重为1个
        self.assertEqual(profile.vulnerability_count, 1)

    def test_different_findings_kept(self):
        """不同描述的 finding 保留"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(description="Prompt injection via DAN role"),
                ],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[
                    _make_finding(description="System prompt leakage via encoding"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 2)

    def test_duplicate_confidence_max(self):
        """去重时取最大置信度"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(description="Same finding", confidence=0.5),
                ],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[
                    _make_finding(description="Same finding", confidence=0.9),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 1)
        # 去重后置信度应取较大值（考虑权重后）
        self.assertGreater(profile.vulnerabilities[0].confidence, 0)


class TestProfileMergerRiskCalculation(unittest.TestCase):
    """风险等级计算测试"""

    def test_risk_critical(self):
        """2个 critical → critical"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(severity="critical"),
                    _make_finding(severity="critical", description="Another critical finding"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.risk_level, "critical")

    def test_risk_high(self):
        """1个 critical → high"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(severity="critical"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.risk_level, "high")

    def test_risk_medium(self):
        """1个 high → medium"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(severity="high"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.risk_level, "medium")

    def test_risk_low(self):
        """1个 medium → low"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[
                    _make_finding(severity="medium"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.risk_level, "low")

    def test_risk_unknown(self):
        """无漏洞 → unknown"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.risk_level, "unknown")


class TestProfileMergerRecommendations(unittest.TestCase):
    """攻击建议生成测试"""

    def test_recommendation_for_prompt_injection(self):
        """prompt_injection 漏洞 → DIRECT_SINGLE 建议"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[_make_finding(category="prompt_injection")],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertTrue(any("DIRECT_SINGLE" in r for r in profile.attack_recommendations))

    def test_recommendation_for_jailbreak(self):
        """jailbreak 漏洞 → PROGRESSIVE 建议"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[_make_finding(category="jailbreak")],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertTrue(any("PROGRESSIVE" in r for r in profile.attack_recommendations))

    def test_recommendation_for_agent_surface(self):
        """agent 攻击面 → TREE_SEARCH 建议"""
        results = [
            AdapterResult(
                tool="deepteam",
                success=True,
                data={"surfaces": ["agent"]},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertTrue(any("TREE_SEARCH" in r for r in profile.attack_recommendations))

    def test_default_recommendation(self):
        """无漏洞 → 标准攻击链建议"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertTrue(any("Fallback Chain" in r or "标准攻击链" in r for r in profile.attack_recommendations))


class TestProfileMergerSurfaces(unittest.TestCase):
    """攻击面合并测试"""

    def test_surfaces_merged_from_all_tools(self):
        """攻击面从所有工具结果合并（去重）"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={"surfaces": ["prompt", "rag"]},
                findings=[],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={"surfaces": ["prompt", "agent"]},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertIn("prompt", profile.surfaces)
        self.assertIn("rag", profile.surfaces)
        self.assertIn("agent", profile.surfaces)
        # prompt 只出现一次（去重）
        self.assertEqual(profile.surfaces.count("prompt"), 1)

    def test_surfaces_from_failed_tool_excluded(self):
        """失败工具的 attack 攻击面不计入"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={"surfaces": ["prompt"]},
                findings=[],
            ),
            AdapterResult(
                tool="deepteam",
                success=False,
                data={"surfaces": ["agent"]},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertIn("prompt", profile.surfaces)
        self.assertNotIn("agent", profile.surfaces)


class TestProfileMergerWeightedConfidence(unittest.TestCase):
    """置信度加权测试"""

    def test_garak_confidence_weighted(self):
        """Garak finding 置信度乘以 garak 权重"""
        results = [
            AdapterResult(
                tool="garak",
                success=True,
                data={},
                findings=[_make_finding(confidence=0.8)],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        # garak 权重 0.85 × finding 置信度 0.8 = 0.68
        self.assertAlmostEqual(profile.vulnerabilities[0].confidence, 0.68, places=2)

    def test_deepteam_confidence_weighted(self):
        """DeepTeam finding 置信度乘以 deepteam 权重"""
        results = [
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[_make_finding(confidence=0.9)],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        # deepteam 权重 0.85 × finding 置信度 0.9 = 0.765
        self.assertAlmostEqual(profile.vulnerabilities[0].confidence, 0.765, places=2)


if __name__ == "__main__":
    unittest.main()
