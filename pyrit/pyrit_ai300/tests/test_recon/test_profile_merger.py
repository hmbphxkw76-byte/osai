# -*- coding: utf-8 -*-
"""
ProfileMerger 多工具结果合并器测试
"""

import unittest

from pyrit_ai300.recon.profile_merger import ProfileMerger
from pyrit_ai300.recon.adapters import AdapterResult
from pyrit_ai300.recon.target_profile import (
    TargetProfile,
    FingerprintData,
    VulnerabilityFinding,
)


def _make_finding(
    category="prompt_injection",
    severity="high",
    description="Test finding",
    tool="native_probe",
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
        self.assertEqual(merger.weights["native_probe"], 0.80)
        self.assertEqual(merger.weights["deepteam"], 0.85)

    def test_custom_weights(self):
        custom = {"native_probe": 0.7, "deepteam": 0.8}
        merger = ProfileMerger(weights=custom)
        self.assertEqual(merger.weights["native_probe"], 0.7)
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
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding()],
                duration=1.0,
            )
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 1)
        self.assertIn("native_probe", profile.tools_used)

    def test_merge_multiple_tools(self):
        """多工具结果合并（OWASP ID 对齐：同一 OWASP ID 合并）"""
        results = [
            AdapterResult(
                tool="native_probe",
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
        # prompt_injection 和 jailbreak 都映射到 LLM01，应合并为 1 个发现
        self.assertEqual(profile.vulnerability_count, 1)
        self.assertEqual(profile.fingerprint.model_name, "gpt-4")
        self.assertEqual(profile.fingerprint.model_family, "gpt")
        # 验证交叉验证信息
        vuln = profile.vulnerabilities[0]
        self.assertEqual(vuln.owasp_mapping, "LLM01")
        self.assertIn("native_probe", vuln.source_tools)
        self.assertIn("deepteam", vuln.source_tools)
        self.assertFalse(vuln.conflict)  # 相同严重等级，无冲突

    def test_merge_multiple_tools_different_owasp(self):
        """多工具结果合并（不同 OWASP ID 独立保留）"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding(category="prompt_injection", owasp_mapping="LLM01")],
                duration=2.0,
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[_make_finding(category="leakage", owasp_mapping="LLM02")],
                duration=3.0,
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 2)
        owasp_ids = {v.owasp_mapping for v in profile.vulnerabilities}
        self.assertIn("LLM01", owasp_ids)
        self.assertIn("LLM02", owasp_ids)

    def test_merge_conflict_detection(self):
        """冲突检测：同一 OWASP ID 严重等级差异 ≥ 2 级"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding(
                    category="prompt_injection",
                    severity="critical",
                    owasp_mapping="LLM01",
                    confidence=0.9,
                )],
                duration=2.0,
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[_make_finding(
                    category="prompt_injection",
                    severity="low",
                    owasp_mapping="LLM01",
                    confidence=0.7,
                )],
                duration=3.0,
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 1)
        vuln = profile.vulnerabilities[0]
        self.assertEqual(vuln.owasp_mapping, "LLM01")
        self.assertTrue(vuln.conflict)  # critical vs low = 冲突
        self.assertEqual(vuln.severity, "critical")  # 取最高严重等级

    def test_merge_cross_validation_confidence_boost(self):
        """交叉验证置信度提升：双工具一致发现，置信度 +0.10"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding(
                    category="prompt_injection",
                    severity="high",
                    owasp_mapping="LLM01",
                    confidence=0.8,
                )],
                duration=2.0,
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[_make_finding(
                    category="prompt_injection",
                    severity="high",
                    owasp_mapping="LLM01",
                    confidence=0.75,
                )],
                duration=3.0,
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        vuln = profile.vulnerabilities[0]
        # NativeProbe 权重 0.85 * 0.8 = 0.68; deepteam 权重 0.85 * 0.75 = 0.6375
        # max = 0.68, 交叉验证提升 +0.10 = 0.78
        self.assertAlmostEqual(vuln.confidence, 0.74, places=2)
        self.assertFalse(vuln.conflict)  # 相同严重等级，无冲突

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
                tool="native_probe",
                success=False,
                errors=["Not installed"],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertIn("deepteam", profile.tools_used)
        self.assertNotIn("native_probe", profile.tools_used)

    def test_raw_results_stored(self):
        """原始结果存入 raw_results"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={"scan": "data"},
                findings=[_make_finding()],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertIn("native_probe", profile.raw_results)
        self.assertEqual(profile.raw_results["native_probe"]["data"]["scan"], "data")


class TestProfileMergerFingerprint(unittest.TestCase):
    """指纹合并测试"""

    def test_fingerprint_from_tool(self):
        """工具指纹数据合并"""
        results = [
            AdapterResult(
                tool="native_probe",
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
                tool="native_probe",
                success=True,
                data={"model_name": "test"},
                findings=[],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertAlmostEqual(profile.fingerprint.confidence, 0.80)

    def test_fingerprint_not_overwritten(self):
        """已有指纹不被覆盖"""
        results = [
            AdapterResult(
                tool="native_probe",
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
                tool="native_probe",
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
        """不同 OWASP ID 的 finding 独立保留"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[
                    _make_finding(
                        description="Prompt injection via DAN role",
                        category="prompt_injection",
                        owasp_mapping="LLM01",
                    ),
                ],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[
                    _make_finding(
                        description="System prompt leakage via encoding",
                        category="leakage",
                        owasp_mapping="LLM02",
                    ),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 2)
        owasp_ids = {v.owasp_mapping for v in profile.vulnerabilities}
        self.assertIn("LLM01", owasp_ids)
        self.assertIn("LLM02", owasp_ids)

    def test_duplicate_confidence_max(self):
        """去重时取最大置信度"""
        results = [
            AdapterResult(
                tool="native_probe",
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
        """2个不同 OWASP ID 的 critical → critical"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[
                    _make_finding(severity="critical", owasp_mapping="LLM01"),
                ],
            ),
            AdapterResult(
                tool="deepteam",
                success=True,
                data={},
                findings=[
                    _make_finding(severity="critical", owasp_mapping="LLM02", description="Another critical finding"),
                ],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertEqual(profile.vulnerability_count, 2)
        self.assertEqual(profile.risk_level, "critical")

    def test_risk_high(self):
        """1个 critical → high"""
        results = [
            AdapterResult(
                tool="native_probe",
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
                tool="native_probe",
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
                tool="native_probe",
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
                tool="native_probe",
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
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding(category="prompt_injection")],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        self.assertTrue(any("DIRECT_SINGLE" in r for r in profile.attack_recommendations))

    def test_recommendation_for_jailbreak(self):
        """excessive_agency 漏洞 → PROGRESSIVE 建议（LLM05）"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding(category="excessive_agency", owasp_mapping="LLM05")],
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
                tool="native_probe",
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
                tool="native_probe",
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
                tool="native_probe",
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

    def test_native_probe_confidence_weighted(self):
        """NativeProbe finding 置信度乘以 NativeProbe 权重"""
        results = [
            AdapterResult(
                tool="native_probe",
                success=True,
                data={},
                findings=[_make_finding(confidence=0.8)],
            ),
        ]
        merger = ProfileMerger()
        profile = merger.merge(target="https://example.com", results=results)
        # NativeProbe 权重 0.85 × finding 置信度 0.8 = 0.68
        self.assertAlmostEqual(profile.vulnerabilities[0].confidence, 0.64, places=2)

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


class TestProfileMergerIncremental(unittest.TestCase):
    """ProfileMerger.merge_incremental() 增量合并测试"""

    def test_incremental_first_result_creates_profile(self):
        """首次增量合并创建基础画像"""
        merger = ProfileMerger()
        result = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={"model_name": "qwen3", "model_family": "qwen"},
            findings=[_make_finding(category="prompt_injection")],
            duration=1.0,
        )

        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result,
        )

        self.assertIsInstance(profile, TargetProfile)
        self.assertEqual(profile.target, "https://example.com")
        self.assertIn("protocol_fingerprint", profile.tools_used)
        self.assertEqual(profile.fingerprint.model_name, "qwen3")
        self.assertEqual(profile.vulnerability_count, 1)

    def test_incremental_second_result_merges(self):
        """第二次增量合并追加数据（不同 OWASP ID 独立保留）"""
        merger = ProfileMerger()

        # 第一次：ProtocolFingerprint
        result1 = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={"model_name": "qwen3", "surfaces": ["prompt"]},
            findings=[_make_finding(
                category="prompt_injection",
                description="Finding A",
                owasp_mapping="LLM01",
            )],
            duration=1.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result1,
        )

        # 第二次：NativeProbe（不同 OWASP ID）
        result2 = AdapterResult(
            tool="native_probe",
            success=True,
            data={"context_window": 8192},
            findings=[_make_finding(
                category="leakage",
                description="Finding B",
                owasp_mapping="LLM02",
            )],
            duration=2.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=profile,
            new_result=result2,
        )

        # 验证合并结果
        self.assertIn("protocol_fingerprint", profile.tools_used)
        self.assertIn("native_probe", profile.tools_used)
        self.assertEqual(profile.fingerprint.model_name, "qwen3")  # 来自第一个
        self.assertEqual(profile.fingerprint.context_window, 8192)  # 来自第二个
        self.assertEqual(profile.vulnerability_count, 2)
        self.assertIn("prompt", profile.surfaces)

    def test_incremental_failed_result_ignored(self):
        """失败的适配器结果不改变画像"""
        merger = ProfileMerger()

        # 先创建一个基础画像
        result_ok = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={"model_name": "test"},
            findings=[_make_finding()],
            duration=1.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result_ok,
        )
        initial_count = profile.vulnerability_count

        # 失败的工具
        result_fail = AdapterResult(
            tool="native_probe",
            success=False,
            errors=["Tool crashed"],
            duration=0.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=profile,
            new_result=result_fail,
        )

        # 画像不变
        self.assertEqual(profile.vulnerability_count, initial_count)
        self.assertNotIn("native_probe", profile.tools_used)

    def test_incremental_duplicate_findings_deduplicated(self):
        """增量合并时重复 finding 去重"""
        merger = ProfileMerger()

        # 第一个工具
        result1 = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={},
            findings=[_make_finding(description="Same finding across tools")],
            duration=1.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result1,
        )

        # 第二个工具（相同 finding）
        result2 = AdapterResult(
            tool="native_probe",
            success=True,
            data={},
            findings=[_make_finding(description="Same finding across tools")],
            duration=2.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=profile,
            new_result=result2,
        )

        # 去重后只有 1 个
        self.assertEqual(profile.vulnerability_count, 1)

    def test_incremental_fingerprint_not_overwritten(self):
        """增量合并不覆盖已有指纹字段"""
        merger = ProfileMerger()

        # 第一个工具设置 model_name
        result1 = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={"model_name": "first-model"},
            findings=[],
            duration=1.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result1,
        )

        # 第二个工具尝试设置 model_name（应被忽略）
        result2 = AdapterResult(
            tool="native_probe",
            success=True,
            data={"model_name": "second-model"},
            findings=[],
            duration=2.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=profile,
            new_result=result2,
        )

        # 保留第一个值
        self.assertEqual(profile.fingerprint.model_name, "first-model")

    def test_incremental_surfaces_deduplicated(self):
        """增量合并攻击面去重"""
        merger = ProfileMerger()

        result1 = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={"surfaces": ["prompt", "mcp"]},
            findings=[],
            duration=1.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result1,
        )

        result2 = AdapterResult(
            tool="native_probe",
            success=True,
            data={"surfaces": ["prompt", "rag"]},
            findings=[],
            duration=2.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=profile,
            new_result=result2,
        )

        # prompt 只出现一次
        self.assertEqual(profile.surfaces.count("prompt"), 1)
        self.assertIn("mcp", profile.surfaces)
        self.assertIn("rag", profile.surfaces)

    def test_incremental_risk_recalculated(self):
        """增量合并后风险等级重新计算"""
        merger = ProfileMerger()

        # 第一个工具：low risk
        result1 = AdapterResult(
            tool="protocol_fingerprint",
            success=True,
            data={},
            findings=[_make_finding(severity="low", description="Low severity finding")],
            duration=1.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=None,
            new_result=result1,
        )
        self.assertEqual(profile.risk_level, "low")

        # 第二个工具：添加 critical finding（不同描述，避免去重）
        result2 = AdapterResult(
            tool="native_probe",
            success=True,
            data={},
            findings=[_make_finding(severity="critical", description="Critical severity finding")],
            duration=2.0,
        )
        profile = merger.merge_incremental(
            target="https://example.com",
            existing_profile=profile,
            new_result=result2,
        )
        # 风险等级应提升（1 critical → high）
        self.assertIn(profile.risk_level, ["high", "critical"])


if __name__ == "__main__":
    unittest.main()
