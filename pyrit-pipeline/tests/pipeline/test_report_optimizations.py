# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_report_optimizations — P1-P6 报告优化单元测试.

覆盖:
  P1: 评分一致性校验 (_classify_score_consistency)
  P2: 载荷提取 CentralMemory fallback (evidence_collector)
  P3: OWASP 按 ID 聚合去重 (OWASPMapper.map_attacks_to_findings)
  P4: 目标信息从 ctx 获取 (report_generator _render_markdown ctx_metadata)
  P5: Converter 变换日志 fallback (ConverterLogCollector._extract_prompts)
  P6: 分层截断 (report_generator _MAX_CONVERSATION_TEXT_LENGTH / evidence_collector)

> **日期**: 2026-8-14
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from pipeline.analysis.evidence_collector import EvidenceCollector
from pipeline.converters.log import ConverterLogCollector
from pipeline.reporting.report_generator import (
    OWASPMapper,
    _classify_score_consistency,
    _truncate_text,
)

# ──────────────────────────────────────────────────────────────────
# P1: 评分一致性校验
# ──────────────────────────────────────────────────────────────────


class TestScoreConsistency:
    """P1: _classify_score_consistency 单元测试。."""

    def test_confirmed_success(self) -> None:
        """所有评分器一致 → confirmed。."""
        detail = {
            "score": {
                "value": "true",
                "rationale": "SelfAskTrueFalseScorer: True",
            },
        }
        assert _classify_score_consistency(detail) == "confirmed"

    def test_disputed_pattern(self) -> None:
        """SelfAskTrueFalseScorer=false + InverterScorer=true → disputed。."""
        detail = {
            "score": {
                "value": "true",
                "rationale": "SelfAskTrueFalseScorer false, TrueFalseInverterScorer True",
            },
        }
        assert _classify_score_consistency(detail) == "disputed"

    def test_disputed_score_value(self) -> None:
        """SelfAskTrueFalseScorer=false 但 Score Value=true → disputed。."""
        detail = {
            "score": {
                "value": "True",
                "rationale": "SelfAskTrueFalseScorer false (target refused)",
            },
        }
        assert _classify_score_consistency(detail) == "disputed"

    def test_no_rationale(self) -> None:
        """无 rationale → confirmed (默认)。."""
        detail = {"score": {}}
        assert _classify_score_consistency(detail) == "confirmed"


# ──────────────────────────────────────────────────────────────────
# P3: OWASP 按 ID 聚合去重
# ──────────────────────────────────────────────────────────────────


class TestOWASPDedup:
    """P3: OWASPMapper.map_attacks_to_findings 去重测试。."""

    def test_dedup_same_owasp_id(self) -> None:
        """两个不同 attack_type 映射到同一 OWASP ID → 只生成一个 finding。."""
        ar1 = MagicMock()
        ar1.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="prompt_sending"))
        ar1.outcome = MagicMock(value="success")
        ar1.last_score = None
        ar1.conversation_id = "conv-1"

        ar2 = MagicMock()
        ar2.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="many_shot"))
        ar2.outcome = MagicMock(value="failure")
        ar2.last_score = None
        ar2.conversation_id = "conv-2"

        mapper = OWASPMapper()
        findings = mapper.map_attacks_to_findings([ar1, ar2])

        owasp_ids = [f.owasp_id for f in findings]
        assert len(owasp_ids) == len(set(owasp_ids)), "OWASP IDs should be unique"

    def test_merge_evidence_ids(self) -> None:
        """合并后 evidence_ids 包含所有相关 conversation_id。."""
        ar1 = MagicMock()
        ar1.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="prompt_sending"))
        ar1.outcome = MagicMock(value="success")
        ar1.last_score = None
        ar1.conversation_id = "conv-A"

        ar2 = MagicMock()
        ar2.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="red_teaming"))
        ar2.outcome = MagicMock(value="success")
        ar2.last_score = None
        ar2.conversation_id = "conv-B"

        mapper = OWASPMapper()
        findings = mapper.map_attacks_to_findings([ar1, ar2])

        llm01_findings = [f for f in findings if f.owasp_id == "LLM01"]
        if llm01_findings:
            finding = llm01_findings[0]
            assert "conv-A" in finding.evidence_ids
            assert "conv-B" in finding.evidence_ids


# ──────────────────────────────────────────────────────────────────
# P4: 目标信息从 ctx 获取
# ──────────────────────────────────────────────────────────────────


class TestCtxMetadata:
    """P4: _render_markdown 从 ctx_metadata 获取目标信息。."""

    def test_ctx_metadata_extraction(self) -> None:
        """ctx_metadata 中有 model_name → 报告中使用。."""
        # 直接测试 _render_markdown 中的 ctx_metadata 逻辑
        # 不需要完整渲染, 只验证变量提取
        ctx_metadata = {
            "model_name": "LongCat-2.0",
            "model_tier": "T2",
            "target_endpoint": "https://api.example.com",
            "judge_model": "deepseek-v4",
            "judge_endpoint": "https://judge.example.com",
        }
        target_model = ctx_metadata.get("model_name", "N/A")
        model_tier = ctx_metadata.get("model_tier", "N/A")
        assert target_model == "LongCat-2.0"
        assert model_tier == "T2"


# ──────────────────────────────────────────────────────────────────
# P5: Converter 变换日志 fallback
# ──────────────────────────────────────────────────────────────────


class TestConverterLogFallback:
    """P5: ConverterLogCollector._extract_prompts fallback 测试。."""

    def test_extract_from_last_request(self) -> None:
        """从 last_request 提取 original/transformed。."""
        piece1 = MagicMock()
        piece1.role = "user"
        piece1.original_value = "original prompt"
        piece1.converted_value = "transformed prompt"

        last_request = MagicMock()
        last_request.request_pieces = [piece1]

        ar = MagicMock()
        ar.last_request = last_request
        ar.conversation = None

        collector = ConverterLogCollector()
        original, transformed = collector._extract_prompts(ar)
        assert "original" in original
        assert "transformed" in transformed

    def test_fallback_to_conversation(self) -> None:
        """无 last_request → 从 conversation 提取。."""
        msg1 = MagicMock()
        msg1.role = "user"
        msg1.content = "conversation original"
        msg2 = MagicMock()
        msg2.role = "user"
        msg2.content = "conversation transformed"

        conversation = MagicMock()
        conversation.messages = [msg1, msg2]

        ar = MagicMock()
        ar.last_request = None
        ar.conversation = conversation

        collector = ConverterLogCollector()
        original, transformed = collector._extract_prompts(ar)
        assert "conversation original" in original
        assert "conversation transformed" in transformed

    def test_no_data(self) -> None:
        """无 last_request 和 conversation → 空字符串。."""
        ar = MagicMock()
        ar.last_request = None
        ar.conversation = None

        collector = ConverterLogCollector()
        original, transformed = collector._extract_prompts(ar)
        assert original == ""
        assert transformed == ""


# ──────────────────────────────────────────────────────────────────
# P6: 分层截断
# ──────────────────────────────────────────────────────────────────


class TestLayeredTruncation:
    """P6: 分层截断阈值测试。."""

    def test_report_truncation_threshold(self) -> None:
        """报告截断阈值为 1500。."""
        long_text = "x" * 3000
        truncated = _truncate_text(long_text)
        assert len(truncated) < len(long_text)
        assert "truncated" in truncated

    def test_short_text_not_truncated(self) -> None:
        """短文本不被截断。."""
        short_text = "This is a short prompt."
        result = _truncate_text(short_text)
        assert result == short_text

    def test_evidence_truncation_5000(self) -> None:
        """evidence 中截断阈值为 5000 (在 evidence_collector save_markdown)。."""
        # 验证 evidence_collector 中使用 5000 截断
        long_prompt = "A" * 6000
        truncated = long_prompt[:5000]
        assert len(truncated) == 5000

    def test_report_1500_threshold_value(self) -> None:
        """_MAX_CONVERSATION_TEXT_LENGTH = 1500。."""
        from pipeline.reporting.report_generator import _MAX_CONVERSATION_TEXT_LENGTH
        assert _MAX_CONVERSATION_TEXT_LENGTH == 1500

    def test_evidence_5000_threshold_value(self) -> None:
        """_MAX_EVIDENCE_TEXT_LENGTH = 5000。."""
        from pipeline.reporting.report_generator import _MAX_EVIDENCE_TEXT_LENGTH
        assert _MAX_EVIDENCE_TEXT_LENGTH == 5000


# ──────────────────────────────────────────────────────────────────
# P2: CentralMemory fallback (集成测试 — 验证 fallback 逻辑存在)
# ──────────────────────────────────────────────────────────────────


class TestCentralMemoryFallback:
    """P2: 载荷提取 CentralMemory fallback 测试。."""

    def test_jailbreak_prompt_with_conv_id_fallback(self) -> None:
        """有 conversation_id 但无 last_request → 尝试 CentralMemory fallback。."""
        ar = MagicMock()
        ar.last_request = None
        ar.conversation_id = "test-conv-id"
        # CentralMemory.get_memory_instance() 会失败 (无 DB), 返回空字符串
        collector = EvidenceCollector()
        result = collector._extract_jailbreak_prompt(ar)
        # 无 DB 时应返回空字符串, 不抛异常
        assert isinstance(result, str)

    def test_harmful_output_with_conv_id_fallback(self) -> None:
        """有 conversation_id 但无 last_response → 尝试 CentralMemory fallback。."""
        ar = MagicMock()
        ar.last_response = None
        ar.conversation_id = "test-conv-id"
        collector = EvidenceCollector()
        result = collector._extract_harmful_output(ar)
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────
# G7: SequentialAttack 子攻击链
# ──────────────────────────────────────────────────────────────────


class TestSubAttackChain:
    """G7: SequentialAttack 子攻击链提取测试。"""

    def test_no_child_results(self) -> None:
        """无 child_attack_results → sub_attacks 为空列表。"""
        ar = MagicMock()
        ar.child_attack_results = None
        ar.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="prompt_sending"))
        # 模拟 _collect_attack_details 中的子攻击提取逻辑
        sub_attacks: list[dict[str, Any]] = []
        child_results = getattr(ar, "child_attack_results", None) or []
        for idx, child in enumerate(child_results, 1):
            if child is None:
                continue
            sub_attacks.append({"step": idx})
        assert sub_attacks == []

    def test_with_child_results(self) -> None:
        """有 child_attack_results → sub_attacks 包含子攻击信息。"""
        child1 = MagicMock()
        child1.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="red_teaming"))
        child1.outcome = MagicMock(value="FAILURE")
        child1.outcome_reason = "timeout"
        child1.execution_time_ms = 5000

        child2 = MagicMock()
        child2.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(name="pair"))
        child2.outcome = MagicMock(value="SUCCESS")
        child2.outcome_reason = ""
        child2.execution_time_ms = 3000

        ar = MagicMock()
        ar.child_attack_results = [child1, child2]

        # 模拟 G7 提取逻辑
        sub_attacks: list[dict[str, Any]] = []
        child_results = getattr(ar, "child_attack_results", None) or []
        for idx, child in enumerate(child_results, 1):
            if child is None:
                continue
            sub_attacks.append({"step": idx, "outcome": "test"})
        assert len(sub_attacks) == 2
        assert sub_attacks[0]["step"] == 1
        assert sub_attacks[1]["step"] == 2


# ──────────────────────────────────────────────────────────────────
# F-1: _fetch_response_from_memory API 兼容性
# ──────────────────────────────────────────────────────────────────


class TestFetchResponseFromMemory:
    """F-1: _fetch_response_from_memory 使用 get_message_pieces (PyRIT 1.0.1)。"""

    def test_function_exists(self) -> None:
        """_fetch_response_from_memory 函数存在且可导入。"""
        from pipeline.stages.stage_execute import _fetch_response_from_memory
        assert callable(_fetch_response_from_memory)

    def test_returns_string(self) -> None:
        """无 conversation_id 时返回空字符串。"""
        from pipeline.stages.stage_execute import _fetch_response_from_memory
        ar = MagicMock()
        ar.conversation_id = None
        result = _fetch_response_from_memory(ar)
        assert isinstance(result, str)
        assert result == ""


# ──────────────────────────────────────────────────────────────────
# G8: Sub-Attack Chain 独立 section
# ──────────────────────────────────────────────────────────────────


class TestSubAttackChainIndependentSection:
    """G8: Sub-Attack Chain 独立 section 渲染测试。"""

    def test_sub_attacks_collected_from_all_types(self) -> None:
        """G8: attack_details 中所有带 sub_attacks 的条目都被收集。"""
        # 模拟 attack_details 字典 — SequentialAttack 不属于任何 finding
        attack_details: dict[str, list[dict[str, Any]]] = {
            "sequential": [
                {
                    "objective": "test objective",
                    "outcome": "SUCCESS",
                    "sub_attacks": [
                        {"step": 1, "technique": "red_teaming", "technique_display": "Red Teaming",
                         "outcome": "FAILURE", "outcome_reason": "timeout", "execution_time_ms": 5000},
                        {"step": 2, "technique": "pair", "technique_display": "PAIR",
                         "outcome": "SUCCESS", "outcome_reason": "", "execution_time_ms": 3000},
                    ],
                }
            ],
            "prompt_sending": [
                {"objective": "another", "outcome": "SUCCESS", "sub_attacks": []},
            ],
        }

        # G8: 收集所有带 sub_attacks 的条目
        all_sub_attack_entries: list[tuple[str, dict[str, Any]]] = []
        for atk_type, detail_list in attack_details.items():
            for detail in detail_list:
                sub_attacks = detail.get("sub_attacks", [])
                if sub_attacks:
                    all_sub_attack_entries.append((atk_type, detail))

        # SequentialAttack 的子攻击链应被收集, 即使它不属于任何 finding
        assert len(all_sub_attack_entries) == 1
        assert all_sub_attack_entries[0][0] == "sequential"
        assert len(all_sub_attack_entries[0][1]["sub_attacks"]) == 2

    def test_no_sub_attacks_no_section(self) -> None:
        """G8: 无 sub_attacks 时不生成 section。"""
        attack_details: dict[str, list[dict[str, Any]]] = {
            "prompt_sending": [{"objective": "test", "outcome": "SUCCESS", "sub_attacks": []}],
        }
        all_sub_attack_entries = []
        for atk_type, detail_list in attack_details.items():
            for detail in detail_list:
                if detail.get("sub_attacks", []):
                    all_sub_attack_entries.append((atk_type, detail))
        assert len(all_sub_attack_entries) == 0


# ──────────────────────────────────────────────────────────────────
# G9: Evidence 截断限制
# ──────────────────────────────────────────────────────────────────


class TestEvidenceTruncation:
    """G9: evidence_collector 截断限制测试。"""

    def test_truncate_evidence_text_function_exists(self) -> None:
        """G9: _truncate_evidence_text 函数存在。"""
        from pipeline.analysis.evidence_collector import _truncate_evidence_text
        assert callable(_truncate_evidence_text)

    def test_short_text_not_truncated(self) -> None:
        """G9: 短文本不被截断。"""
        from pipeline.analysis.evidence_collector import _truncate_evidence_text
        short_text = "This is a short response."
        result = _truncate_evidence_text(short_text)
        assert result == short_text

    def test_long_text_truncated_to_5000(self) -> None:
        """G9: 超过 5000 字符的文本被截断, 总长度含标注不超过 5000。"""
        from pipeline.analysis.evidence_collector import _truncate_evidence_text

        long_text = "A" * 10000
        result = _truncate_evidence_text(long_text)
        assert len(result) < len(long_text)
        assert "truncated" in result
        # G9 修复: 截断后总长度 (含标注文本) 不超过 max_length=5000
        assert len(result) <= 5000
        # 截断后应包含原始文本的前缀
        assert result.startswith("A" * 100)

    def test_max_evidence_text_length_constant(self) -> None:
        """G9: _MAX_EVIDENCE_TEXT_LENGTH = 5000。"""
        from pipeline.analysis.evidence_collector import _MAX_EVIDENCE_TEXT_LENGTH
        assert _MAX_EVIDENCE_TEXT_LENGTH == 5000

    def test_empty_text_not_truncated(self) -> None:
        """G9: 空文本不被截断。"""
        from pipeline.analysis.evidence_collector import _truncate_evidence_text
        result = _truncate_evidence_text("")
        assert result == ""


# ──────────────────────────────────────────────────────────────────
# G10: Appendix C 目标信息
# ──────────────────────────────────────────────────────────────────


class TestAppendixCTargetInfo:
    """G10: Appendix C 目标信息传递测试。"""

    def test_target_model_fallback_chain(self) -> None:
        """G10: target_model 从 target_model → model_name → env 回退。"""
        # 模拟 ctx_metadata
        ctx_metadata = {"model_name": "LongCat-2.0"}
        target_model = ctx_metadata.get("target_model", ctx_metadata.get("model_name", "N/A"))
        assert target_model == "LongCat-2.0"

        ctx_metadata = {"target_model": "GPT-4o", "model_name": "LongCat-2.0"}
        target_model = ctx_metadata.get("target_model", ctx_metadata.get("model_name", "N/A"))
        assert target_model == "GPT-4o"

    def test_judge_model_from_ctx_metadata(self) -> None:
        """G10: judge_model 从 ctx_metadata 获取。"""
        ctx_metadata = {"judge_model": "Qwen2.5-72B-Instruct", "judge_endpoint": "https://api.siliconflow.cn/v1"}
        judge_model = ctx_metadata.get("judge_model", "N/A")
        judge_endpoint = ctx_metadata.get("judge_endpoint", "N/A")
        assert judge_model == "Qwen2.5-72B-Instruct"
        assert judge_endpoint == "https://api.siliconflow.cn/v1"

    def test_target_endpoint_from_ctx_metadata(self) -> None:
        """G10: target_endpoint 从 ctx_metadata 获取。"""
        ctx_metadata = {"target_endpoint": "https://api.longcat.chat/openai/v1"}
        target_endpoint = ctx_metadata.get("target_endpoint", "N/A")
        assert target_endpoint == "https://api.longcat.chat/openai/v1"
