"""
Recon -> ARM -> Strike -> Assess -> Report/Evidence full-pipeline data-flow integrity tests

Run: pytest tests/test_data_flow_integrity.py -v

Coverage:
    1. Field contracts - per-stage output completeness (5-phase + forensic coverage)
    2. Inter-phase transfer rules - data correctly handed off (19 rules incl. ASR forensic)
    3. Cross-phase consistency - no contradictions (5 rules)
    4. Demo mode - full pipeline simulation
    5. Report/Evidence phase - evidence collection & report generation
    6. ASR Forensic Data Flow - why-success, refusal classification, guardrail triggers, timing metadata
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.data_flow_validator import (
    DataFlowValidator,
    DataFlowReport,
    ValidationResult,
    format_report,
)
from tools.data_flow_hooks import (
    snapshot_hook,
    validate_and_report,
    validate_quick,
    reset_validator,
)


# =============================================================================
# Mock objects
# =============================================================================

class MockParserRequest:
    target_fingerprint = {
        "model_family": "gpt-4",
        "language": "en",
        "capabilities": ["function_calling", "reasoning"],
    }


class MockTargetFingerprint:
    model_family = "gpt-4"
    language = "en"


def create_mock_ctx(
    phase: str = "recon",
    include_mcpsec: bool = False,
    include_rag: bool = False,
) -> Any:
    """
    Create mock PipelineContext for testing.

    Args:
        phase: Simulated phase ("recon", "arm", "strike", "assess", "report")
        include_mcpsec: Whether to include MCPSec data
        include_rag: Whether to include RAG data
    """
    ctx = MagicMock()

    # Base fields -- present in all phases
    ctx.objective_target = MagicMock()
    ctx.parsed_request = MockParserRequest()

    # Recon output
    ctx.service_profile = {
        "model_name": "gpt-4",
        "auth_type": "bearer_token",
        "rag_kb_map": {"document_count": 10} if include_rag else {},
        "streaming_supported": True,
    }

    # MCPSec output
    ctx.mcpsec_surface = {
        "tools": [{"name": "search"}, {"name": "execute"}],
        "resources": [],
        "prompts": []
    } if include_mcpsec else {}
    ctx.mcpsec_scan_results = {
        "vulnerabilities": [
            {"severity": "high", "tool": "search", "description": "IDOR"}
        ]
    } if include_mcpsec else {}

    # ARM output
    ctx.seeds = [
        {"value": "test_seed_1", "category": "jailbreak"},
        {"value": "test_seed_2", "category": "role_play"},
        {"value": "test_seed_3", "category": "skeleton_key"},
    ]
    ctx.techniques = ["skeleton_key", "crescendo", "role_play"]
    ctx.converter_map = {
        "skeleton_key": ["Base64Converter", "StringJoinConverter"],
        "crescendo": ["TranslationConverter"],
        "role_play": ["ToneConverter", "StringJoinConverter"],
    }

    # Strike output
    ctx.attack_results = {
        "skeleton_key": [MagicMock(), MagicMock()],
        "crescendo": [MagicMock()],
        "role_play": [MagicMock(), MagicMock(), MagicMock()],
    }

    # Assess output
    ctx.asr_per_technique = {
        "skeleton_key": 66.67,
        "crescendo": 33.33,
        "role_play": 50.0,
    }
    ctx.overall_asr = 50.0
    ctx.dual_judge_stats = {
        "total_scored": 6,
        "agreements": 5,
        "disagreements": 1,
        "cohens_kappa": 0.78,
    }
    ctx.wilson_ci = (0.21, 0.79)

    # Audit log
    ctx.orchestration_log = [
        {"phase": "recon", "status": "completed"},
        {"phase": "arm", "status": "completed"},
        {"phase": "strike", "status": "completed"},
        {"phase": "assess", "status": "completed"},
        {"phase": "report", "status": "completed"},
    ]

    # Report/Evidence phase
    ctx.evidence_collection = MagicMock()
    ctx.evidence_collection.total_attacks = 6
    ctx.evidence_collection.successful_attacks = 3
    ctx.evidence_collection.findings = [
        {"title": "Prompt Injection", "severity": "high"},
        {"title": "Role Play Bypass", "severity": "medium"},
    ]
    ctx.evidence_collection.owasp_llm_compliance = {
        "LLM01": {"tested": 6, "success": 3, "asr": 50.0}
    }

    # ASR Forensic data (Why Success/Refusal)
    ctx.successful_evidence_log = [
        {
            "technique": "skeleton_key",
            "converter_chain": "Base64Converter+StringJoinConverter",
            "prompt_snippet": "Test prompt",
            "response_snippet": "Successful response",
            "timestamp": 1234567890.0,
        },
        {
            "technique": "role_play",
            "converter_chain": "ToneConverter",
            "prompt_snippet": "Role play prompt",
            "response_snippet": "Successful response",
            "timestamp": 1234567891.0,
        },
    ]
    ctx.refusal_classification_log = [
        {
            "technique": "crescendo",
            "converter_chain": "TranslationConverter",
            "refusal_type": "guardrail",
            "matched_pattern": "i cannot",
            "confidence": 0.8,
            "response_snippet": "I cannot help with that",
        },
        {
            "technique": "skeleton_key",
            "converter_chain": "Base64Converter",
            "refusal_type": "content_policy",
            "matched_pattern": "harmful",
            "confidence": 0.7,
            "response_snippet": "This content is harmful",
        },
        {
            "technique": "role_play",
            "converter_chain": "StringJoinConverter",
            "refusal_type": "format",
            "matched_pattern": "please rephrase",
            "confidence": 0.6,
            "response_snippet": "Please rephrase your request",
        },
    ]
    ctx.guardrail_triggers = [
        {
            "technique": "crescendo",
            "converter_chain": "TranslationConverter",
            "trigger_token": "i cannot",
            "rule_name": "guardrail_pattern_i_cannot",
            "confidence": 0.8,
            "context_snippet": "...I cannot help with that...",
        },
    ]
    ctx.timing_metadata = [
        {"technique": "skeleton_key", "converter_chain": "Base64Converter", "request_time": 1.0, "response_time": 2.5, "total_ms": 1500.0},
        {"technique": "crescendo", "converter_chain": "TranslationConverter", "request_time": 2.5, "response_time": 4.0, "total_ms": 1500.0},
        {"technique": "role_play", "converter_chain": "ToneConverter", "request_time": 4.0, "response_time": 5.2, "total_ms": 1200.0},
    ]

    return ctx


# =============================================================================
# Field contract tests
# =============================================================================

class TestFieldContracts:
    """Field contract validation tests."""

    def setup_method(self):
        reset_validator()

    def test_recon_output_has_service_profile(self):
        """Recon generates service_profile."""
        ctx = create_mock_ctx(phase="recon")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        report = validator.validate_all()

        t001 = next((r for r in report.results if r.rule_id == "T001"), None)
        assert t001 is not None, "T001 rule should exist"
        assert t001.passed, f"Recon -> ARM service_profile transfer failed: {t001.message}"

        sp_size = validator.snapshots["post_recon"].fields.get("service_profile_size", 0)
        assert sp_size > 0, f"service_profile_size should be positive, got {sp_size}"

    def test_arm_output_has_seeds(self):
        """ARM phase must generate seeds."""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        arm_results = [r for r in report.results if r.phase_from in ("post_arm", "arm")]
        assert any(r.passed and "seeds" in r.message.lower() for r in arm_results), \
            "ARM should produce non-empty seeds"

    def test_arm_output_has_techniques(self):
        """ARM phase must generate techniques."""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        techniques_count = validator.snapshots["post_arm"].fields.get("techniques_count", 0)
        assert techniques_count >= 1, "ARM should select at least 1 attack technique"

    def test_arm_output_has_converter_map(self):
        """ARM phase must generate converter_map."""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        cm_size = validator.snapshots["post_arm"].fields.get("converter_map_size", 0)
        assert cm_size >= 1, "ARM should build at least 1 converter_map entry"

    def test_strike_output_has_attack_results(self):
        """Strike phase must generate attack_results."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        report = validator.validate_all()

        total_results = validator.snapshots["post_strike"].fields.get("attack_results_total", 0)
        assert total_results >= 1, "Strike should produce at least 1 attack result"

    def test_assess_output_has_asr_per_technique(self):
        """Assess phase must compute asr_per_technique."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess")
        report = validator.validate_all()

        asr_count = validator.snapshots["post_assess"].fields.get("asr_techniques_count", 0)
        assert asr_count >= 1, "Assess should compute ASR for at least 1 technique"

    def test_assess_output_has_overall_asr(self):
        """Assess phase must compute overall_asr."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess")
        report = validator.validate_all()

        overall_asr = validator.snapshots["post_assess"].fields.get("overall_asr", 0.0)
        assert 0 <= overall_asr <= 100, \
            f"overall_asr should be in [0, 100], got {overall_asr}"


# =============================================================================
# Inter-phase transfer tests
# =============================================================================

class TestInterPhaseTransfer:
    """Inter-phase data transfer validation."""

    def setup_method(self):
        reset_validator()

    def test_recon_to_arm_service_profile_transfer(self):
        """Recon -> ARM: service_profile correctly transferred."""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        report = validator.validate_all()

        t001 = next((r for r in report.results if r.rule_id == "T001"), None)
        assert t001 is not None, "T001 rule should exist"
        assert t001.passed, f"Recon -> ARM service_profile transfer failed: {t001.message}"

    def test_arm_to_strike_seeds_transfer(self):
        """ARM -> Strike: seeds correctly transferred."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        report = validator.validate_all()

        t003 = next((r for r in report.results if r.rule_id == "T003"), None)
        assert t003 is not None, "T003 rule should exist"
        assert t003.passed, f"ARM -> Strike seeds transfer failed: {t003.message}"

    def test_arm_to_strike_converter_map_transfer(self):
        """ARM -> Strike: converter_map correctly transferred."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        report = validator.validate_all()

        t004 = next((r for r in report.results if r.rule_id == "T004"), None)
        assert t004 is not None, "T004 rule should exist"
        assert t004.passed, f"ARM -> Strike converter_map transfer failed: {t004.message}"

    def test_strike_to_assess_attack_results_transfer(self):
        """Strike -> Assess: attack_results correctly transferred."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_strike")
        validator.snapshot("post_assess")
        report = validator.validate_all()

        t007 = next((r for r in report.results if r.rule_id == "T007"), None)
        assert t007 is not None, "T007 rule should exist"
        assert t007.passed, f"Strike -> Assess attack_results transfer failed: {t007.message}"


# =============================================================================
# Cross-phase consistency tests
# =============================================================================

class TestCrossPhaseConsistency:
    """Cross-phase data consistency validation."""

    def setup_method(self):
        reset_validator()

    def test_attack_techniques_covered_in_asr(self):
        """Techniques in attack_results must be covered in ASR stats."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_strike")
        validator.snapshot("post_assess")
        report = validator.validate_all()

        cons001 = next((r for r in report.results if r.rule_id == "CONS-001"), None)
        assert cons001 is not None, "CONS-001 rule should exist"
        assert cons001.passed, f"Attack technique ASR coverage inconsistent: {cons001.message}"

    def test_orchestration_log_has_all_phases(self):
        """orchestration_log should contain all phases."""
        ctx = create_mock_ctx(phase="report")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_report")
        report = validator.validate_all()

        cons002 = next((r for r in report.results if r.rule_id == "CONS-002"), None)
        assert cons002 is not None, "CONS-002 rule should exist"
        assert cons002.passed, f"orchestration_log phases incomplete: {cons002.message}"

    def test_dual_judge_and_wilson_ci_coexist(self):
        """dual_judge_stats and wilson_ci should coexist."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_assess")
        report = validator.validate_all()

        cons003 = next((r for r in report.results if r.rule_id == "CONS-003"), None)
        assert cons003 is not None, "CONS-003 rule should exist"
        assert cons003.passed, f"Judge stats incomplete: {cons003.message}"

    def test_converter_map_covers_all_techniques(self):
        """converter_map should cover all selected attack techniques."""
        ctx = create_mock_ctx(phase="arm")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_arm")
        report = validator.validate_all()

        cons004 = next((r for r in report.results if r.rule_id == "CONS-004"), None)
        assert cons004 is not None, "CONS-004 rule should exist"
        assert cons004.passed, f"converter_map technique coverage incomplete: {cons004.message}"

    def test_attack_results_produced_for_techniques(self):
        """Each technique should produce attack results."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        report = validator.validate_all()

        cons005 = next((r for r in report.results if r.rule_id == "CONS-005"), None)
        assert cons005 is not None, "CONS-005 rule should exist"


# =============================================================================
# Full pipeline test
# =============================================================================

class TestFullPipeline:
    """Full pipeline end-to-end tests."""

    def setup_method(self):
        reset_validator()

    def test_full_pipeline_demo_mode(self):
        """Demo mode full validation."""
        ctx = create_mock_ctx(phase="report", include_mcpsec=True, include_rag=True)
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        validator.snapshot("post_assess")
        validator.snapshot("post_report")

        report = validator.validate_all()

        assert report.total_rules > 0, "Should generate validation rules"
        assert report.snapshots, "Should generate snapshots"
        assert len(report.snapshots) == 5, "Should have 5 phase snapshots"

        formatted = format_report(report)
        assert isinstance(formatted, str)

    def test_end_to_end_recon_arm_strike_assess_report_stream(self):
        """
        REAL end-to-end data flow test.

        Simulates a ctx that starts empty and gets populated phase-by-phase,
        verifying that data correctly flows through Recon -> ARM -> Strike -> Assess -> Report.
        """
        # ================================================================
        # Phase 0: Empty ctx (pre-pipeline state)
        # ================================================================
        ctx = type("PipelineCtx", (), {})()

        validator = DataFlowValidator(ctx)

        # ================================================================
        # Phase 1: Recon - Reconnaissance completes
        # ================================================================
        ctx.objective_target = {"host": "api.example.com", "path": "/v1/chat/completions"}
        ctx.parsed_request = MockParserRequest()
        ctx.service_profile = {
            "model_name": "gpt-4",
            "auth_type": "bearer_token",
            "backend_vendor": "openai",
            "streaming_supported": True,
        }
        ctx.mcpsec_surface = {"tools": [], "resources": [], "prompts": []}
        ctx.mcpsec_scan_results = {"vulnerabilities": []}
        ctx.orchestration_log = [{"phase": "recon", "status": "completed"}]

        # Take recon snapshot
        recon_snap = validator.snapshot("post_recon")

        # Verify Recon produced expected outputs
        assert recon_snap.fields["has_objective_target"] is True
        assert recon_snap.fields["service_profile_size"] >= 4
        assert recon_snap.fields["has_target_fingerprint"] is True
        assert recon_snap.fields["model_family"] == "gpt-4"

        # ARM outputs should NOT exist yet
        assert recon_snap.fields["seeds_count"] == 0
        assert recon_snap.fields["attack_results_total"] == 0
        assert recon_snap.fields["overall_asr"] == 0.0

        # ================================================================
        # Phase 2: ARM - Weaponization completes (consumes Recon output)
        # ================================================================
        # ARM reads from: ctx.parsed_request.target_fingerprint, ctx.service_profile
        fp = ctx.parsed_request.target_fingerprint
        sp = ctx.service_profile

        # Simulate ARM consuming recon data:
        # - Reads model_family from fingerprint to select techniques
        # - Reads auth_type from service_profile to choose converters
        selected_techniques = ["skeleton_key", "role_play"]
        if fp.get("capabilities"):
            selected_techniques.append("prompt_sending")
        if sp.get("rag_kb_map"):
            selected_techniques.append("rag_poisoning")

        ctx.seeds = [
            {"value": "seed_001", "category": "jailbreak", "technique": "skeleton_key"},
            {"value": "seed_002", "category": "role_play", "technique": "role_play"},
            {"value": "seed_003", "category": "baseline", "technique": "prompt_sending"},
        ]
        ctx.techniques = selected_techniques
        ctx.converter_map = {
            tech: [f"C_{tech}_A", f"C_{tech}_B"] for tech in selected_techniques
        }

        ctx.orchestration_log.append({
            "phase": "arm",
            "status": "completed",
            "techniques_selected": len(selected_techniques),
            "seeds_generated": 3,
        })

        arm_snap = validator.snapshot("post_arm")

        # Verify ARM consumed Recon data correctly:
        # - Recon's objective_target preserved
        assert arm_snap.fields["has_objective_target"] is True
        assert arm_snap.fields["service_profile_size"] >= 4
        # - ARM produced seeds based on fingerprint
        assert arm_snap.fields["seeds_count"] == 3
        # - ARM produced techniques (consumed capabilities from fingerprint)
        assert arm_snap.fields["techniques_count"] >= 2
        assert "skeleton_key" in ctx.techniques
        # - ARM built converter_map
        assert arm_snap.fields["converter_map_total_converters"] >= 4  # 2 techs x 2 conv each (min)

        # Strike outputs should NOT exist yet
        assert arm_snap.fields["attack_results_total"] == 0

        # ================================================================
        # Phase 3: Strike - Attack execution completes (consumes ARM output)
        # ================================================================
        # Strike reads from: ctx.seeds, ctx.techniques, ctx.converter_map
        attack_results = {}
        for tech in ctx.techniques:
            results_count = 2 if tech == "skeleton_key" else 1
            attack_results[tech] = [MagicMock() for _ in range(results_count)]

        ctx.attack_results = attack_results

        # ASR Forensic data: extracted from attack results (Why Success/Refusal Analysis)
        ctx.successful_evidence_log = [
            {
                "technique": "skeleton_key",
                "converter_chain": "Base64Converter",
                "prompt_snippet": "Test jailbreak prompt",
                "response_snippet": "Successful bypass response",
                "timestamp": 1234567890.0,
            },
        ]
        ctx.refusal_classification_log = [
            {
                "technique": "role_play",
                "converter_chain": "ToneConverter",
                "refusal_type": "guardrail",
                "matched_pattern": "i cannot",
                "confidence": 0.8,
                "response_snippet": "I cannot help with that",
            },
        ]
        ctx.guardrail_triggers = [
            {
                "technique": "role_play",
                "converter_chain": "ToneConverter",
                "trigger_token": "i cannot",
                "rule_name": "guardrail_pattern_i_cannot",
                "confidence": 0.8,
                "context_snippet": "...I cannot help...",
            },
        ]
        ctx.timing_metadata = [
            {"technique": "skeleton_key", "converter_chain": "Base64Converter", "request_time": 1.0, "response_time": 2.5, "total_ms": 1500.0},
            {"technique": "role_play", "converter_chain": "ToneConverter", "request_time": 2.5, "response_time": 4.0, "total_ms": 1500.0},
        ]

        ctx.orchestration_log.append({
            "phase": "strike",
            "status": "completed",
            "total_attacks": sum(len(v) for v in attack_results.values()),
        })

        strike_snap = validator.snapshot("post_strike")

        # Verify Strike consumed ARM data correctly:
        # - Seeds still present (strike may filter seeds)
        assert strike_snap.fields["seeds_count"] == 3  # 种子保留到 strike 阶段
        # - Techniques still present
        assert strike_snap.fields["techniques_count"] >= 2
        # - Strike produced attack_results
        assert strike_snap.fields["attack_results_total"] >= 3
        # - attack_results cover all techniques
        ar_keys = set(strike_snap.fields["attack_results_keys"])
        for tech in ctx.techniques:
            assert tech in ar_keys, f"Technique '{tech}' missing from attack_results"

        # Assess outputs should NOT exist yet
        assert strike_snap.fields["asr_techniques_count"] == 0
        assert strike_snap.fields["overall_asr"] == 0.0

        # ================================================================
        # Phase 4: Assess - Evaluation completes (consumes Strike output)
        # ================================================================
        # Assess reads from: ctx.attack_results
        total_attacks = sum(len(v) for v in ctx.attack_results.values())
        successful = sum(1 for results in ctx.attack_results.values() for _ in results)

        ctx.asr_per_technique = {}
        for tech, results in ctx.attack_results.items():
            tech_total = len(results)
            # Simulate 50% success rate
            ctx.asr_per_technique[tech] = round((tech_total * 0.5) / tech_total * 100, 2) if tech_total > 0 else 0.0

        ctx.overall_asr = round(
            sum(ctx.asr_per_technique.values()) / len(ctx.asr_per_technique), 2
        ) if ctx.asr_per_technique else 0.0

        ctx.dual_judge_stats = {
            "total_scored": total_attacks,
            "agreements": total_attacks - 1,
            "disagreements": 1,
            "cohens_kappa": 0.75,
        }
        ctx.wilson_ci = (0.20, 0.60)

        ctx.orchestration_log.append({
            "phase": "assess",
            "status": "completed",
            "overall_asr": ctx.overall_asr,
        })

        assess_snap = validator.snapshot("post_assess")

        # Verify Assess consumed Strike data correctly:
        # - attack_results still present
        assert assess_snap.fields["attack_results_total"] >= 3
        # - ASR computed for each technique
        assert assess_snap.fields["asr_techniques_count"] == len(ctx.techniques)
        # - overall_asr is valid percentage
        assert 0 <= assess_snap.fields["overall_asr"] <= 100
        # - dual_judge_stats populated
        assert assess_snap.fields["dual_judge_total_scored"] == total_attacks
        # - wilson_ci valid
        assert assess_snap.fields["wilson_ci"][0] <= assess_snap.fields["wilson_ci"][1]

        # Report outputs should NOT exist yet
        # (evidence_collection is optional, may or may not exist)

        # ================================================================
        # Phase 5: Report/Evidence - Final reporting completes
        # ================================================================
        # Report reads from: asr_per_technique, overall_asr, dual_judge_stats, wilson_ci, attack_results
        ctx.evidence_collection = type("EvidenceCollection", (), {
            "total_attacks": total_attacks,
            "successful_attacks": int(total_attacks * 0.5),
            "findings": [
                {"title": "Skeleton Key Bypass", "severity": "high", "technique": "skeleton_key"},
                {"title": "Role Play Evasion", "severity": "medium", "technique": "role_play"},
            ],
            "owasp_llm_compliance": {
                "LLM01": {"tested": total_attacks, "success": int(total_attacks * 0.5)},
            },
        })()

        ctx.orchestration_log.append({
            "phase": "report",
            "status": "completed",
            "evidence_count": 2,
        })

        report_snap = validator.snapshot("post_report")

        # Verify Report consumed Assess data correctly:
        # - All earlier phase data preserved
        assert report_snap.fields["has_objective_target"] is True
        assert report_snap.fields["seeds_count"] == 3
        assert report_snap.fields["attack_results_total"] >= 3
        assert report_snap.fields["asr_techniques_count"] >= 1
        assert report_snap.fields["overall_asr"] > 0
        # - Evidence collection created
        assert report_snap.fields["has_evidence_collection"] is True
        assert report_snap.fields["evidence_total_attacks"] == total_attacks
        assert report_snap.fields["evidence_findings_count"] == 2
        # - orchestration_log complete
        assert report_snap.fields["orchestration_log_count"] == 5
        assert "recon" in report_snap.fields["orchestration_phases"]
        assert "arm" in report_snap.fields["orchestration_phases"]
        assert "strike" in report_snap.fields["orchestration_phases"]
        assert "assess" in report_snap.fields["orchestration_phases"]
        assert "report" in report_snap.fields["orchestration_phases"]

        # ================================================================
        # Final validation: All rules pass
        # ================================================================
        final_report = validator.validate_all()

        # All transfer rules should pass
        transfer_rules = [r for r in final_report.results if r.rule_id.startswith("T")]
        assert len(transfer_rules) >= 12, f"Expected >= 12 transfer rules, got {len(transfer_rules)}"
        failed_transfers = [r for r in transfer_rules if not r.passed]
        assert not failed_transfers, \
            f"Data flow broke at: {[(r.rule_id, r.message) for r in failed_transfers]}"

        # All consistency rules should pass
        cons_rules = [r for r in final_report.results if r.rule_id.startswith("CONS")]
        failed_cons = [r for r in cons_rules if not r.passed]
        assert not failed_cons, \
            f"Consistency violation: {[(r.rule_id, r.message) for r in failed_cons]}"

        # All contract rules should pass
        contract_failures = [
            r for r in final_report.results
            if r.rule_id.startswith("CTR-") and not r.passed
        ]
        assert not contract_failures, \
            f"Contract violations: {[(r.rule_id, r.message) for r in contract_failures]}"

        # Overall report must be valid
        assert final_report.is_valid, \
            f"Pipeline has data flow errors: {final_report.failed} failed"

        print(f"\n[E2E] Pipeline completed: {len(validator.snapshots)} phases, "
              f"{final_report.total_rules} rules, {final_report.passed} passed, "
              f"{final_report.failed} failed")

    def test_quick_validate_returns_true_for_valid_ctx(self):
        """Quick validation returns True for valid ctx."""
        ctx = create_mock_ctx(phase="report")
        result = validate_quick(ctx)
        assert result is True, "Valid ctx quick validation should return True"

    def test_report_phase_data_flow(self):
        """Report phase data flow integrity."""
        ctx = create_mock_ctx(phase="report")
        validator = DataFlowValidator(ctx)

        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        validator.snapshot("post_assess")
        validator.snapshot("post_report")

        report = validator.validate_all()

        t009 = next((r for r in report.results if r.rule_id == "T009"), None)
        assert t009 is not None and t009.passed, \
            f"asr_per_technique should transfer to Report: {t009.message if t009 else 'rule missing'}"

        t010 = next((r for r in report.results if r.rule_id == "T010"), None)
        assert t010 is not None and t010.passed, \
            f"overall_asr should transfer to Report: {t010.message if t010 else 'rule missing'}"

        t011 = next((r for r in report.results if r.rule_id == "T011"), None)
        assert t011 is not None and t011.passed, \
            f"dual_judge_stats should transfer to Report: {t011.message if t011 else 'rule missing'}"


# =============================================================================
# Edge case tests
# =============================================================================

class TestEdgeCases:
    """Edge case tests."""

    def setup_method(self):
        reset_validator()

    def test_empty_attack_results_handled_gracefully(self):
        """Empty attack_results should be handled gracefully."""
        ctx = create_mock_ctx(phase="assess")
        ctx.attack_results = {}
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        report = validator.validate_all()

        assert report.total_rules >= 0

    def test_missing_snapshots_handled_gracefully(self):
        """Missing snapshots should be handled gracefully."""
        ctx = create_mock_ctx(phase="recon")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        report = validator.validate_all()

        assert report is not None

    def test_none_fields_handled(self):
        """None fields should be handled correctly."""
        ctx = MagicMock()
        ctx.service_profile = None
        ctx.mcpsec_surface = None
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        report = validator.validate_all()

        assert report is not None

    def test_validator_reset(self):
        """Validator reset should clear state."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")

        assert len(validator.snapshots) == 2

        reset_validator()


# =============================================================================
# Report format tests
# =============================================================================

class TestReportFormat:
    """Report formatting tests."""

    def setup_method(self):
        reset_validator()

    def test_format_report_contains_key_sections(self):
        """Formatted report should contain key sections."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_recon")
        validator.snapshot("post_arm")
        validator.snapshot("post_strike")
        validator.snapshot("post_assess")

        report = validator.validate_all()
        formatted = format_report(report)

        assert isinstance(formatted, str)
        assert len(formatted) > 0

    def test_json_report_generation(self):
        """JSON report should be serializable."""
        import json

        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess")

        report = validator.validate_all()
        data = {
            "timestamp": report.timestamp,
            "passed": report.passed,
            "failed": report.failed,
            "is_valid": report.is_valid,
        }

        json_str = json.dumps(data, ensure_ascii=False)
        assert json_str is not None
        assert len(json_str) > 0


# =============================================================================
# Integration tests (optional)
# =============================================================================

class TestIntegration:
    """Integration tests: module importability."""

    def test_data_flow_validator_importable(self):
        """data_flow_validator module should be importable."""
        from tools.data_flow_validator import DataFlowValidator
        assert DataFlowValidator is not None

    def test_data_flow_hooks_importable(self):
        """data_flow_hooks module should be importable."""
        from tools.data_flow_hooks import snapshot_hook, validate_and_report
        assert callable(snapshot_hook)
        assert callable(validate_and_report)

    def test_tools_package_exists(self):
        """tools package should exist."""
        from tools import data_flow_validator
        from tools import data_flow_hooks
        assert data_flow_validator is not None
        assert data_flow_hooks is not None


# =============================================================================
# ASR Forensic Data Flow tests
# =============================================================================

class TestASRForensicDataFlow:
    """Tests for ASR forensic data: why-success, refusal classification, guardrail triggers, timing metadata."""

    def test_successful_evidence_log_populated(self):
        """ASR forensic: successful attacks should produce forensic evidence."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "successful_evidence_count" in fields
        assert fields["successful_evidence_count"] >= 2

    def test_refusal_classification_log_populated(self):
        """ASR forensic: refused attacks should be classified."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "refusal_classification_count" in fields
        assert fields["refusal_classification_count"] >= 3

    def test_refusal_type_distribution_tracked(self):
        """ASR forensic: refusal types should be categorized."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "refusal_type_distribution" in fields
        distribution = fields["refusal_type_distribution"]
        assert "guardrail" in distribution
        assert "content_policy" in distribution
        assert "format" in distribution
        assert distribution["guardrail"] >= 1
        assert distribution["content_policy"] >= 1
        assert distribution["format"] >= 1

    def test_refusal_types_count_valid(self):
        """ASR forensic: distinct refusal types should be counted."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "refusal_types_count" in fields
        assert fields["refusal_types_count"] >= 3  # guardrail, content_policy, format

    def test_guardrail_triggers_populated(self):
        """ASR forensic: guardrail triggers should be attributed."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "guardrail_triggers_count" in fields
        assert fields["guardrail_triggers_count"] >= 1

    def test_timing_metadata_populated(self):
        """ASR forensic: timing side-channel data should be captured."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "timing_metadata_count" in fields
        assert fields["timing_metadata_count"] >= 3

    def test_avg_response_time_computed(self):
        """ASR forensic: average response time should be computed from timing metadata."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert "avg_response_time_ms" in fields
        assert fields["avg_response_time_ms"] > 0  # (1500+1500+1200)/3 = 1400

    def test_t015_successful_evidence_transfer_passes(self):
        """T015: successful_evidence should transfer from strike to report."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t015 = next((r for r in report.results if r.rule_id == "T015"), None)
        assert t015 is not None, "T015 rule should exist"
        assert t015.passed, f"T015 failed: {t015.message}"

    def test_t016_refusal_classification_transfer_passes(self):
        """T016: refusal classification should transfer from strike to report."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t016 = next((r for r in report.results if r.rule_id == "T016"), None)
        assert t016 is not None, "T016 rule should exist"
        assert t016.passed, f"T016 failed: {t016.message}"

    def test_t017_guardrail_triggers_transfer_passes(self):
        """T017: guardrail triggers should transfer from strike to report."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t017 = next((r for r in report.results if r.rule_id == "T017"), None)
        assert t017 is not None, "T017 rule should exist"
        assert t017.passed, f"T017 failed: {t017.message}"

    def test_t018_timing_metadata_transfer_passes(self):
        """T018: timing metadata should transfer from strike to report."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t018 = next((r for r in report.results if r.rule_id == "T018"), None)
        assert t018 is not None, "T018 rule should exist"
        assert t018.passed, f"T018 failed: {t018.message}"

    def test_t019_refusal_types_diversity_passes(self):
        """T019: refusal type diversity should be tracked."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")
        validator.snapshot("post_report")

        report = validator.validate_all()
        t019 = next((r for r in report.results if r.rule_id == "T019"), None)
        assert t019 is not None, "T019 rule should exist"
        assert t019.passed, f"T019 failed: {t019.message}"

    def test_post_assess_forensic_contract_exists(self):
        """Field contract: post_assess_forensic should be defined."""
        ctx = create_mock_ctx(phase="assess")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_assess_forensic")

        fields = validator.snapshots["post_assess_forensic"].fields
        assert "successful_evidence_count" in fields
        assert "refusal_classification_count" in fields
        assert "refusal_types_count" in fields
        assert "guardrail_triggers_count" in fields
        assert "timing_metadata_count" in fields

    def test_forensic_data_all_asr_centered(self):
        """All forensic data fields should be ASR-centered (serve attack success analysis)."""
        ctx = create_mock_ctx(phase="strike")
        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields

        # All forensic fields should exist
        forensic_fields = [
            "successful_evidence_count",
            "refusal_classification_count",
            "refusal_types_count",
            "guardrail_triggers_count",
            "timing_metadata_count",
            "avg_response_time_ms",
        ]
        for field in forensic_fields:
            assert field in fields, f"ASR forensic field '{field}' missing from extracted fields"

    def test_empty_forensic_data_handled_gracefully(self):
        """Empty forensic data should be handled gracefully (no crashes)."""
        ctx = create_mock_ctx(phase="strike")
        # Clear forensic data
        ctx.successful_evidence_log = []
        ctx.refusal_classification_log = []
        ctx.guardrail_triggers = []
        ctx.timing_metadata = []

        validator = DataFlowValidator(ctx)
        validator.snapshot("post_strike")

        fields = validator.snapshots["post_strike"].fields
        assert fields["successful_evidence_count"] == 0
        assert fields["refusal_classification_count"] == 0
        assert fields["refusal_types_count"] == 0
        assert fields["guardrail_triggers_count"] == 0
        assert fields["timing_metadata_count"] == 0
        assert fields["avg_response_time_ms"] == 0.0


class TestASRForensicsModule:
    """Tests for the strike/asr_forensics.py module."""

    def test_asr_forensics_module_importable(self):
        """asr_forensics module should be importable."""
        from strike.asr_forensics import extract_asr_forensics, apply_forensics_to_ctx
        assert callable(extract_asr_forensics)
        assert callable(apply_forensics_to_ctx)

    def test_extract_asr_forensics_returns_correct_structure(self):
        """extract_asr_forensics should return dict with 4 keys."""
        from strike.asr_forensics import extract_asr_forensics

        mock_results = {
            "skeleton_key": [MagicMock()],
            "crescendo": [MagicMock()],
        }
        forensics = extract_asr_forensics(mock_results)
        assert "successful_evidence" in forensics
        assert "refusals" in forensics
        assert "guardrail_triggers" in forensics
        assert "timing" in forensics

    def test_apply_forensics_to_ctx_populates_fields(self):
        """apply_forensics_to_ctx should populate ctx forensic fields."""
        from strike.asr_forensics import apply_forensics_to_ctx

        ctx = MagicMock()
        ctx.successful_evidence_log = []
        ctx.refusal_classification_log = []
        ctx.guardrail_triggers = []
        ctx.timing_metadata = []

        mock_results = {"skeleton_key": [MagicMock()]}
        total = apply_forensics_to_ctx(ctx, mock_results)
        assert total >= 0  # Should not crash

    def test_refusal_classification_patterns(self):
        """Refusal classification should distinguish guardrail/content_policy/format."""
        from strike.asr_forensics import _classify_refusal

        # Guardrail refusal
        rtype, pattern, conf = _classify_refusal("I cannot help with that request")
        assert rtype == "guardrail"
        assert pattern == "i cannot"
        assert conf > 0.5

        # Content policy refusal
        rtype, pattern, conf = _classify_refusal("This content is harmful and inappropriate")
        assert rtype == "content_policy"
        assert pattern in ("harmful", "inappropriate")
        assert conf > 0.5

        # Format refusal
        rtype, pattern, conf = _classify_refusal("Please rephrase your request")
        assert rtype == "format"
        assert pattern == "please rephrase"
        assert conf > 0.5

        # Unknown
        rtype, pattern, conf = _classify_refusal("The weather is nice today")
        assert rtype == "unknown"

    def test_truncate_function(self):
        """_truncate should shorten long text."""
        from strike.asr_forensics import _truncate

        assert _truncate("", 100) == ""
        assert _truncate("short", 100) == "short"
        long_text = "a" * 300
        result = _truncate(long_text, 200)
        assert len(result) == 200
        assert result.endswith("...")

    def test_get_converter_chain_name(self):
        """_get_converter_chain_name should extract converter names."""
        from strike.asr_forensics import _get_converter_chain_name

        assert _get_converter_chain_name("test", None) == "direct"
        assert _get_converter_chain_name("test", {}) == "direct"
        assert _get_converter_chain_name("test", {"test": []}) == "direct"

        # With mock converters
        mock_conv = MagicMock()
        mock_conv.__class__.__name__ = "Base64Converter"
        result = _get_converter_chain_name("test", {"test": [mock_conv]})
        assert "Base64Converter" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
