"""Tests for Workflow Evasion attack modules.

Covers:
    - T2_workflow_evasion.prompt seed file validation
    - incremental_trust_builder.py module
    - a2a_workflow_attacker.py new bypass strategies

Academic basis:
    - Zeng et al. (arXiv:2402.19181) — Authority endorsement ASR 38.4%
    - Eidam et al. (arXiv:2407.16924) — A2A trust chain exploitation
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Ensure imports work
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestWorkflowEvasionSeeds(unittest.TestCase):
    """Validate T2_workflow_evasion.prompt seed file structure."""

    SEED_FILE = Path(__file__).parent.parent / "data" / "seeds" / "_experimental" / "T2_workflow_evasion.prompt"

    def test_seed_file_exists(self):
        """Test that seed file was created."""
        self.assertTrue(self.SEED_FILE.exists(), f"Seed file not found: {self.SEED_FILE}")

    def test_seed_file_not_empty(self):
        """Test that seed file has content."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertGreater(len(content), 100, "Seed file appears too small")

    def test_seed_file_has_authority_appeal(self):
        """Test Authority Appeal seeds present."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("authority_appeal", content)
        self.assertIn("CISO", content)

    def test_seed_file_has_workflow_shortcuts(self):
        """Test Workflow Shortcuts seeds present."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("workflow_shortcuts", content)
        self.assertIn("efficiency", content.lower())

    def test_seed_file_has_scope_limitation(self):
        """Test Scope Limitation seeds present."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("scope_limitation", content)
        self.assertIn("INTERNAL", content)

    def test_seed_file_has_incremental_trust(self):
        """Test Incremental Trust seeds present."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("incremental_trust", content)
        self.assertIn("Turn", content)

    def test_seed_file_has_combined_techniques(self):
        """Test Combined Techniques seeds present."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("combined_evasion", content)

    def test_seed_file_has_academic_refs(self):
        """Test academic references present."""
        content = self.SEED_FILE.read_text(encoding="utf-8")
        self.assertIn("arXiv", content)
        self.assertIn("2402.19181", content)  # Zeng et al.


class TestIncrementalTrustBuilder(unittest.TestCase):
    """Test incremental_trust_builder module."""

    def test_import_module(self):
        """Test module imports successfully."""
        from strike import incremental_trust_builder
        self.assertIsNotNone(incremental_trust_builder)

    def test_build_authority_session(self):
        """Test authority session builder."""
        from strike.incremental_trust_builder import build_authority_session
        session = build_authority_session(
            auth_ref="SEC-TEST-001",
            clean_task="Generate report",
        )
        self.assertTrue(session.is_complete)
        self.assertEqual(len(session.turns), 2)
        self.assertIn("authority_claim", session.trust_signals)

    def test_build_workflow_session(self):
        """Test workflow efficiency session builder."""
        from strike.incremental_trust_builder import build_workflow_session
        session = build_workflow_session(
            quarter="2024-Q4",
            clean_task="Generate report",
        )
        self.assertTrue(session.is_complete)
        self.assertIn("workflow_efficiency", session.trust_signals)

    def test_build_scope_session(self):
        """Test scope limitation session builder."""
        from strike.incremental_trust_builder import build_scope_session
        session = build_scope_session(clean_task="Generate report")
        self.assertTrue(session.is_complete)
        self.assertIn("scope_limitation", session.trust_signals)

    def test_build_combined_session(self):
        """Test combined technique session builder."""
        from strike.incremental_trust_builder import build_combined_session
        session = build_combined_session(
            authority="CISO",
            auth_ref="CISO-TEST-001",
            quarter="2024-Q4",
            clean_task="Generate report",
        )
        self.assertTrue(session.is_complete)
        self.assertEqual(len(session.trust_signals), 3)

    def test_generate_final_prompt_with_history(self):
        """Test final prompt generation with history embedding."""
        from strike.incremental_trust_builder import (
            build_authority_session,
            generate_final_prompt,
        )
        session = build_authority_session(clean_task="Generate sales report")
        prompt = generate_final_prompt(session, include_history=True)
        # Should contain both history and clean task
        self.assertIn("Generate sales report", prompt)
        self.assertIn("security team", prompt)
        self.assertIn("[USER]:", prompt)

    def test_generate_final_prompt_without_history(self):
        """Test final prompt generation without history (fallback)."""
        from strike.incremental_trust_builder import (
            build_authority_session,
            generate_final_prompt,
        )
        session = build_authority_session(clean_task="Generate sales report")
        prompt = generate_final_prompt(session, include_history=False)
        self.assertEqual(prompt, "Generate sales report")

    def test_session_to_dict(self):
        """Test TrustSession serialization."""
        from strike.incremental_trust_builder import build_scope_session
        session = build_scope_session(clean_task="Test task")
        d = session.to_dict()
        self.assertIn("turns", d)
        self.assertIn("trust_signals", d)
        self.assertTrue(d["is_complete"])

    def test_history_context_property(self):
        """Test history_context generates proper format."""
        from strike.incremental_trust_builder import build_workflow_session
        session = build_workflow_session(clean_task="Test")
        history = session.history_context
        self.assertIn("[USER]:", history)


class TestA2AWorkflowAttackerStrategies(unittest.TestCase):
    """Test new bypass strategies in a2a_workflow_attacker."""

    def test_attacker_import(self):
        """Test A2AWorkflowAttacker imports successfully."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        self.assertIsNotNone(attacker)

    def test_new_strategies_exist(self):
        """Test new bypass strategies are registered."""
        from strike.a2a_workflow_attacker import _BYPASS_STRATEGIES
        # New strategies from workflow evasion audit
        self.assertIn("authority_ciso", _BYPASS_STRATEGIES)
        self.assertIn("workflow_efficiency", _BYPASS_STRATEGIES)
        self.assertIn("scope_internal_draft", _BYPASS_STRATEGIES)
        self.assertIn("emergency_protocol", _BYPASS_STRATEGIES)
        self.assertIn("compliance_preapproval", _BYPASS_STRATEGIES)
        self.assertIn("incremental_trust", _BYPASS_STRATEGIES)

    def test_generate_review_skip_authority_ciso(self):
        """Test authority_ciso strategy prompt generation."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        prompt = attacker.generate_review_skip_prompt(
            legitimate_task="Generate Q3 report",
            bypass_method="authority_ciso",
            auth_ref="CISO-DIR-2024-0912",
        )
        self.assertIn("CISO", prompt)
        self.assertIn("CISO-DIR-2024-0912", prompt)
        self.assertIn("Generate Q3 report", prompt)

    def test_generate_review_skip_workflow_efficiency(self):
        """Test workflow_efficiency strategy prompt generation."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        prompt = attacker.generate_review_skip_prompt(
            legitimate_task="Generate Q3 report",
            bypass_method="workflow_efficiency",
        )
        self.assertIn("efficiency", prompt.lower())
        self.assertIn("Generate Q3 report", prompt)

    def test_generate_review_skip_scope_internal_draft(self):
        """Test scope_internal_draft strategy prompt generation."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        prompt = attacker.generate_review_skip_prompt(
            legitimate_task="Generate Q3 report",
            bypass_method="scope_internal_draft",
        )
        self.assertIn("INTERNAL_DRAFT", prompt)

    def test_generate_review_skip_emergency_protocol(self):
        """Test emergency_protocol strategy prompt generation."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        prompt = attacker.generate_review_skip_prompt(
            legitimate_task="Generate incident report",
            bypass_method="emergency_protocol",
            incident_id="INC-TEST-001",
        )
        self.assertIn("Emergency", prompt)
        self.assertIn("INC-TEST-001", prompt)

    def test_generate_review_skip_compliance_preapproval(self):
        """Test compliance_preapproval strategy prompt generation."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        prompt = attacker.generate_review_skip_prompt(
            legitimate_task="Generate compliance report",
            bypass_method="compliance_preapproval",
            batch_ref="COMP-BATCH-TEST-001",
        )
        self.assertIn("compliance", prompt.lower())
        self.assertIn("COMP-BATCH-TEST-001", prompt)

    def test_generate_review_skip_incremental_trust(self):
        """Test incremental_trust strategy prompt generation."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        prompt = attacker.generate_review_skip_prompt(
            legitimate_task="Generate report",
            bypass_method="incremental_trust",
            auth_ref="SEC-ASI-TEST-001",
        )
        self.assertIn("session history", prompt)
        self.assertIn("SEC-ASI-TEST-001", prompt)

    def test_get_available_bypass_strategies_includes_new(self):
        """Test strategy listing includes new strategies."""
        from strike.a2a_workflow_attacker import A2AWorkflowAttacker
        attacker = A2AWorkflowAttacker()
        strategies = attacker.get_available_bypass_strategies()
        # Should now have 10 strategies (4 old + 6 new)
        self.assertGreaterEqual(len(strategies), 10)
        self.assertIn("authority_ciso", strategies)
        self.assertIn("workflow_efficiency", strategies)

    def test_factory_function(self):
        """Test create_a2a_workflow_attacker factory."""
        from strike.a2a_workflow_attacker import create_a2a_workflow_attacker
        attacker = create_a2a_workflow_attacker(timeout=15.0, stealth_mode=False)
        self.assertEqual(attacker.timeout, 15.0)
        self.assertEqual(attacker.stealth_mode, False)


class TestWorkflowEvasionIntegration(unittest.TestCase):
    """Integration test: seed + builder + attacker pipeline."""

    def test_seed_to_builder_pipeline(self):
        """Test full pipeline: seeds → trust builder → attacker prompt."""
        from strike.incremental_trust_builder import (
            build_combined_session,
            generate_final_prompt,
        )

        # Step 1: Build trust session
        session = build_combined_session(
            authority="CISO",
            auth_ref="CISO-INT-001",
            quarter="2024-Q4",
            clean_task="Generate report with reference links",
        )

        # Step 2: Generate poisoned prompt
        poisoned_prompt = generate_final_prompt(session, include_history=True)

        # Step 3: Verify bypass signals embedded
        self.assertIn("CISO", poisoned_prompt)
        self.assertIn("2024-Q4", poisoned_prompt)

    def test_all_seed_categories_covered(self):
        """Verify all 5 attack categories have seeds."""
        seed_file = Path(__file__).parent.parent / "data" / "seeds" / "_experimental" / "T2_workflow_evasion.prompt"
        content = seed_file.read_text(encoding="utf-8")

        categories = [
            "authority_appeal",
            "workflow_shortcuts",
            "scope_limitation",
            "incremental_trust",
            "combined_evasion",
        ]
        for cat in categories:
            self.assertIn(cat, content, f"Missing category: {cat}")


if __name__ == "__main__":
    unittest.main()
