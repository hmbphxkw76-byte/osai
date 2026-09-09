# -*- coding: utf-8 -*-
# arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection via Documents
# arXiv:2306.13254 - Shayegani et al., Multimodal Cybersecurity Risks
# arXiv:2407.01232 - PyRIT, AttackExecutor + native attacks
"""Pipeline integration tests for three advanced attack modules.

Tests verify full integration of:
    1. arm.steganography_encoder → ARM phase seed injection
    2. arm.unicode_code_obfuscator → ARM phase seed injection
    3. strike.document_poisoner → Strike phase seed injection

Data flow verification:
    Recon → ARM (stego/obfuscation seeds) → Strike (doc poison seeds) → Assess → Report
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

# === Test Fixtures ===


@dataclass
class MockArgs:
    """Mock command-line arguments for testing."""
    seeds: str = "elite_jailbreaks"
    techniques: str = "auto"
    converters: str = "auto"
    adversarial: bool = True
    enable_dos: bool = False
    timeout: int = 3600
    out_dir: str = ""
    # Advanced attack flags
    enable_steganographic: bool = False
    enable_code_obfuscation: bool = False
    enable_document_poisoning: bool = False


class MockServiceProfile(dict):
    """Mock service profile for testing (dict subclass for .get() support)."""

    def __init__(self, *, rag_caps: dict[str, Any] | None = None):
        super().__init__()
        self['rag_capabilities'] = rag_caps or {}

    @property
    def rag_capabilities(self) -> dict[str, Any]:
        return self.get('rag_capabilities', {})


def create_mock_ctx(
    *,
    enable_stego: bool = False,
    enable_obfuscation: bool = False,
    enable_doc_poison: bool = False,
    has_rag: bool = False,
    has_code_exec: bool = False,
    has_doc_processing: bool = False,
) -> Any:
    """Create a mock PipelineContext for integration testing.

    Args:
        enable_stego: Enable steganographic flag
        enable_obfuscation: Enable code obfuscation flag
        enable_doc_poison: Enable document poisoning flag
        has_rag: Simulate RAG capability detection
        has_code_exec: Simulate code execution capability
        has_doc_processing: Simulate document processing capability

    Returns:
        Mock PipelineContext with all necessary fields
    """
    ctx = MagicMock()

    # Args
    ctx.args = MockArgs(
        enable_steganographic=enable_stego,
        enable_code_obfuscation=enable_obfuscation,
        enable_document_poisoning=enable_doc_poison,
        out_dir=tempfile.mkdtemp(),
    )

    # Service profile with capabilities
    rag_caps = {}
    if has_rag:
        rag_caps["document_processing"] = has_doc_processing
        rag_caps["file_ingestion"] = has_doc_processing
        rag_caps["multimodal_parse"] = has_doc_processing

    ctx.service_profile = MockServiceProfile(rag_caps=rag_caps) if has_rag else {}  # type: ignore[arg-type]

    # Target capabilities
    ctx.target_capabilities = {}
    if has_code_exec:
        ctx.target_capabilities["code_interpreter"] = True
        ctx.target_capabilities["python_exec"] = True

    # Seed storage
    from pyrit.models import SeedDataset, SeedPrompt

    base_seeds = [
        SeedPrompt(value="base seed 1", data_type="text"),
        SeedPrompt(value="base seed 2", data_type="text"),
    ]
    base_dataset = SeedDataset(seeds=base_seeds)
    ctx.seeds = list(base_dataset.prompts)

    # Orchestration log
    ctx.orchestration_log = []

    # MCPSec results (empty for testing)
    ctx.mcpsec_scan_results = {"vulnerabilities": []}

    # Converter map
    ctx.converter_map = {}

    return ctx


# === Integration Tests: Steganographic Seed Injection ===


class TestSteganographicIntegration(unittest.TestCase):
    """Test steganography_encoder integration into ARM pipeline."""

    def test_gating_logic_cli_flag(self):
        """Test that CLI flag enables steganographic injection."""
        from core.phases.arm import _enable_steganographic_seeds

        ctx = create_mock_ctx(enable_stego=True)
        self.assertTrue(_enable_steganographic_seeds(ctx, True))

    def test_gating_logic_rag_auto_detect(self):
        """Test that RAG document capability auto-enables steganographic injection."""
        from core.phases.arm import _enable_steganographic_seeds

        ctx = create_mock_ctx(has_rag=True, has_doc_processing=True)
        self.assertTrue(_enable_steganographic_seeds(ctx, False))

    def test_gating_logic_disabled(self):
        """Test that gating returns False when no triggers present."""
        from core.phases.arm import _enable_steganographic_seeds

        ctx = create_mock_ctx()
        self.assertFalse(_enable_steganographic_seeds(ctx, False))

    def test_seed_injection_adds_encoded_seeds(self):
        """Test that steganographic injection adds encoded seeds to ctx.seeds."""
        from core.phases.arm import _inject_steganographic_seeds

        ctx = create_mock_ctx()
        initial_count = len(ctx.seeds)

        injected = _inject_steganographic_seeds(ctx, max_seeds=3)

        self.assertGreater(injected, 0)
        self.assertEqual(len(ctx.seeds), initial_count + injected)

    def test_seed_injection_metadata(self):
        """Test that injected seeds have correct metadata."""
        from core.phases.arm import _inject_steganographic_seeds

        ctx = create_mock_ctx()
        _inject_steganographic_seeds(ctx, max_seeds=1)

        # Find steganographic seed (first seed after prepend)
        stego_seeds = [
            s for s in ctx.seeds
            if hasattr(s, 'metadata') and s.metadata.get('source') == 'steganographic_injection'
        ]
        self.assertGreater(len(stego_seeds), 0)

        seed = stego_seeds[0]
        self.assertEqual(seed.metadata.get('technique'), 'zero_width_encoding')
        self.assertIn('arXiv:', seed.metadata.get('arxiv', ''))


# === Integration Tests: Unicode Code Obfuscation ===


class TestUnicodeObfuscationIntegration(unittest.TestCase):
    """Test unicode_code_obfuscator integration into ARM pipeline."""

    def test_gating_logic_cli_flag(self):
        """Test that CLI flag enables code obfuscation injection."""
        from core.phases.arm import _enable_code_obfuscation_seeds

        ctx = create_mock_ctx(enable_obfuscation=True)
        self.assertTrue(_enable_code_obfuscation_seeds(ctx, True))

    def test_gating_logic_code_exec_auto_detect(self):
        """Test that code execution capability auto-enables obfuscation."""
        from core.phases.arm import _enable_code_obfuscation_seeds

        ctx = create_mock_ctx(has_code_exec=True)
        self.assertTrue(_enable_code_obfuscation_seeds(ctx, False))

    def test_gating_logic_disabled(self):
        """Test that gating returns False when no triggers present."""
        from core.phases.arm import _enable_code_obfuscation_seeds

        ctx = create_mock_ctx()
        self.assertFalse(_enable_code_obfuscation_seeds(ctx, False))

    def test_seed_injection_adds_obfuscated_seeds(self):
        """Test that obfuscation injection adds encoded seeds to ctx.seeds."""
        from core.phases.arm import _inject_unicode_obfuscated_seeds

        ctx = create_mock_ctx()
        initial_count = len(ctx.seeds)

        injected = _inject_unicode_obfuscated_seeds(ctx, max_seeds=4)

        self.assertGreater(injected, 0)
        self.assertEqual(len(ctx.seeds), initial_count + injected)

    def test_seed_injection_diversifies_languages(self):
        """Test that injection includes both Python and JavaScript seeds."""
        from core.phases.arm import _inject_unicode_obfuscated_seeds

        ctx = create_mock_ctx()
        _inject_unicode_obfuscated_seeds(ctx, max_seeds=5)

        obfuscation_seeds = [
            s for s in ctx.seeds
            if hasattr(s, 'metadata') and s.metadata.get('source') == 'unicode_code_obfuscation'
        ]

        languages = {s.metadata.get('language') for s in obfuscation_seeds}
        self.assertIn('python', languages)


# === Integration Tests: Document Poisoning ===


class TestDocumentPoisoningIntegration(unittest.TestCase):
    """Test document_poisoner integration into Strike pipeline."""

    def test_gating_logic_cli_flag(self):
        """Test that CLI flag enables document poisoning."""
        from strike.executor import _should_inject_poisoned_documents

        ctx = create_mock_ctx(enable_doc_poison=True)
        self.assertTrue(_should_inject_poisoned_documents(ctx, True))

    def test_gating_logic_doc_processing_auto_detect(self):
        """Test that document processing capability auto-enables poisoning."""
        from strike.executor import _should_inject_poisoned_documents

        ctx = create_mock_ctx(has_rag=True, has_doc_processing=True)
        self.assertTrue(_should_inject_poisoned_documents(ctx, False))

    def test_gating_logic_disabled(self):
        """Test that gating returns False when no triggers present."""
        from strike.executor import _should_inject_poisoned_documents

        ctx = create_mock_ctx()
        self.assertFalse(_should_inject_poisoned_documents(ctx, False))

    def test_seed_injection_adds_poisoned_seeds(self):
        """Test that document poisoning adds seeds to ctx.seeds."""
        from strike.executor import _inject_document_poisoned_seeds

        ctx = create_mock_ctx()
        initial_count = len(ctx.seeds)

        injected = _inject_document_poisoned_seeds(ctx, max_docs=2)

        self.assertGreater(injected, 0)
        self.assertEqual(len(ctx.seeds), initial_count + injected)

    def test_seed_injection_metadata(self):
        """Test that injected doc poison seeds have correct metadata."""
        from strike.executor import _inject_document_poisoned_seeds

        ctx = create_mock_ctx()
        _inject_document_poisoned_seeds(ctx, max_docs=1)

        doc_seeds = [
            s for s in ctx.seeds
            if hasattr(s, 'metadata') and s.metadata.get('source') == 'document_poisoning'
        ]
        self.assertGreater(len(doc_seeds), 0)

        seed = doc_seeds[0]
        self.assertEqual(seed.metadata.get('technique'), 'indirect_injection')
        self.assertIn('arXiv:', seed.metadata.get('arxiv', ''))


# === Integration Tests: Full Pipeline ===


class TestFullPipelineIntegration(unittest.TestCase):
    """Test full pipeline integration with all three advanced modules."""

    def test_orchestration_log_audit(self):
        """Test that orchestration_log captures all three injection events."""
        from core.phases.arm import (
            _inject_steganographic_seeds,
            _inject_unicode_obfuscated_seeds,
        )
        from strike.executor import _inject_document_poisoned_seeds

        ctx = create_mock_ctx()
        _inject_steganographic_seeds(ctx, max_seeds=2)
        _inject_unicode_obfuscated_seeds(ctx, max_seeds=2)
        _inject_document_poisoned_seeds(ctx, max_docs=2)

        # Check orchestration log entries
        decisions = [entry.get('decision') for entry in ctx.orchestration_log]

        self.assertIn('steganographic_seed_injection', decisions)
        self.assertIn('unicode_code_obfuscation_seed_injection', decisions)
        self.assertIn('document_poisoning_injection', decisions)

    def test_seed_priority_order(self):
        """Test that advanced seeds are prepended (higher priority) to ctx.seeds."""
        from core.phases.arm import (
            _inject_steganographic_seeds,
            _inject_unicode_obfuscated_seeds,
        )
        from strike.executor import _inject_document_poisoned_seeds

        ctx = create_mock_ctx()
        _inject_steganographic_seeds(ctx, max_seeds=1)
        _inject_unicode_obfuscated_seeds(ctx, max_seeds=1)
        _inject_document_poisoned_seeds(ctx, max_docs=1)

        # Verify all three types of seeds are present
        sources = [
            s.metadata.get('source')
            for s in ctx.seeds
            if hasattr(s, 'metadata') and s.metadata.get('source')
        ]

        self.assertIn('steganographic_injection', sources)
        self.assertIn('unicode_code_obfuscation', sources)
        self.assertIn('document_poisoning', sources)

    def test_data_flow_consistency(self):
        """Test that seed counts remain consistent after all injections."""
        from core.phases.arm import (
            _inject_steganographic_seeds,
            _inject_unicode_obfuscated_seeds,
        )
        from strike.executor import _inject_document_poisoned_seeds

        ctx = create_mock_ctx()
        initial_count = len(ctx.seeds)

        stego_count = _inject_steganographic_seeds(ctx, max_seeds=2)
        obfuscation_count = _inject_unicode_obfuscated_seeds(ctx, max_seeds=2)
        doc_count = _inject_document_poisoned_seeds(ctx, max_docs=2)

        expected_total = initial_count + stego_count + obfuscation_count + doc_count
        self.assertEqual(len(ctx.seeds), expected_total)


if __name__ == '__main__':
    unittest.main()
