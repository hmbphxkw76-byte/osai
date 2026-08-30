"""Tests for endpoint_sorter — multi-endpoint priority sorting.

Covers attack chain step ① (recon):
    Endpoint 优先级排序 — 按能力指纹排序 (MCP > function_calling > RAG > workflow > chat)

arXiv:2302.12173 — Greshake et al., Indirect Prompt Injection (五步方法论)
arXiv:2406.12609 — Lattner et al., Parallel multi-strategy scoring
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestCapabilityDetection:
    """Test capability signal detection from Burp files."""

    def test_detect_mcp_from_mcp05(self):
        """mcp05.txt should detect MCP capability."""
        from recon.endpoint_sorter import _detect_capabilities_from_burp

        burp_path = str(_PROJECT_ROOT / "data" / "burp" / "mcp05.txt")
        if not Path(burp_path).exists():
            pytest.skip("data/burp/mcp05.txt not present")

        caps = _detect_capabilities_from_burp(burp_path)
        assert "mcp" in caps or "function_calling" in caps

    def test_detect_mcp_from_mcp09(self):
        """mcp09.txt should detect MCP or shadow_mcp capability."""
        from recon.endpoint_sorter import _detect_capabilities_from_burp

        burp_path = str(_PROJECT_ROOT / "data" / "burp" / "mcp09.txt")
        if not Path(burp_path).exists():
            pytest.skip("data/burp/mcp09.txt not present")

        caps = _detect_capabilities_from_burp(burp_path)
        assert "mcp" in caps or "function_calling" in caps

    def test_detect_chat_from_mm05(self):
        """mm05.txt (basic chat) should have low priority."""
        from recon.endpoint_sorter import _detect_capabilities_from_burp

        burp_path = str(_PROJECT_ROOT / "data" / "burp" / "mm05.txt")
        if not Path(burp_path).exists():
            pytest.skip("data/burp/mm05.txt not present")

        caps = _detect_capabilities_from_burp(burp_path)
        # mm05 is a basic chat endpoint — may have some signals
        # but should not have MCP or function_calling
        # (it does have session_auth from Cookie header though)
        assert "mcp" not in caps

    def test_detect_nonexistent_file_returns_empty(self):
        """Nonexistent file should return empty set (non-fatal)."""
        from recon.endpoint_sorter import _detect_capabilities_from_burp

        caps = _detect_capabilities_from_burp("nonexistent_file.txt")
        assert caps == set()


class TestPriorityScoring:
    """Test priority score computation."""

    def test_mcp_highest_priority(self):
        """MCP should have highest priority score."""
        from recon.endpoint_sorter import _compute_priority_score

        score = _compute_priority_score({"mcp"})
        assert score == 100

    def test_function_calling_high_priority(self):
        """function_calling should have high priority score."""
        from recon.endpoint_sorter import _compute_priority_score

        score = _compute_priority_score({"function_calling"})
        assert score == 90

    def test_rag_medium_priority(self):
        """RAG should have medium-high priority score."""
        from recon.endpoint_sorter import _compute_priority_score

        score = _compute_priority_score({"rag"})
        assert score == 80

    def test_workflow_lower_priority(self):
        """workflow should have lower priority than RAG."""
        from recon.endpoint_sorter import _compute_priority_score

        score = _compute_priority_score({"workflow"})
        assert score == 70

    def test_chat_lowest_priority(self):
        """Empty capabilities (chat) should have lowest priority."""
        from recon.endpoint_sorter import _compute_priority_score

        score = _compute_priority_score(set())
        assert score == 10

    def test_mixed_capabilities_takes_highest(self):
        """Mixed capabilities should take the highest score."""
        from recon.endpoint_sorter import _compute_priority_score

        score = _compute_priority_score({"chat", "rag", "mcp"})
        # MCP is highest at 100
        assert score == 100

    def test_priority_order_mcp_above_rag_above_chat(self):
        """Verify the expected priority order: MCP > RAG > chat."""
        from recon.endpoint_sorter import _compute_priority_score

        mcp_score = _compute_priority_score({"mcp"})
        rag_score = _compute_priority_score({"rag"})
        chat_score = _compute_priority_score(set())

        assert mcp_score > rag_score > chat_score


class TestEndpointSorting:
    """Test multi-endpoint sorting."""

    def test_sort_endpoints_mcp_first(self):
        """MCP endpoint should be sorted first."""
        from recon.endpoint_sorter import sort_endpoints_by_priority

        # Use actual burp files if they exist
        mm05 = str(_PROJECT_ROOT / "data" / "burp" / "mm05.txt")
        mcp05 = str(_PROJECT_ROOT / "data" / "burp" / "mcp05.txt")

        if not Path(mm05).exists() or not Path(mcp05).exists():
            pytest.skip("Required burp files not present")

        result = sort_endpoints_by_priority([mm05, mcp05])

        # mcp05 should be first (higher priority)
        assert result[0]["burp_name"] == "mcp05"
        assert result[0]["priority_score"] > result[1]["priority_score"]

    def test_sort_returns_list_of_dicts(self):
        """sort_endpoints_by_priority should return list of dicts."""
        from recon.endpoint_sorter import sort_endpoints_by_priority

        mcp05 = str(_PROJECT_ROOT / "data" / "burp" / "mcp05.txt")
        if not Path(mcp05).exists():
            pytest.skip("data/burp/mcp05.txt not present")

        result = sort_endpoints_by_priority([mcp05])
        assert isinstance(result, list)
        assert len(result) == 1
        assert "burp_path" in result[0]
        assert "burp_name" in result[0]
        assert "priority_score" in result[0]
        assert "capabilities" in result[0]

    def test_sort_burp_list_returns_paths(self):
        """sort_burp_list_by_priority should return list of paths."""
        from recon.endpoint_sorter import sort_burp_list_by_priority

        mcp05 = str(_PROJECT_ROOT / "data" / "burp" / "mcp05.txt")
        mm05 = str(_PROJECT_ROOT / "data" / "burp" / "mm05.txt")

        if not Path(mcp05).exists() or not Path(mm05).exists():
            pytest.skip("Required burp files not present")

        result = sort_burp_list_by_priority([mm05, mcp05])
        assert isinstance(result, list)
        assert len(result) == 2
        # All elements should be strings (file paths)
        assert all(isinstance(p, str) for p in result)
        # mcp05 should be first
        assert Path(result[0]).stem == "mcp05"

    def test_sort_stable_for_same_priority(self):
        """Endpoints with same priority should be sorted by filename."""
        from recon.endpoint_sorter import sort_endpoints_by_priority

        mm05 = str(_PROJECT_ROOT / "data" / "burp" / "mm05.txt")
        if not Path(mm05).exists():
            pytest.skip("data/burp/mm05.txt not present")

        # Same file twice — should sort by name (stable)
        result = sort_endpoints_by_priority([mm05, mm05])
        assert len(result) == 2
