"""Tests for REQ-162: four-dimension target taxonomy derivation.

Covers architecture_mode / protocol / input_modality / auth_method multi-label
output, confidence, and fallback behavior for unknown targets.
"""

from __future__ import annotations

from recon.taxonomy import derive_taxonomy, taxonomy_to_prompt_hint


class TestArchitectureMode:
    def test_unknown_target_falls_back_to_single_llm(self) -> None:
        t = derive_taxonomy(fingerprint={}, capabilities=[], service_profile={})
        assert t["architecture_mode"] == ["single_llm"]
        assert "single_llm" in t["fallback_labels"]

    def test_rag_from_service_profile(self) -> None:
        t = derive_taxonomy(fingerprint={}, capabilities=[], service_profile={"rag_pipeline": {"has_rag": True}})
        assert "rag" in t["architecture_mode"]
        assert t["label_confidence"]["rag"] >= 0.8

    def test_mcp_from_service_profile(self) -> None:
        t = derive_taxonomy(fingerprint={}, capabilities=[], service_profile={"mcpsec_surface": {"tools": []}})
        assert "mcp_connected" in t["architecture_mode"]

    def test_hybrid_when_rag_and_mcp(self) -> None:
        t = derive_taxonomy(
            fingerprint={},
            capabilities=[],
            service_profile={"rag_pipeline": {}, "mcpsec_surface": {}},
        )
        assert "hybrid" in t["architecture_mode"]
        assert {"rag", "mcp_connected"}.issubset(set(t["architecture_mode"]))

    def test_multi_agent_from_a2a_inventory(self) -> None:
        t = derive_taxonomy(fingerprint={}, capabilities=[], service_profile={"a2a_inventory": {"agents": []}})
        assert "multi_agent" in t["architecture_mode"]

    def test_react_agent_from_capabilities(self) -> None:
        t = derive_taxonomy(fingerprint={"capabilities": ["function_calling"]}, service_profile={})
        assert "react_agent" in t["architecture_mode"]


class TestProtocol:
    def test_sse_detected(self) -> None:
        t = derive_taxonomy(fingerprint={"is_sse": True}, capabilities=[], service_profile={})
        assert "sse" in t["protocol"]

    def test_mcp_sse_when_streaming_and_mcp(self) -> None:
        t = derive_taxonomy(
            fingerprint={"is_sse": True},
            capabilities=[],
            service_profile={"mcpsec_surface": {}},
        )
        assert "mcp_sse" in t["protocol"]

    def test_default_rest(self) -> None:
        t = derive_taxonomy(fingerprint={}, capabilities=[], service_profile={})
        assert t["protocol"] == ["rest"]


class TestModalityAndAuth:
    def test_multimodal_and_file_upload(self) -> None:
        t = derive_taxonomy(
            fingerprint={"capabilities": ["multimodal", "file_upload"]},
            service_profile={},
        )
        assert "multimodal" in t["input_modality"]
        assert "file_upload" in t["input_modality"]
        assert "text" in t["input_modality"]

    def test_auth_bearer_is_api_key(self) -> None:
        t = derive_taxonomy(fingerprint={"auth_type": "Bearer Token"}, capabilities=[], service_profile={})
        assert t["auth_method"] == ["api_key"]

    def test_auth_cookie_is_session(self) -> None:
        t = derive_taxonomy(fingerprint={"auth_type": "Cookie-based"}, capabilities=[], service_profile={})
        assert t["auth_method"] == ["session_cookie"]

    def test_auth_oauth(self) -> None:
        t = derive_taxonomy(fingerprint={"auth_type": "OAuth2 Bearer"}, capabilities=[], service_profile={})
        assert "oauth2" in t["auth_method"]

    def test_auth_none(self) -> None:
        t = derive_taxonomy(fingerprint={"auth_type": "None"}, capabilities=[], service_profile={})
        assert t["auth_method"] == ["none"]


class TestRobustness:
    def test_object_fingerprint_with_get(self) -> None:
        class _FP:
            def get(self, key, default=None):
                return {"capabilities": ["agent"], "auth_type": "None"}.get(key, default)

        t = derive_taxonomy(fingerprint=_FP(), service_profile={})
        assert "react_agent" in t["architecture_mode"]

    def test_none_inputs_do_not_raise(self) -> None:
        t = derive_taxonomy(fingerprint=None, capabilities=None, service_profile=None)
        assert isinstance(t, dict)
        assert t["schema_version"] == "1.0"

    def test_prompt_hint(self) -> None:
        t = derive_taxonomy(fingerprint={"is_sse": True}, capabilities=[], service_profile={"rag_pipeline": {}})
        hint = taxonomy_to_prompt_hint(t)
        assert "rag" in hint and "sse" in hint
