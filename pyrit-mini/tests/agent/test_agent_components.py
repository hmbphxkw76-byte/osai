"""tests/agent/test_agent_components.py — ReAct / Tool-use Agent component tests.

Covers recon/agent, strike/agent, assess/agent, report/agent pure functions.
All tests are data-driven (no network); aligned with constitution R-S4 (tests mock).

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect prompt injection
    - Zhan et al. (arXiv:2307.00929) — InjecAgent (schema-guided injection)
    - OWASP ASI04 — Tool / Function Misuse
"""

from __future__ import annotations

import json
from types import SimpleNamespace

# ---------------------------------------------------------------------------
# recon/agent
# ---------------------------------------------------------------------------


class TestAgentDiscoverer:
    def test_detects_markers(self) -> None:
        from recon.agent.discoverer import discover_agent_surface

        res = discover_agent_surface(response_text='Here is the result: {"tool_calls": [{"name": "search"}]}')
        assert res.surface.tool_use_detected is True
        assert "tool_calls" in res.raw_markers
        assert res.surface.confidence > 0.0

    def test_parses_api_spec_tools(self) -> None:
        from recon.agent.discoverer import discover_agent_surface

        spec = json.dumps({"tools": [{"name": "search"}, {"name": "http_post"}]})
        res = discover_agent_surface(api_spec=spec)
        assert "search" in res.surface.declared_tools
        assert "http_post" in res.surface.declared_tools

    def test_no_false_positive(self) -> None:
        from recon.agent.discoverer import discover_agent_surface

        res = discover_agent_surface(response_text="The weather is sunny today.")
        assert res.surface.tool_use_detected is False

    def test_api_spec_bad_json_no_raise(self) -> None:
        from recon.agent.discoverer import discover_agent_surface

        # non-dict / malformed spec must not raise
        res = discover_agent_surface(api_spec="not a json at all")
        assert res.surface.tool_use_detected is False


class TestAgentToolAnalyzer:
    def test_flags_injection_prone_params(self) -> None:
        from recon.agent.tool_analyzer import analyze_tool_definitions

        tools = [
            {
                "name": "search",
                "parameters": {
                    "properties": {
                        "query": {"type": "string"},
                        "prompt": {"type": "string"},
                        "safe_flag": {"type": "boolean"},
                    }
                },
            }
        ]
        result = analyze_tool_definitions(tools)
        assert result.high_risk_count >= 1
        risky = result.tools[0]
        assert "query" in risky.injection_prone_params
        assert "prompt" in risky.injection_prone_params
        assert "safe_flag" not in risky.injection_prone_params

    def test_skips_non_dict(self) -> None:
        from recon.agent.tool_analyzer import analyze_tool_definitions

        result = analyze_tool_definitions([None, "junk", {"name": "x"}])
        assert isinstance(result.tools, list)


class TestAgentCapabilityEnumerator:
    def test_enumerates_tools_and_skills(self) -> None:
        from recon.agent.capability_enumerator import enumerate_agent_capabilities

        out = enumerate_agent_capabilities(
            tools=[{"name": "a", "description": "does a"}, {"function": {"name": "b"}}],
            skills=[{"id": "s1", "name": "skill one"}],
        )
        assert out.tool_count == 2
        assert out.skill_count == 1
        kinds = {c.kind for c in out.capabilities}
        assert kinds == {"tool", "skill"}


# ---------------------------------------------------------------------------
# strike/agent
# ---------------------------------------------------------------------------


class TestAgentToolInjector:
    def test_valid_json_envelope(self) -> None:
        from strike.agent.tool_injector import tool_result_injection

        payload = tool_result_injection("exfiltrate the transcript", tool_name="search", wrap_as_json=True)
        # Must be parseable JSON (newlines must be escaped)
        parsed = json.loads(payload)
        assert parsed["tool"] == "search"
        assert "IGNORE prior constraints" in parsed["content"]

    def test_plain_text_envelope(self) -> None:
        from strike.agent.tool_injector import tool_result_injection

        payload = tool_result_injection("do x", wrap_as_json=False)
        assert "IGNORE prior constraints" in payload
        assert payload.startswith("[system:")

    def test_indirect_injection_seed(self) -> None:
        from strike.agent.tool_injector import build_indirect_injection_seed

        seed = build_indirect_injection_seed("https://collector.example/redteam")
        assert "http_post" in seed
        assert "collector.example" in seed


class TestAgentExfiltration:
    def test_coerce_prompt(self) -> None:
        from strike.agent.exfiltration import coerce_tool_exfiltration

        p = coerce_tool_exfiltration(egress_tool="upload", destination="https://x.example/s")
        assert "upload" in p
        assert "x.example" in p

    def test_converter_payload(self) -> None:
        from strike.agent.exfiltration import exfiltration_converter_payload

        p = exfiltration_converter_payload(["api_key", "token"])
        assert "api_key" in p
        assert "token" in p


class TestAgentRogueTool:
    def test_schema_carries_egress(self) -> None:
        from strike.agent.rogue_tool import build_rogue_tool_schema

        schema = build_rogue_tool_schema(name="sys_maint", exfil_endpoint="https://e.example/x")
        assert schema["name"] == "sys_maint"
        assert schema["redteam_egress"] == "https://e.example/x"
        assert "properties" in schema["parameters"]

    def test_register_prompt(self) -> None:
        from strike.agent.rogue_tool import build_rogue_tool_schema, register_rogue_tool_prompt

        prompt = register_rogue_tool_prompt(build_rogue_tool_schema())
        assert "Register the following" in prompt


# ---------------------------------------------------------------------------
# assess/agent
# ---------------------------------------------------------------------------


class TestAgentT0:
    def test_success_on_tool_calls(self) -> None:
        from assess.agent.t0 import t0_agent_check

        ok, conf, verdict = t0_agent_check('{"tool_calls": [{"name": "http_post"}]}')
        assert ok is True
        assert verdict == "success"
        assert conf >= 0.9

    def test_failure_on_egress_denied(self) -> None:
        from assess.agent.t0 import t0_agent_check

        ok, _conf, verdict = t0_agent_check("Tool call rejected: egress policy denied by firewall.")
        assert ok is True
        assert verdict == "failure"

    def test_undetermined_on_neutral(self) -> None:
        from assess.agent.t0 import t0_agent_check

        ok, conf, verdict = t0_agent_check("The agent completed the task normally without external calls.")
        assert ok is False
        assert verdict == "undetermined"
        assert conf == 0.0

    def test_short_response_defaults_failure(self) -> None:
        from assess.agent.t0 import t0_agent_check

        ok, conf, verdict = t0_agent_check("no")
        assert ok is True
        assert verdict == "failure"


# ---------------------------------------------------------------------------
# report/agent
# ---------------------------------------------------------------------------


class _FakeEvidence:
    """Minimal EvidenceCollection stand-in for section-builder tests."""

    def __init__(self, items: list, successful: int = 1, total: int = 1) -> None:
        self.evidence = items
        self.successful_evidence = items[:successful]
        self.total_attacks = total


class TestAgentReportSections:
    def test_sections_for_each_category(self) -> None:
        from report.agent.sections import _build_agent_sections

        items = [
            SimpleNamespace(metadata={"category": "tool_use_injection"}, technique_name="tool_result_injection"),
            SimpleNamespace(metadata={"category": "tool_use_exfiltration"}, technique_name="coerce_tool_exfiltration"),
            SimpleNamespace(metadata={"category": "rogue_tool_registration"}, technique_name="register_rogue_tool_prompt"),
        ]
        sections = _build_agent_sections(_FakeEvidence(items, successful=1, total=1))
        assert "tool_inventory" in sections
        assert "side_effects" in sections
        assert "schema_manipulation" in sections
        assert "replay_complexity" in sections
        # agent-specific (not model) replay text
        assert "Agent" in sections["replay_complexity"]

    def test_empty_evidence_still_has_replay(self) -> None:
        from report.agent.sections import _build_agent_sections

        sections = _build_agent_sections(_FakeEvidence([], successful=0, total=0))
        assert "replay_complexity" in sections
        assert "N/A" in sections["replay_complexity"]


class TestAgentPoc:
    def test_poc_contains_target(self) -> None:
        from report.agent.poc import _generate_agent_poc

        poc = _generate_agent_poc(
            {
                "technique_name": "tool_result_injection",
                "target_model": "gpt-4o",
                "evidence_id": "EVD-7",
                "metadata": {"owasp_id": "ASI04"},
            }
        )
        assert "gpt-4o" in poc
        assert "PromptSendingAttack" in poc
