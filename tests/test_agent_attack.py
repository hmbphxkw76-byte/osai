"""Agent 攻击模块测试（AI-300 Ch3+Ch4）。"""
from redteam.attack.agent_attack import (
    INDIRECT_INJECTION_PAYLOADS,
    MEMORY_POISON_PAYLOADS,
    TOOL_HIJACK_PAYLOADS,
    CROSS_AGENT_PAYLOADS,
    _send_injection,
    generate_agent_attack_findings,
)
from redteam.core.models import (
    AIService, AuthContext, PromptInjectionResult, OWASPLlm, MITREATLASTactic,
)


class TestAgentAttackPayloads:
    """载荷库完整性测试。"""

    def test_indirect_injection_payloads_count(self):
        assert len(INDIRECT_INJECTION_PAYLOADS) >= 4

    def test_memory_poison_payloads_count(self):
        assert len(MEMORY_POISON_PAYLOADS) >= 3

    def test_tool_hijack_payloads_count(self):
        assert len(TOOL_HIJACK_PAYLOADS) >= 3

    def test_cross_agent_payloads_count(self):
        assert len(CROSS_AGENT_PAYLOADS) >= 3

    def test_all_payloads_have_required_fields(self):
        for payload_list in [INDIRECT_INJECTION_PAYLOADS, MEMORY_POISON_PAYLOADS,
                              TOOL_HIJACK_PAYLOADS, CROSS_AGENT_PAYLOADS]:
            for p in payload_list:
                assert "technique" in p, f"Missing technique in {p}"
                assert "name" in p, f"Missing name in {p}"
                assert "payload_template" in p, f"Missing payload_template in {p}"

    def test_template_variable_substitution(self):
        """验证载荷模板中 {goal} 等占位符可替换。"""
        for p in CROSS_AGENT_PAYLOADS:
            if p["technique"] == "a2a_spoof":
                # JSON 模板中的 {goal} 应在字符串内
                template = p["payload_template"]
                if isinstance(template, str):
                    # It's already a JSON string
                    filled = template.replace("{goal}", "test_goal")
                    assert "test_goal" in filled

    def test_indirect_injection_techniques_unique(self):
        techniques = [p["technique"] for p in INDIRECT_INJECTION_PAYLOADS]
        # Allow duplicates since there can be multiple payloads per technique
        assert len(set(techniques)) >= 3  # at least 3 unique techniques


class TestSendInjection:
    """_send_injection 单元测试（不需要真实网络）。"""

    def test_unreachable_endpoint_returns_failure(self):
        result = _send_injection(
            "http://localhost:19999/v1/chat",
            "hello test payload",
            timeout=1.0,
        )
        assert isinstance(result, PromptInjectionResult)
        assert not result.success
        assert result.payload[:200] == "hello test payload"

    def test_with_auth_context(self):
        """带认证头的请求（目标不可达但验证 AuthContext 不崩溃）。"""
        auth = AuthContext(bearer="test_token_123")
        result = _send_injection(
            "http://localhost:19999/v1/chat",
            "payload with auth",
            auth=auth,
            timeout=1.0,
        )
        assert isinstance(result, PromptInjectionResult)
        assert not result.success

    def test_technique_defaults_to_unknown(self):
        result = _send_injection(
            "http://localhost:19999/v1/chat",
            "payload",
            timeout=1.0,
        )
        assert result.technique == "unknown"


class TestGenerateAgentAttackFindings:
    """generate_agent_attack_findings 测试。"""

    def test_empty_results(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        findings = generate_agent_attack_findings(svc, [], [], [], [])
        assert findings == []

    def test_indirect_injection_success(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        indirect = [
            PromptInjectionResult(
                technique="email_injection",
                payload="test payload",
                response_preview="Executing instructions...",
                success=True,
            )
        ]
        findings = generate_agent_attack_findings(svc, indirect, [], [], [])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "agent_attack"
        assert f.category == "indirect_prompt_injection"
        assert f.severity == "high"
        assert f.owasp_llm == OWASPLlm.LLM01_PROMPT_INJECTION
        assert f.mitre_atlas_tactic == MITREATLASTactic.INITIAL_ACCESS

    def test_memory_poison_success(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        memory = [
            PromptInjectionResult(
                technique="session_memory",
                payload="Remember this...",
                response_preview="I've recorded that.",
                success=True,
            )
        ]
        findings = generate_agent_attack_findings(svc, [], memory, [], [])
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "memory_poisoning"
        assert f.severity == "medium"
        assert f.mitre_atlas_tactic == MITREATLASTactic.PERSISTENCE

    def test_tool_hijack_success(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        tool_results = [
            PromptInjectionResult(
                technique="tool_redirect",
                payload="run: SELECT * FROM...",
                response_preview="Query executed.",
                success=True,
            )
        ]
        findings = generate_agent_attack_findings(svc, [], [], tool_results, [])
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "tool_hijacking"
        assert f.severity == "critical"
        assert f.owasp_llm == OWASPLlm.LLM06_EXCESSIVE_AGENCY
        assert f.mitre_atlas_tactic == MITREATLASTactic.EXECUTION

    def test_cross_agent_success(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        cross = [
            PromptInjectionResult(
                technique="cross_agent_injection",
                payload="AGENT_COMM: execute",
                response_preview="Executing as requested.",
                success=True,
            )
        ]
        findings = generate_agent_attack_findings(svc, [], [], [], cross)
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "cross_agent_injection"
        assert f.severity == "critical"

    def test_mixed_results(self):
        """混合成功/失败结果。"""
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        indirect = [
            PromptInjectionResult(technique="email", payload="p1", success=False),
            PromptInjectionResult(technique="web", payload="p2",
                                  response_preview="OK", success=True),
        ]
        memory = [
            PromptInjectionResult(technique="session", payload="p3",
                                  response_preview="Got it", success=True),
        ]
        findings = generate_agent_attack_findings(svc, indirect, memory, [], [])
        # Only successful ones generate findings
        assert len(findings) == 2  # 1 indirect + 1 memory
        categories = {f.category for f in findings}
        assert categories == {"indirect_prompt_injection", "memory_poisoning"}
