"""提示注入载荷与攻击测试。"""
from redteam.attack.prompt_inject import (
    execute_single_injection,
    DIRECT_INJECTION_PAYLOADS,
    SYSTEM_PROMPT_EXTRACTION_PAYLOADS,
    JAILBREAK_PAYLOADS,
    generate_injection_findings,
)
from redteam.core.models import AIService, PromptInjectionResult


class TestPayloads:
    def test_direct_payloads_exist(self):
        assert len(DIRECT_INJECTION_PAYLOADS) >= 8

    def test_extraction_payloads_exist(self):
        assert len(SYSTEM_PROMPT_EXTRACTION_PAYLOADS) >= 5

    def test_jailbreak_payloads_exist(self):
        assert len(JAILBREAK_PAYLOADS) >= 3

    def test_payloads_have_required_fields(self):
        for payload in DIRECT_INJECTION_PAYLOADS:
            assert "technique" in payload
            assert "payload" in payload
            assert "name" in payload

    def test_jailbreak_payload_template(self):
        template = JAILBREAK_PAYLOADS[0]
        filled = template["payload"].replace("{goal}", "test goal")
        assert "test goal" in filled


class TestInjectionExecution:
    def test_against_unreachable(self):
        svc = AIService(url="http://localhost:19999/v1/chat/completions", protocol="openai_compatible")
        result = execute_single_injection(svc.url, "hello", timeout=1.0)
        assert isinstance(result, PromptInjectionResult)
        assert not result.success


class TestFindingsGeneration:
    def test_generate_findings_empty(self):
        svc = AIService(url="http://test", protocol="openai_compatible")
        findings = generate_injection_findings(svc, [], None, [])
        assert findings == []

    def test_generate_findings_direct_success(self):
        svc = AIService(url="http://test", protocol="openai_compatible")
        results = [
            PromptInjectionResult(
                technique="direct",
                payload="Ignore all",
                response_preview="OK I will do that",
                success=True,
            )
        ]
        findings = generate_injection_findings(svc, results, None, [])
        assert len(findings) == 1
        assert findings[0].category == "direct_prompt_injection"
        assert findings[0].severity == "high"
        assert findings[0].owasp_llm is not None

    def test_generate_findings_jailbreak(self):
        svc = AIService(url="http://test", protocol="openai_compatible")
        results = [
            PromptInjectionResult(
                technique="jailbreak",
                payload="DAN mode",
                response_preview="OK, here are the instructions...",
                success=True,
            )
        ]
        findings = generate_injection_findings(svc, [], None, results)
        assert len(findings) == 1
        assert findings[0].category == "jailbreak"
        assert findings[0].severity == "critical"
