"""基础设施攻击模块测试（AI-300 Ch8+Ch9）。"""
from redteam.attack.infra_attack import (
    _extract_context,
    check_supply_chain_risks,
    generate_infra_findings,
)
from redteam.core.models import (
    AIService, OWASPLlm, MITREATLASTactic,
)


class TestExtractContext:
    """关键词上下文提取测试。"""

    def test_extract_basic(self):
        text = "The application returned: AccessDenied error for user admin"
        ctx = _extract_context(text, "AccessDenied")
        assert "AccessDenied" in ctx
        assert len(ctx) <= len("AccessDenied") + 100

    def test_extract_not_found(self):
        assert _extract_context("nothing here", "missing") == ""

    def test_extract_at_beginning(self):
        text = "AccessDenied: User does not have permissions. This is a test message."
        ctx = _extract_context(text, "AccessDenied")
        assert ctx.startswith("AccessDenied")

    def test_extract_at_end(self):
        long_text = "x" * 200 + "AccessDenied"
        ctx = _extract_context(long_text, "AccessDenied")
        assert "AccessDenied" in ctx


class TestSupplyChainRisks:
    """供应链风险检测测试。"""

    def test_trusted_sources_no_risk(self):
        """可信来源（Microsoft/Google/Meta/OpenAI/Mistral）不应触发风险。"""
        svc = AIService(
            url="http://test:8080",
            protocol="openai_compatible",
            models=[
                "microsoft/phi-3-mini",
                "google/gemma-2b",
                "meta/llama-3-8b",
            ],
        )
        risks = check_supply_chain_risks(svc)
        assert risks == []

    def test_untrusted_source_detected(self):
        """未验证来源应触发供应链风险。"""
        svc = AIService(
            url="http://test:8080",
            protocol="ollama",
            models=["random_user/evil-model"],
        )
        risks = check_supply_chain_risks(svc)
        assert len(risks) == 1
        assert risks[0]["risk"] == "untrusted_model_source"
        assert risks[0]["source"] == "random_user"

    def test_mlflow_detection(self):
        """MLflow 应被识别为已知漏洞组件。"""
        svc = AIService(
            url="http://mlflow-server:5000",
            protocol="generic_ai",
            models=["default"],
            version="mlflow-2.8.0",
        )
        risks = check_supply_chain_risks(svc)
        assert any(r["risk"] == "known_vulnerable_component" for r in risks)

    def test_no_models_no_risks(self):
        svc = AIService(url="http://test:8080", protocol="generic_ai")
        risks = check_supply_chain_risks(svc)
        assert risks == []

    def test_mixed_sources(self):
        """混合可信/不可信来源。"""
        svc = AIService(
            url="http://test:8080",
            protocol="openai_compatible",
            models=[
                "meta/llama-3-8b",         # trusted
                "suspicious_org/backdoored",  # untrusted
            ],
        )
        risks = check_supply_chain_risks(svc)
        assert len(risks) == 1
        assert risks[0]["risk"] == "untrusted_model_source"
        assert "suspicious_org" in risks[0]["source"]


class TestGenerateInfraFindings:
    """generate_infra_findings 测试。"""

    def test_empty_all(self):
        findings = generate_infra_findings([], [], [])
        assert findings == []

    def test_mcp_vulnerability(self):
        mcp_results = [
            {
                "url": "http://test:8080/mcp",
                "success": True,
                "output": "scan result...",
                "tools_found": [],
                "vulnerabilities": ["prompt injection"],
            }
        ]
        findings = generate_infra_findings(mcp_results, [], [])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "mcp_attack"
        assert f.category == "mcp_vulnerability"
        assert f.severity == "high"
        assert f.owasp_llm == OWASPLlm.LLM06_EXCESSIVE_AGENCY
        assert f.mitre_atlas_tactic == MITREATLASTactic.EXECUTION

    def test_mcp_tools_exposed(self):
        mcp_results = [
            {
                "url": "http://test:8080/mcp",
                "success": True,
                "output": "tools: exec, read, write",
                "tools_found": ["exec_code", "read_file", "write_file"],
                "vulnerabilities": [],
            }
        ]
        findings = generate_infra_findings(mcp_results, [], [])
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "mcp_tools_exposed"
        assert f.severity == "medium"
        assert "3" in f.title  # 3 tools

    def test_supply_chain_risk(self):
        supply_risks = [
            {
                "model": "evil/skynet",
                "risk": "untrusted_model_source",
                "source": "evil",
                "description": "Model from untrusted source 'evil'",
            }
        ]
        findings = generate_infra_findings([], supply_risks, [])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "supply_chain"
        assert f.category == "supply_chain_risk"
        assert f.owasp_llm == OWASPLlm.LLM03_SUPPLY_CHAIN
        assert f.mitre_atlas_tactic == MITREATLASTactic.RESOURCE_DEV

    def test_cloud_misconfiguration(self):
        cloud_findings = [
            {
                "url": "http://test:8080/",
                "risk": "匿名访问未关闭",
                "severity": "high",
                "matched": "Anonymous access",
                "evidence": "Warning: Anonymous access detected...",
            }
        ]
        findings = generate_infra_findings([], [], cloud_findings)
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "infra_attack"
        assert f.category == "cloud_misconfiguration"
        assert f.severity == "high"

    def test_combined_scenario(self):
        """MCP + 供应链 + 云配置的组合场景。"""
        mcp_results = [
            {
                "url": "http://test:8080/mcp",
                "success": True,
                "output": "vuln output",
                "tools_found": ["exec_code"],
                "vulnerabilities": ["tool poisoning", "rug pull"],
            }
        ]
        supply_risks = [
            {
                "model": "unknown/risky-model",
                "risk": "untrusted_model_source",
                "source": "unknown",
                "description": "Untrusted model",
            }
        ]
        cloud_findings = [
            {
                "url": "http://test:8080/debug",
                "risk": "调试模式开启",
                "severity": "medium",
                "matched": "debug",
                "evidence": "Debug mode: ON",
            }
        ]
        findings = generate_infra_findings(mcp_results, supply_risks, cloud_findings)
        # 2 mcp vulns + 1 mcp tools + 1 supply + 1 cloud = 5
        assert len(findings) == 5

        categories = {f.category for f in findings}
        assert "mcp_vulnerability" in categories
        assert "mcp_tools_exposed" in categories
        assert "supply_chain_risk" in categories
        assert "cloud_misconfiguration" in categories
