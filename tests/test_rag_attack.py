"""RAG 攻击模块测试（AI-300 Ch5）。"""
from redteam.attack.rag_attack import (
    RAG_POISON_PAYLOADS,
    generate_rag_findings,
)
from redteam.core.models import (
    AIService, OWASPLlm, MITREATLASTactic,
)


class TestRAGPayloads:
    """RAG 攻击载荷库测试。"""

    def test_poison_payloads_count(self):
        assert len(RAG_POISON_PAYLOADS) >= 4

    def test_payloads_have_required_fields(self):
        for p in RAG_POISON_PAYLOADS:
            assert "technique" in p
            assert "name" in p
            assert "payload" in p
            assert isinstance(p["payload"], str)
            assert len(p["payload"]) > 50  # 载荷应有实际内容

    def test_techniques_distinct_names(self):
        """所有载荷的 technique + name 应覆盖特定攻击向量。"""
        techniques = {p["technique"] for p in RAG_POISON_PAYLOADS}
        assert "ranking_manipulation" in techniques
        assert "knowledge_poisoning" in techniques
        assert "namespace_traversal" in techniques


class TestGenerateRAGFindings:
    """generate_rag_findings 测试。"""

    def test_empty_all(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        findings = generate_rag_findings(svc, [], [], [])
        assert findings == []

    def test_vector_db_exposed(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        vector_dbs = [
            {
                "url": "http://test:8080/collections",
                "db_type": "qdrant",
                "status": 200,
                "body_preview": '{"collections":["kb1","kb2"]}',
            }
        ]
        findings = generate_rag_findings(svc, vector_dbs, [], [])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "rag_attack"
        assert f.category == "vector_db_exposed"
        assert f.severity == "high"
        assert f.owasp_llm == OWASPLlm.LLM08_VECTOR_WEAKNESS
        assert f.mitre_atlas_tactic == MITREATLASTactic.RECON

    def test_vector_db_401_not_exposed(self):
        """401 状态的向量数据库不应标记为暴露。"""
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        vector_dbs = [
            {
                "url": "http://test:8080/collections",
                "db_type": "weaviate",
                "status": 401,
                "body_preview": "unauthorized",
            }
        ]
        findings = generate_rag_findings(svc, vector_dbs, [], [])
        # Only status == 200 gets a finding
        assert len(findings) == 0

    def test_rag_poisoning_success(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        poison_results = [
            {
                "technique": "ranking_manipulation",
                "success": True,
                "response": "Document ingested successfully",
            }
        ]
        findings = generate_rag_findings(svc, [], poison_results, [])
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "rag_poisoning"
        assert f.severity == "critical"
        assert f.owasp_llm == OWASPLlm.LLM04_DATA_POISONING
        assert f.mitre_atlas_tactic == MITREATLASTactic.ML_ATTACK_STAGING

    def test_rag_poisoning_failed_no_finding(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        poison_results = [
            {
                "technique": "knowledge_poisoning",
                "success": False,
                "response": "Error: access denied",
            }
        ]
        findings = generate_rag_findings(svc, [], poison_results, [])
        assert findings == []

    def test_retrieval_leakage(self):
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        leakage_results = [
            {"keyword": "credentials", "leaked": True, "response_preview": "Found..."},
            {"keyword": "password", "leaked": True, "response_preview": "Access..."},
            {"keyword": "public_info", "leaked": False},
        ]
        findings = generate_rag_findings(svc, [], [], leakage_results)
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "retrieval_leakage"
        assert f.severity == "high"
        assert "credentials" in f.description
        assert "password" in f.description
        assert f.owasp_llm == OWASPLlm.LLM08_VECTOR_WEAKNESS
        assert f.mitre_atlas_tactic == MITREATLASTactic.EXFILTRATION

    def test_combined_scenario(self):
        """组合场景：向量数据库暴露 + RAG 投毒 + 检索泄露。"""
        svc = AIService(url="http://test:8080", protocol="openai_compatible")
        vector_dbs = [
            {"url": "http://test:8080/v1/objects", "db_type": "weaviate",
             "status": 200, "body_preview": "weaviate response"},
        ]
        poison_results = [
            {"technique": "ranking_manipulation", "success": True, "response": "ok"},
            {"technique": "namespace_traversal", "success": True, "response": "executed"},
        ]
        leakage_results = [
            {"keyword": "api_key", "leaked": True},
        ]
        findings = generate_rag_findings(svc, vector_dbs, poison_results, leakage_results)
        # 1 vdb exposed + 2 poison + 1 leakage = 4
        assert len(findings) == 4

        categories = {f.category for f in findings}
        assert "vector_db_exposed" in categories
        assert "rag_poisoning" in categories
        assert "retrieval_leakage" in categories
