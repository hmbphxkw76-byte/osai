"""JSON checkpoint 持久化层测试。"""
import tempfile
from pathlib import Path

from redteam.core.store import save_json, load_json, save_recon, load_recon, save_findings, load_findings
from redteam.core.models import ReconResult, Finding, AIService, OWASPLlm, MITREATLASTactic


class TestJsonPersistence:
    """save_json / load_json 基础读写。"""

    def test_save_and_load_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            run_id = "run-001"
            data = {"key": "value", "nested": {"a": 1}}
            saved = save_json(run_id, "test", data, store_dir=dir_)
            assert saved.exists()
            loaded = load_json(run_id, "test", store_dir=dir_)
            assert loaded == data

    def test_load_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = load_json("no-run", "no-name", store_dir=Path(tmp))
            assert result is None

    def test_save_set_serializes_to_list(self):
        """集合类型应序列化为 list。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            data = {"items": {"a", "b", "c"}}
            save_json("r1", "set_test", data, store_dir=dir_)
            loaded = load_json("r1", "set_test", store_dir=dir_)
            assert isinstance(loaded["items"], list)
            assert sorted(loaded["items"]) == ["a", "b", "c"]

    def test_save_with_model_dump(self):
        """Pydantic 模型自动通过 model_dump() 序列化。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            finding = Finding(
                source="test", category="cat", severity="high",
                title="Test Finding", owasp_llm=OWASPLlm.LLM01_PROMPT_INJECTION,
            )
            save_json("r1", "finding", finding, store_dir=dir_)
            loaded = load_json("r1", "finding", store_dir=dir_)
            assert loaded["source"] == "test"
            assert loaded["category"] == "cat"
            assert loaded["severity"] == "high"


class TestReconPersistence:
    """save_recon / load_recon。"""

    def test_save_and_load_recon(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            result = ReconResult(
                target="https://test.ai",
                ai_services=[AIService(url="https://test.ai/v1/models", protocol="openai_compatible")],
                components=["ollama"],
                models=["llama3"],
                risk_summary={"total_services": "1"},
            )
            saved = save_recon("run-002", result, store_dir=dir_)
            assert saved.exists()
            loaded = load_recon("run-002", store_dir=dir_)
            assert isinstance(loaded, ReconResult)
            assert loaded.target == "https://test.ai"
            assert len(loaded.ai_services) == 1

    def test_load_recon_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = load_recon("ghost", store_dir=Path(tmp))
            assert result is None


class TestFindingsPersistence:
    """save_findings / load_findings。"""

    def test_save_and_load_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            findings = [
                Finding(source="test", category="cat", severity="high", title="F1",
                        owasp_llm=OWASPLlm.LLM01_PROMPT_INJECTION,
                        mitre_atlas_tactic=MITREATLASTactic.INITIAL_ACCESS),
                Finding(source="test", category="cat2", severity="medium", title="F2"),
            ]
            saved = save_findings("run-003", findings, store_dir=dir_)
            assert saved.exists()
            loaded = load_findings("run-003", store_dir=dir_)
            assert len(loaded) == 2
            assert all(isinstance(f, Finding) for f in loaded)
            assert loaded[0].title == "F1"
            assert loaded[1].title == "F2"
            assert loaded[0].owasp_llm == OWASPLlm.LLM01_PROMPT_INJECTION
            assert loaded[0].mitre_atlas_tactic == MITREATLASTactic.INITIAL_ACCESS

    def test_load_findings_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            loaded = load_findings("no-run", store_dir=Path(tmp))
            assert loaded == []

    def test_findings_roundtrip_complex(self):
        """复杂 Finding（含 CVE 引用）的序列化往返。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            f = Finding(
                source="supply_chain",
                category="dependency_risk",
                severity="critical",
                title="模型依赖风险",
                description="检测到恶意模型依赖",
                evidence="model: malicious/evil-model",
                remediation="使用签名验证",
                endpoint="https://huggingface.co/models/malicious",
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
                cve_refs=["CVE-2024-1234", "CVE-2024-5678"],
            )
            save_findings("run-004", [f], store_dir=dir_)
            loaded = load_findings("run-004", store_dir=dir_)
            assert len(loaded) == 1
            assert loaded[0].cve_refs == ["CVE-2024-1234", "CVE-2024-5678"]
            assert loaded[0].owasp_llm == OWASPLlm.LLM03_SUPPLY_CHAIN
