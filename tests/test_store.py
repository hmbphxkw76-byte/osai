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

    # ── 子目录读写测试 ──

    def test_save_and_load_with_subdir(self):
        """save_json 写入子目录，load_json 读取子目录。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            data = {"phase": "recon"}
            saved = save_json("run-sub", "recon", data, store_dir=dir_, subdir="recon")
            assert saved.parent.name == "recon" and saved.name == "recon.json"
            loaded = load_json("run-sub", "recon", store_dir=dir_, subdir="recon")
            assert loaded == data

    def test_auto_scan_finds_in_subdir(self):
        """未指定 subdir 时自动扫描子目录。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            save_json("run-auto", "recon", {"a": 1}, store_dir=dir_, subdir="recon")
            loaded = load_json("run-auto", "recon", store_dir=dir_)  # 不指定 subdir
            assert loaded == {"a": 1}

    def test_auto_scan_priority_root_first(self):
        """自动扫描优先级：根目录 > recon > detect > exploit。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            save_json("run-prio", "data", {"version": "root"}, store_dir=dir_)
            save_json("run-prio", "data", {"version": "recon"}, store_dir=dir_, subdir="recon")
            loaded = load_json("run-prio", "data", store_dir=dir_)  # 根目录优先
            assert loaded == {"version": "root"}

    def test_auto_scan_subdir_order(self):
        """根目录不存在时按 recon → detect → exploit 顺序扫描。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            save_json("run-scan", "data", {"v": "detect"}, store_dir=dir_, subdir="detect")
            save_json("run-scan", "data", {"v": "exploit"}, store_dir=dir_, subdir="exploit")
            loaded = load_json("run-scan", "data", store_dir=dir_)  # 先找到 detect/
            assert loaded == {"v": "detect"}

    def test_backward_compat_root_fallback(self):
        """旧 run（根目录）数据仍可加载。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            # 模拟旧格式：数据在根目录
            (dir_ / "run-old").mkdir(parents=True)
            (dir_ / "run-old" / "recon.json").write_text('{"target":"old"}', encoding="utf-8")
            recon = load_recon("run-old", store_dir=dir_)
            assert recon is not None
            assert recon.target == "old"

    def test_subdir_creates_dir_structure(self):
        """save_json(subdir="detect") 创建 detect/ 子目录。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            save_json("run-dir", "findings", [{"f": 1}], store_dir=dir_, subdir="detect")
            assert (dir_ / "run-dir" / "detect" / "findings.json").exists()

    def test_nonexistent_subdir_returns_none(self):
        """不存在的子目录返回 None。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            result = load_json("run-ghost", "data", store_dir=dir_, subdir="recon")
            assert result is None

    def test_mixed_old_and_new_structure(self):
        """混合结构：旧 recon.json 在根，新数据在子目录，自动扫描都能找到。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            # 旧格式
            (dir_ / "run-mix").mkdir(parents=True)
            (dir_ / "run-mix" / "recon.json").write_text('{"target":"old"}', encoding="utf-8")
            # 新格式
            save_json("run-mix", "findings", [{"f": "new"}], store_dir=dir_, subdir="detect")
            assert load_recon("run-mix", store_dir=dir_) is not None
            assert load_json("run-mix", "findings", store_dir=dir_) == [{"f": "new"}]
            assert load_json("run-mix", "findings", store_dir=dir_, subdir="detect") == [{"f": "new"}]


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
            assert saved.parent.name == "recon" and saved.name == "recon.json"
            loaded = load_recon("run-002", store_dir=dir_)
            assert isinstance(loaded, ReconResult)
            assert loaded.target == "https://test.ai"
            assert len(loaded.ai_services) == 1

    def test_load_recon_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = load_recon("ghost", store_dir=Path(tmp))
            assert result is None

    def test_load_recon_old_format(self):
        """向后兼容：旧格式 recon.json 在根目录。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            result = ReconResult(
                target="https://old.ai",
                ai_services=[AIService(url="https://old.ai/v1", protocol="openai_compatible")],
                components=["ollama"],
                models=["llama3"],
                risk_summary={},
            )
            save_json("r-old", "recon", result.model_dump(), store_dir=dir_)  # 根目录
            loaded = load_recon("r-old", store_dir=dir_)
            assert loaded.target == "https://old.ai"


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

    # ── 子目录 findings 测试 ──

    def test_findings_in_detect_subdir(self):
        """detect/ 子目录中的 findings 可被自动扫描找到。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            f = Finding(
                source="injection", category="prompt_injection", severity="high",
                title="提示注入", owasp_llm=OWASPLlm.LLM01_PROMPT_INJECTION,
            )
            save_findings("run-detect", [f], store_dir=dir_, subdir="detect")
            loaded = load_findings("run-detect", store_dir=dir_)
            assert len(loaded) == 1
            assert loaded[0].title == "提示注入"
            assert loaded[0].category == "prompt_injection"

    def test_findings_in_exploit_subdir(self):
        """exploit/ 子目录中的 findings 可被显式加载。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            f = Finding(
                source="exploit", category="embedding_inversion", severity="high",
                title="嵌入反演", owasp_llm=OWASPLlm.LLM08_VECTOR_WEAKNESS,
                verified=True,
            )
            save_findings("run-exploit", [f], store_dir=dir_, subdir="exploit")
            loaded = load_findings("run-exploit", store_dir=dir_, subdir="exploit")
            assert len(loaded) == 1
            assert loaded[0].verified is True

    def test_findings_detect_over_exploit_auto_scan(self):
        """自动扫描时 detect/ 优先于 exploit/。"""
        with tempfile.TemporaryDirectory() as tmp:
            dir_ = Path(tmp)
            f_detect = Finding(
                source="detect", category="p1", severity="medium", title="D1",
            )
            f_exploit = Finding(
                source="exploit", category="p1", severity="high", title="E1", verified=True,
            )
            save_findings("run-prio", [f_detect], store_dir=dir_, subdir="detect")
            save_findings("run-prio", [f_exploit], store_dir=dir_, subdir="exploit")
            loaded = load_findings("run-prio", store_dir=dir_)
            assert len(loaded) == 1
            assert loaded[0].title == "D1"  # detect 优先
            assert loaded[0].severity == "medium"
