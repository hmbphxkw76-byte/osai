"""AIMap runner 单元测试（增强版：风险评分 + Finding 生成 + 协议指纹）。"""
from redteam.recon import aimap_runner


def test_run_returns_tuple():
    """基本功能：AIMap 不可用时返回空列表。"""
    comps, eps, findings, fingerprints = aimap_runner.run("https://x.ai")
    assert isinstance(comps, list)
    assert isinstance(eps, list)
    assert isinstance(findings, list)
    assert isinstance(fingerprints, list)


def test_extract_urls():
    """URL 提取逻辑。"""
    text = "Found: http://example.com/api/tags and https://ai.local:11434"
    urls = aimap_runner._extract_urls(text)
    assert len(urls) >= 1
    assert any("http" in u for u in urls)


def test_extract_urls_with_protocol():
    """按协议过滤 URL 提取。"""
    text = "Found: http://example.com:11434/api/tags and https://ai.local/api/v1/models"
    urls = aimap_runner._extract_urls(text, "ollama")
    assert len(urls) >= 1


def test_parse_fingerprint():
    """协议指纹解析。"""
    text = "MCP server detected - no authentication required - HTTP only - CORS wildcard *"
    fp = aimap_runner._parse_fingerprint(text, "mcp")
    assert fp.protocol == "mcp"
    assert fp.auth_required is False
    assert fp.tls is False
    assert fp.cors_open is True
    assert fp.risk_score > 0


def test_parse_fingerprint_secure():
    """安全配置的指纹解析。"""
    text = "Ollama detected - authentication required - HTTPS enabled"
    fp = aimap_runner._parse_fingerprint(text, "ollama")
    assert fp.protocol == "ollama"
    assert fp.auth_required is True
    assert fp.tls is True
    assert fp.cors_open is False
    # 安全配置风险评分应较低（仅未知认证 +1）
    assert fp.risk_score <= 2.0


def test_parse_models():
    """模型名解析。"""
    text = "Models: llama3:latest, gemma:7b, mistral - model id=gpt-4-turbo"
    models = aimap_runner._parse_models(text, "ollama")
    assert len(models) >= 1


def test_risk_to_severity():
    """风险评分到严重程度映射。"""
    assert aimap_runner._risk_to_severity(0) == "info"
    assert aimap_runner._risk_to_severity(2.0) == "low"
    assert aimap_runner._risk_to_severity(4.0) == "medium"
    assert aimap_runner._risk_to_severity(6.0) == "high"
    assert aimap_runner._risk_to_severity(9.0) == "critical"


def test_ai_fingerprint_risk_scoring():
    """AIFingerprint 综合风险评分验证。"""
    from redteam.core.models import AIFingerprint

    # 最危险：无认证 + 无 TLS + 关键工具 + 系统提示词泄漏 + 无审查
    fp = AIFingerprint(
        protocol="mcp",
        auth_required=False,
        auth_type="none",
        tls=False,
        cors_open=True,
        system_prompt_leaked=True,
        uncensored_model=True,
        tools=["exec_code", "run_shell", "query_db"],
    )
    assert fp.risk_score >= 8.0  # 4 + 1 + 0.5 + 0.5 + 2 + 0 (tools<10, but exec_code×2) + 1(dangerous combo)
    # Actually: 4(no_auth) + 2(critical tools x2 = exec_code+run_shell) + 1(cors) + 0.5(tls) + 0.5(prompt) + 2(uncensored) + 1(combo) = 11, capped at 10

    # 安全：全认证 + TLS
    fp2 = AIFingerprint(
        protocol="langserve",
        auth_required=True,
        auth_type="bearer",
        tls=True,
    )
    assert fp2.risk_score <= 1.0  # 0 - no risk factors


def test_protocol_detect():
    """协议检测。"""
    from redteam.core.models import AIProtocol
    assert AIProtocol.detect("http://localhost:11434/ollama/api/tags") == AIProtocol.OLLAMA
    assert AIProtocol.detect("https://example.com/comfyui/prompt") == AIProtocol.COMFYUI
    assert AIProtocol.detect("https://example.com/vllm/v1/models") == AIProtocol.VLLM
    assert AIProtocol.detect("https://example.com/login") is None
