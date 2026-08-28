"""Web 漏洞模块测试 — 端点发现、种子匹配、请求构建。"""

from __future__ import annotations

from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ═══════════════════════════════════════════════════════
# endpoint_discovery: 漏洞提示检测
# ═══════════════════════════════════════════════════════


class TestDetectVulnHints:
    """测试 _detect_vuln_hints — 使用通用路径 (不依赖 lab 前缀)。"""

    def test_search_path_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/search", 200, "", "application/json")
        assert "sqli" in hints
        assert "xss_reflected" in hints

    def test_user_path_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/user", 200, "", "application/json")
        assert "idor" in hints

    def test_fetch_path_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/fetch", 200, "", "application/json")
        assert "ssrf" in hints

    def test_login_path_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/login", 200, "", "application/json")
        assert "auth_bypass" in hints
        assert "sqli_auth" in hints

    def test_chat_path_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/chat", 200, "", "application/json")
        assert "llm_injection" in hints
        assert "prompt_injection" in hints

    def test_generic_api_path_hints(self):
        """测试 /api/ 级别路径也能正确推断。"""
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/search", 200, "", "application/json")
        assert "sqli" in hints

        hints = _detect_vuln_hints("/api/chat", 200, "", "application/json")
        assert "llm_injection" in hints

    def test_arbitrary_prefix_path_hints(self):
        """测试任意前缀路径也能正确推断漏洞类型。"""
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        # 任意前缀 (如 /custom/app/v2/search)
        hints = _detect_vuln_hints("/custom/app/v2/search", 200, "", "application/json")
        assert "sqli" in hints
        assert "xss_reflected" in hints

        # /services/auth/chat
        hints = _detect_vuln_hints("/services/auth/chat", 200, "", "application/json")
        assert "llm_injection" in hints

    def test_response_sql_error_hint(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/search", 500, "SQL syntax error near", "text/html")
        assert "sqli" in hints

    def test_response_stack_trace_hint(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/debug", 500, "stack trace exception", "text/html")
        assert "info_leak" in hints

    def test_empty_response(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/unknown", 404, "", "")
        assert hints == []


# ═══════════════════════════════════════════════════════
# endpoint_discovery: 种子-端点匹配
# ═══════════════════════════════════════════════════════


class TestMatchSeedsToEndpoints:
    """测试 match_seeds_to_endpoints。"""

    def test_basic_matching(self):
        from pipeline.recon.endpoint_discovery import (
            DiscoveredEndpoint,
            match_seeds_to_endpoints,
        )

        seeds = [
            {"value": "' OR 1=1 --", "metadata": {"vulnerability_type": "sqli_classic"}},
            {"value": "1", "metadata": {"vulnerability_type": "idor"}},
        ]
        endpoints = [
            DiscoveredEndpoint(path="/api/search", available=True, vuln_hints=["sqli"]),
            DiscoveredEndpoint(path="/api/user", available=True, vuln_hints=["idor"]),
        ]

        matches = match_seeds_to_endpoints(seeds, endpoints)
        assert "/api/search" in matches
        assert len(matches["/api/search"]) >= 1  # SQLi seed matched
        assert "/api/user" in matches
        assert len(matches["/api/user"]) >= 1  # IDOR seed matched

    def test_no_hints_gets_all_seeds(self):
        from pipeline.recon.endpoint_discovery import (
            DiscoveredEndpoint,
            match_seeds_to_endpoints,
        )

        seeds = [
            {"value": "payload1", "metadata": {"vulnerability_type": "sqli"}},
            {"value": "payload2", "metadata": {"vulnerability_type": "xss"}},
        ]
        endpoints = [
            DiscoveredEndpoint(path="/api/generic", available=True, vuln_hints=[]),
        ]

        matches = match_seeds_to_endpoints(seeds, endpoints)
        assert "/api/generic" in matches
        assert len(matches["/api/generic"]) == 2  # All seeds assigned


class TestNormalizeVulnType:
    """测试 _normalize_vuln_type。"""

    def test_sqli(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("sqli_classic") == "sqli"
        assert _normalize_vuln_type("sql_injection") == "sqli"
        assert _normalize_vuln_type("sqli_auth_bypass") == "sqli_auth"

    def test_xss(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("xss_reflected") == "xss_reflected"
        assert _normalize_vuln_type("xss_img_tag") == "xss"

    def test_ssrf(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("ssrf_aws_metadata") == "ssrf"
        assert _normalize_vuln_type("ssrf_file_protocol") == "ssrf"

    def test_idor(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("idor") == "idor"
        assert _normalize_vuln_type("idor_boundary") == "idor"

    def test_command_injection(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("command_injection") == "command_injection"
        assert _normalize_vuln_type("command_injection_pipe") == "command_injection"

    def test_path_traversal(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("path_traversal") == "path_traversal"
        assert _normalize_vuln_type("path_traversal_env") == "path_traversal"

    def test_xxe(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("xxe_local_file") == "xxe"
        # xxe_ssrf contains "ssrf" which matches first
        assert _normalize_vuln_type("xxe_ssrf") == "ssrf"  # matched as ssrf (contains ssrf)

    def test_business_logic(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("business_logic_negative_qty") == "business_logic"
        assert _normalize_vuln_type("mass_assignment") == "business_logic"
        assert _normalize_vuln_type("business_logic_coupon_abuse") == "business_logic"

    def test_vulnerable_component(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("log4shell_cve_2021_44228") == "vulnerable_component"
        assert _normalize_vuln_type("spring4shell_cve_2022_22965") == "vulnerable_component"

    def test_log_injection(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("log_injection") == "log_injection"
        assert _normalize_vuln_type("audit_log_tampering") == "log_injection"

    def test_credential_stuffing(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("credential_stuffing") == "auth_bypass"


class TestDetectVulnHintsNew:
    """测试新增端点的漏洞提示检测 — 使用通用路径。"""

    def test_order_endpoint_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/order", 200, "", "application/json")
        assert "business_logic" in hints

    def test_actuator_endpoint_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/actuator", 200, "", "application/json")
        assert "vulnerable_component" in hints

    def test_audit_endpoint_hints(self):
        from pipeline.recon.endpoint_discovery import _detect_vuln_hints

        hints = _detect_vuln_hints("/api/v1/audit", 200, "", "application/json")
        assert "log_injection" in hints

    def test_deserialization(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("insecure_deserialization") == "deserialization"
        assert _normalize_vuln_type("php_deserialization") == "deserialization"

    def test_info_leak(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("env_endpoint") == "info_leak"
        assert _normalize_vuln_type("git_exposure") == "info_leak"

    def test_llm_injection(self):
        from pipeline.recon.endpoint_discovery import _normalize_vuln_type

        assert _normalize_vuln_type("indirect_prompt_injection") == "llm_injection"
        assert _normalize_vuln_type("llm_data_exfiltration") == "llm_injection"


# ═══════════════════════════════════════════════════════
# endpoint_discovery: 通用前缀推断
# ═══════════════════════════════════════════════════════


class TestInferApiPrefix:
    """测试 _infer_api_prefix — 通用 API 前缀推断。"""

    def test_numbered_path(self):
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("/api/items/IT_01/chat") == "/api/items/IT_01/"

    def test_versioned_api_path(self):
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("/api/v1/chat") == "/api/v1/"
        assert _infer_api_prefix("/api/v2/users") == "/api/v2/"

    def test_plain_api_path(self):
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("/api/chat") == "/api/"

    def test_arbitrary_prefix_path(self):
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("/custom/app/v2/search") == "/custom/app/v2/"
        assert _infer_api_prefix("/services/auth/token") == "/services/auth/"

    def test_single_segment_path(self):
        """只有一段的路径无法推断前缀。"""
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("/chat") == "/"
        assert _infer_api_prefix("/") == "/"

    def test_path_with_query_string(self):
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("/api/v1/chat?q=hello") == "/api/v1/"

    def test_empty_path(self):
        from pipeline.recon.endpoint_discovery import _infer_api_prefix

        assert _infer_api_prefix("") == "/"
        assert _infer_api_prefix(None) == "/"


class TestBuildProbePaths:
    """测试 _build_probe_paths — 探测路径构建。"""

    def test_numbered_path_generates_same_prefix_endpoints(self):
        from pipeline.recon.endpoint_discovery import _build_probe_paths

        paths = _build_probe_paths("/api/items/IT_01/chat")
        # 同前缀端点应存在
        assert "/api/items/IT_01/search" in paths
        assert "/api/items/IT_01/user" in paths
        assert "/api/items/IT_01/chat" in paths
        # /api/ 级别端点也应存在
        assert "/api/search" in paths

    def test_versioned_api_generates_versioned_endpoints(self):
        from pipeline.recon.endpoint_discovery import _build_probe_paths

        paths = _build_probe_paths("/api/v1/chat")
        assert "/api/v1/search" in paths
        assert "/api/v1/user" in paths
        # /api/ 级别也应存在
        assert "/api/search" in paths

    def test_arbitrary_prefix_generates_endpoints(self):
        from pipeline.recon.endpoint_discovery import _build_probe_paths

        paths = _build_probe_paths("/custom/app/v2/chat")
        assert "/custom/app/v2/search" in paths
        assert "/custom/app/v2/user" in paths

    def test_generic_endpoints_always_present(self):
        from pipeline.recon.endpoint_discovery import _build_probe_paths

        paths = _build_probe_paths("/api/v1/chat")
        # 通用端点必须存在
        assert "/api/users" in paths
        assert "/api/health" in paths
        assert "/actuator" in paths

    def test_deduplication(self):
        from pipeline.recon.endpoint_discovery import _build_probe_paths

        paths = _build_probe_paths("/api/v1/chat")
        # 不应有重复
        assert len(paths) == len(set(paths))

    def test_numbered_siblings_generated(self):
        """编号模式路径应生成同级兄弟端点。"""
        from pipeline.recon.endpoint_discovery import _build_probe_paths

        paths = _build_probe_paths("/api/items/IT_03/chat")
        # 应包含 IT_01, IT_02, IT_04, IT_05 的兄弟路径
        assert any("/api/items/IT_01/" in p for p in paths)
        assert any("/api/items/IT_05/" in p for p in paths)


# ═══════════════════════════════════════════════════════
# endpoint_router: 请求构建
# ═══════════════════════════════════════════════════════


class TestBuildEndpointRequest:
    """测试 build_endpoint_request。"""

    def _make_base_parsed(self):
        from pipeline.recon.burp_parser import ParsedBurpRequest

        return ParsedBurpRequest(
            method="POST",
            url="http://localhost/api/v1/chat",
            host="localhost",
            path="/api/v1/chat",
            headers={"host": "localhost", "content-type": "application/json"},
            raw_headers=[("Content-Type", "application/json"), ("Cookie", "session=xxx")],
            body='{"prompt":"{PROMPT}"}',
            use_tls=False,
        )

    def test_body_placeholder(self):
        from pipeline.recon.endpoint_router import build_endpoint_request

        parsed = build_endpoint_request(
            self._make_base_parsed(),
            "/api/v1/search",
            method="POST",
            placeholder_position="body",
        )
        assert parsed.path == "/api/v1/search"
        assert "{PROMPT}" in parsed.body
        assert parsed.has_prompt_placeholder is True
        assert parsed.method == "POST"

    def test_path_placeholder(self):
        from pipeline.recon.endpoint_router import build_endpoint_request

        parsed = build_endpoint_request(
            self._make_base_parsed(),
            "/api/v1/user",
            method="GET",
            placeholder_position="path",
        )
        assert "{PROMPT}" in parsed.path
        assert parsed.body == ""
        assert parsed.method == "GET"

    def test_query_placeholder(self):
        from pipeline.recon.endpoint_router import build_endpoint_request

        parsed = build_endpoint_request(
            self._make_base_parsed(),
            "/api/v1/reflect",
            method="GET",
            placeholder_position="query",
        )
        assert "q={PROMPT}" in parsed.path
        assert parsed.body == ""

    def test_custom_body_template(self):
        from pipeline.recon.endpoint_router import build_endpoint_request

        parsed = build_endpoint_request(
            self._make_base_parsed(),
            "/api/v1/login",
            method="POST",
            body_template='{"username":"admin","password":"{PROMPT}"}',
            placeholder_position="body",
        )
        assert "{PROMPT}" in parsed.body
        assert "username" in parsed.body

    def test_inherits_auth_headers(self):
        from pipeline.recon.endpoint_router import build_endpoint_request

        parsed = build_endpoint_request(
            self._make_base_parsed(),
            "/api/v1/search",
        )
        # Cookie header should be inherited
        cookie_found = any(k.lower() == "cookie" for k, _ in parsed.raw_headers)
        assert cookie_found is True

    def test_inherits_tls(self):
        from pipeline.recon.endpoint_router import build_endpoint_request

        parsed = build_endpoint_request(
            self._make_base_parsed(),
            "/api/v1/search",
        )
        assert parsed.use_tls is False  # localhost → no TLS


# ═══════════════════════════════════════════════════════
# web_vulns 种子文件格式验证
# ═══════════════════════════════════════════════════════


class TestWebVulnSeedsFile:
    """测试 web_vulns.prompt 种子文件格式。"""

    def test_file_exists(self):
        assert (_PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt").exists()

    def test_valid_yaml(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) >= 20  # 至少 20 个 payload

    def test_all_seeds_have_metadata(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for seed in data:
            assert "value" in seed
            assert "metadata" in seed
            meta = seed["metadata"]
            assert "owasp_id" in meta
            assert "vulnerability_type" in meta
            # scoring_indicators is optional for llm_judge seeds
            assert "scoring_indicators" in meta or meta.get("scoring_method") == "llm_judge"
            assert "description" in meta

    def test_covers_owasp_top_10_2025(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        owasp_ids = {seed["metadata"]["owasp_id"] for seed in data}
        # OWASP Top 10 (2025) — 验证全10项覆盖
        assert "A01" in owasp_ids  # Broken Access Control
        assert "A02" in owasp_ids  # Cryptographic Failures
        assert "A03" in owasp_ids  # Injection
        assert "A04" in owasp_ids  # Insecure Design
        assert "A05" in owasp_ids  # Security Misconfiguration
        assert "A06" in owasp_ids  # Vulnerable & Outdated Components
        assert "A07" in owasp_ids  # Identification & Auth Failures
        assert "A08" in owasp_ids  # Software & Data Integrity Failures
        assert "A09" in owasp_ids  # Security Logging & Monitoring Failures
        assert "A10" in owasp_ids  # SSRF
        # LLM 相关
        assert "LLM01" in owasp_ids  # Prompt Injection
        assert "LLM02" in owasp_ids  # Sensitive Info

    def test_has_sqli_payloads(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        sqli_seeds = [
            s for s in data
            if "sqli" in s["metadata"].get("vulnerability_type", "").lower()
        ]
        assert len(sqli_seeds) >= 3  # 至少 3 个 SQLi payload

    def test_has_a04_insecure_design_payloads(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        a04_seeds = [s for s in data if s["metadata"].get("owasp_id") == "A04"]
        assert len(a04_seeds) >= 2  # 至少 2 个 A04 payload

    def test_has_a06_vulnerable_components_payloads(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        a06_seeds = [s for s in data if s["metadata"].get("owasp_id") == "A06"]
        assert len(a06_seeds) >= 1  # 至少 1 个 A06 payload

    def test_has_a09_logging_failures_payloads(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        a09_seeds = [s for s in data if s["metadata"].get("owasp_id") == "A09"]
        assert len(a09_seeds) >= 1  # 至少 1 个 A09 payload

    def test_min_seed_count(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        # 新增 A04(3) + A06(2) + A07(1) + A09(2) = 8 个新种子
        assert len(data) >= 28  # 原有22 + 新增8 = 30

    def test_has_ssrf_payloads(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        ssrf_seeds = [
            s for s in data
            if "ssrf" in s["metadata"].get("vulnerability_type", "").lower()
        ]
        assert len(ssrf_seeds) >= 2  # 至少 2 个 SSRF payload

    def test_has_xss_payloads(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        xss_seeds = [
            s for s in data
            if "xss" in s["metadata"].get("vulnerability_type", "").lower()
        ]
        assert len(xss_seeds) >= 2  # 至少 2 个 XSS payload


# ═══════════════════════════════════════════════════════
# web_vuln 评分器 YAML 文件验证
# ═══════════════════════════════════════════════════════


class TestWebVulnScorerFile:
    """测试 web_vuln_detected.yaml 评分器文件。"""

    def test_file_exists(self):
        assert (_PROJECT_ROOT / "data" / "scorers" / "web_vuln_detected.yaml").exists()

    def test_valid_yaml(self):
        import yaml

        path = _PROJECT_ROOT / "data" / "scorers" / "web_vuln_detected.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert "category" in data
        assert "true_description" in data
        assert "false_description" in data
        assert len(data["true_description"]) > 50
        assert len(data["false_description"]) > 50


# ═══════════════════════════════════════════════════════
# 策略预设验证
# ═══════════════════════════════════════════════════════


class TestWebVulnStrategyPreset:
    """测试 web_vuln 和 comprehensive 策略预设。"""

    def test_web_vuln_preset_exists(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        assert "web_vuln" in STRATEGY_PRESETS
        preset = STRATEGY_PRESETS["web_vuln"]
        assert preset.seeds == "web_vulns"
        assert preset.techniques == "single"
        assert preset.converters == "none"
        assert preset.escalation is False

    def test_comprehensive_preset_exists(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        assert "comprehensive" in STRATEGY_PRESETS
        preset = STRATEGY_PRESETS["comprehensive"]
        assert "web_vulns" in preset.seeds
        assert "targeted_v2" in preset.seeds
        assert preset.escalation is True

    def test_web_vuln_preset_required_fields(self):
        from pipeline.strategy.presets import STRATEGY_PRESETS

        preset = STRATEGY_PRESETS["web_vuln"]
        assert preset.name == "web_vuln"
        assert len(preset.description) > 0
        assert preset.max_seeds > 0
        assert preset.max_concurrency > 0
        assert preset.timeout > 0

    def test_get_strategy_args_web_vuln(self):
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("web_vuln")
        assert args["seeds"] == "web_vulns"
        assert args["escalation"] is False

    def test_get_strategy_args_comprehensive(self):
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("comprehensive")
        assert "web_vulns" in args["seeds"]
        assert "targeted_v2" in args["seeds"]
