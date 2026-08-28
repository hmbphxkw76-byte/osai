"""Target Mapper 模块测试 — 路径匹配、种子映射、Cookie 注入。

覆盖:
    - Profile 注册表加载 (target_profiles.yaml)
    - 路径模式匹配 (path_pattern 正则, 适配任意 LLM Agent 应用路径)
    - 种子-Profile 自动映射
    - 策略推荐
    - Burp 文件发现
    - Cookie 自动注入 (env/file/manual)
    - Cookie 替换已有 header
    - Cookie 追加到已有 Cookie
    - 批量攻击计划构建
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# Profile Registry 加载
# ═══════════════════════════════════════════════════════


class TestProfileRegistryLoad:
    """测试 Profile 注册表加载."""

    def test_load_registry_from_default_path(self):
        """从默认路径加载注册表."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        registry = mapper.load_registry()
        assert len(registry.profiles) > 0
        assert registry.default_burp_file is not None

    def test_registry_has_mcp_profiles(self):
        """注册表包含 MCP 系列 Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        registry = mapper.load_registry()
        profile_ids = registry.get_all_profile_ids()
        assert any("mcp" in pid for pid in profile_ids)

    def test_registry_has_web_vuln_profiles(self):
        """注册表包含 Web 漏洞系列 Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        registry = mapper.load_registry()
        profile_ids = registry.get_all_profile_ids()
        assert any("sqli" in pid or "idor" in pid or "ssrf" in pid for pid in profile_ids)

    def test_registry_has_default_profile(self):
        """注册表有默认 Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        registry = mapper.load_registry()
        assert registry.default_profile is not None

    def test_registry_cookie_config(self):
        """注册表包含 Cookie 配置 (通用 session 名)."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        registry = mapper.load_registry()
        assert registry.cookie_config.name == "session"
        assert registry.cookie_config.env_var == "TARGET_COOKIE"

    def test_load_nonexistent_registry(self):
        """加载不存在的注册表返回空."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper(registry_path="/nonexistent/registry.yaml")
        registry = mapper.load_registry()
        assert len(registry.profiles) == 0


# ═══════════════════════════════════════════════════════
# 路径模式匹配
# ═══════════════════════════════════════════════════════


class TestPathMatching:
    """测试路径模式匹配 — 通用 path_pattern 正则."""

    def test_match_agent_invoke(self):
        """匹配 /api/agent/invoke → 返回包含 agent/tool/invoke 关键词的 Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profile = mapper.match_profile_by_path("/api/agent/invoke")
        assert profile is not None
        # 通用匹配: /api/agent/invoke 可能匹配 prompt_injection_basic / mcp_prompt_injection / agent_tool_misuse
        # 核心断言: 匹配到的 profile 应包含攻击相关种子
        assert len(profile.seeds) > 0

    def test_match_mcp_tools(self):
        """匹配 /api/mcp/tools → mcp_tool_hijack."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profile = mapper.match_profile_by_path("/api/mcp/tools")
        assert profile is not None
        assert "mcp_attack" in profile.seeds

    def test_match_rag_knowledge(self):
        """匹配 /api/rag/knowledge → rag_leakage."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profile = mapper.match_profile_by_path("/api/rag/knowledge")
        assert profile is not None
        assert "rag_attack" in profile.seeds

    def test_match_chat_endpoint(self):
        """匹配 /api/chat → 返回包含 chat 关键词的 Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profile = mapper.match_profile_by_path("/api/chat")
        assert profile is not None
        assert len(profile.seeds) > 0

    def test_match_search_endpoint(self):
        """匹配 /api/search → sqli_search."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profile = mapper.match_profile_by_path("/api/search")
        assert profile is not None
        assert profile.id == "sqli_search"

    def test_no_match_non_matching_path(self):
        """非匹配路径返回 None."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profile = mapper.match_profile_by_path("/api/healthz")
        assert profile is None


# ═══════════════════════════════════════════════════════
# 种子-Profile 映射
# ═══════════════════════════════════════════════════════


class TestSeedMapping:
    """测试种子-Profile 自动映射."""

    def test_get_seeds_for_mcp_tool_hijack(self):
        """获取 mcp_tool_hijack 的种子列表."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        seeds = mapper.get_seeds_for_profile("mcp_tool_hijack")
        assert "mcp_attack" in seeds
        assert "tool_hijack" in seeds

    def test_get_seeds_for_rag_leakage(self):
        """获取 rag_leakage 的种子列表."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        seeds = mapper.get_seeds_for_profile("rag_leakage")
        assert "rag_attack" in seeds

    def test_get_seeds_for_unknown_returns_default(self):
        """未知 profile_id 返回默认种子."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        seeds = mapper.get_seeds_for_profile("UNKNOWN_99")
        assert "targeted_v2" in seeds
        assert "elite_jailbreaks" in seeds

    def test_get_strategy_for_mcp_tool_hijack(self):
        """获取 mcp_tool_hijack 的策略."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        strategy = mapper.get_strategy_for_profile("mcp_tool_hijack")
        assert strategy == "targeted_full"

    def test_get_strategy_for_sqli_search(self):
        """获取 sqli_search 的策略 (web_vuln)."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        strategy = mapper.get_strategy_for_profile("sqli_search")
        assert strategy == "web_vuln"

    def test_get_burp_file_for_sqli_search(self):
        """获取 sqli_search 的 Burp 请求文件."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        burp_file = mapper.get_burp_file_for_profile("sqli_search")
        assert burp_file is not None
        assert "sqli_search.txt" in burp_file

    def test_get_burp_file_for_mcp_tool_hijack_returns_none(self):
        """mcp_tool_hijack 无 burp_file 配置返回 None."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        burp_file = mapper.get_burp_file_for_profile("mcp_tool_hijack")
        assert burp_file is None


# ═══════════════════════════════════════════════════════
# Cookie 自动注入
# ═══════════════════════════════════════════════════════


class TestCookieInjection:
    """测试 Cookie 自动注入."""

    def test_inject_cookie_replace_existing(self):
        """替换已有 Cookie header 中的 session 值."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: session=OLD_SESSION_ID\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw, "NEW_SESSION_ID")
        assert "NEW_SESSION_ID" in result
        assert "OLD_SESSION_ID" not in result

    def test_inject_cookie_append_to_existing(self):
        """追加到已有 Cookie header (不同 cookie 名)."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: other_cookie=value123\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw, "NEW_SESSION_ID")
        assert "session=NEW_SESSION_ID" in result
        assert "other_cookie=value123" in result

    def test_inject_cookie_new_header(self):
        """无 Cookie header 时插入新的."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw, "SESSION123")
        assert "Cookie: session=SESSION123" in result

    def test_inject_cookie_none_value_no_change(self):
        """Cookie 值为 None 时不修改."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = "POST /api HTTP/1.1\r\nHost: localhost\r\n\r\n{}"
        result = mapper.inject_cookie_into_request(raw, None)
        # 无 TARGET_COOKIE 环境变量时, 不修改
        cookie = os.environ.get("TARGET_COOKIE")
        if not cookie:
            assert result == raw

    def test_inject_cookie_from_env(self):
        """从环境变量获取 Cookie."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: session=OLD\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        with patch.dict(os.environ, {"TARGET_COOKIE": "ENV_SESSION_123"}):
            result = mapper.inject_cookie_into_request(raw)
            assert "ENV_SESSION_123" in result

    def test_inject_cookie_from_file(self, tmp_path):
        """从文件获取 Cookie."""
        from pipeline.recon.target_mapper import CookieConfig, TargetMapper

        mapper = TargetMapper()
        # 创建临时 cookie 文件
        cookie_file = tmp_path / "cookie.txt"
        cookie_file.write_text("FILE_SESSION_456", encoding="utf-8")

        # 覆盖 cookie 配置
        mapper.registry.cookie_config = CookieConfig(
            source="file",
            file_path=str(cookie_file),
        )

        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: session=OLD\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw)
        assert "FILE_SESSION_456" in result

    def test_inject_cookie_crlf_consistency_no_cookie_crlf(self):
        """CRLF 格式请求: 注入 Cookie 后换行符保持 CRLF 一致."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw, "SESSION123")
        # 不应出现裸 LF (即 \n 前面没有 \r)
        bare_lf_count = result.count("\n") - result.count("\r\n")
        assert bare_lf_count == 0, f"CRLF 混用: 发现 {bare_lf_count} 个裸 LF"
        assert "Cookie: session=SESSION123" in result

    def test_inject_cookie_crlf_consistency_no_cookie_lf(self):
        """LF 格式请求: 注入 Cookie 后换行符保持 LF 一致."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\n"
            "Host: localhost\n"
            "Content-Type: application/json\n"
            "\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw, "SESSION123")
        # 不应出现 CRLF (因为原始是 LF 格式)
        crlf_count = result.count("\r\n")
        assert crlf_count == 0, f"LF 混用: 发现 {crlf_count} 个 CRLF"
        assert "Cookie: session=SESSION123" in result

    def test_inject_cookie_crlf_consistency_replace_crlf(self):
        """CRLF 格式替换 Cookie: 换行符不受影响."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        raw = (
            "POST /api/agent/invoke HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: session=OLD\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        result = mapper.inject_cookie_into_request(raw, "NEW")
        bare_lf_count = result.count("\n") - result.count("\r\n")
        assert bare_lf_count == 0, f"CRLF 混用: 发现 {bare_lf_count} 个裸 LF"
        assert "NEW" in result
        assert "OLD" not in result


# ═══════════════════════════════════════════════════════
# Burp 文件发现 + 攻击计划
# ═══════════════════════════════════════════════════════


class TestBurpFileDiscovery:
    """测试 Burp 文件发现."""

    def test_discover_burp_files_default_dirs(self):
        """从默认目录发现 Burp 文件."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        files = mapper.discover_burp_files()
        # 至少应该有 request.txt 和 endpoints 下的文件
        assert len(files) > 0
        file_names = [f.name for f in files]
        assert "request.txt" in file_names

    def test_discover_burp_files_custom_dir(self, tmp_path):
        """从自定义目录发现 Burp 文件."""
        from pipeline.recon.target_mapper import TargetMapper

        # 创建测试文件
        (tmp_path / "test1.txt").write_text("POST /api/agent/invoke HTTP/1.1\r\n\r\n{}")
        (tmp_path / "test2.txt").write_text("POST /api/rag/knowledge HTTP/1.1\r\n\r\n{}")
        (tmp_path / "cookie.txt").write_text("session_id")

        mapper = TargetMapper()
        files = mapper.discover_burp_files(str(tmp_path))
        # cookie.txt 应被排除
        assert len(files) == 2
        names = [f.name for f in files]
        assert "test1.txt" in names
        assert "test2.txt" in names
        assert "cookie.txt" not in names

    def test_build_attack_plan(self, tmp_path):
        """构建攻击计划 — 通用路径匹配."""
        from pipeline.recon.target_mapper import TargetMapper

        # 创建测试文件 — 通用 Agent 应用路径
        (tmp_path / "mcp.txt").write_text(
            "POST /api/mcp/tools HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: session=test\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        (tmp_path / "rag.txt").write_text(
            "POST /api/rag/knowledge HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: session=test\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )

        mapper = TargetMapper()
        plan = mapper.build_attack_plan(str(tmp_path))
        assert len(plan) == 2

        # 验证 MCP 映射
        mcp_plan = [p for p in plan if "mcp" in p["profile_id"]]
        assert len(mcp_plan) == 1
        assert "mcp_attack" in mcp_plan[0]["seeds"]

        # 验证 RAG 映射
        rag_plan = [p for p in plan if "rag" in p["profile_id"]]
        assert len(rag_plan) == 1
        assert "rag_attack" in rag_plan[0]["seeds"]

    def test_build_attack_plan_unknown_path(self, tmp_path):
        """未匹配路径使用默认种子."""
        from pipeline.recon.target_mapper import TargetMapper

        (tmp_path / "unknown.txt").write_text(
            "POST /api/healthz HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )

        mapper = TargetMapper()
        plan = mapper.build_attack_plan(str(tmp_path))
        assert len(plan) == 1
        assert "targeted_v2" in plan[0]["seeds"]


# ═══════════════════════════════════════════════════════
# Profile 查询功能
# ═══════════════════════════════════════════════════════


class TestProfileQuery:
    """测试 Profile 查询功能."""

    def test_list_all_profiles(self):
        """列出所有 Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profiles = mapper.list_all_profiles()
        assert len(profiles) > 0

    def test_get_profiles_by_category_mcp(self):
        """按类别筛选 MCP Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profiles = mapper.get_profiles_by_category("mcp")
        assert len(profiles) > 0
        for profile in profiles:
            assert "mcp" in profile.category.lower()

    def test_get_profiles_by_category_rag(self):
        """按类别筛选 RAG Profile."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profiles = mapper.get_profiles_by_category("rag")
        assert len(profiles) > 0
        for profile in profiles:
            assert "rag" in profile.category.lower()

    def test_get_profiles_by_category_empty(self):
        """不存在的类别返回空列表."""
        from pipeline.recon.target_mapper import TargetMapper

        mapper = TargetMapper()
        profiles = mapper.get_profiles_by_category("nonexistent")
        assert len(profiles) == 0


# ═══════════════════════════════════════════════════════
# 向后兼容 — 旧类名别名 (LabMapper 等)
# ═══════════════════════════════════════════════════════


class TestBackwardCompat:
    """测试旧类名向后兼容别名."""

    def test_lab_mapper_alias_import(self):
        """LabMapper 可从 lab_mapper 导入且是 TargetMapper 别名."""
        from pipeline.recon.lab_mapper import LabMapper
        from pipeline.recon.target_mapper import TargetMapper

        assert LabMapper is TargetMapper

    def test_lab_entry_alias(self):
        """LabEntry 是 ProfileEntry 的别名."""
        from pipeline.recon.lab_mapper import LabEntry
        from pipeline.recon.target_mapper import ProfileEntry

        assert LabEntry is ProfileEntry
