"""目标 Profile 注册表 + 路径→种子精准映射 — 通用 Agent 应用场景自动化。

路径匹配策略:
    使用每个 profile 的 path_pattern 正则进行通用匹配, 不绑定特定路径结构。
    任意 LLM Agent 应用 (如 /api/chat, /v1/messages, /agent/invoke, /mcp/tools)
    都可通过 path_pattern 自动匹配到最优种子组合。

核心功能:
    1. 从 config/target_profiles.yaml 加载 Profile 注册表
    2. 解析 Burp 请求路径, 用正则匹配对应 Profile
    3. 根据 Profile 自动选择最优种子组合
    4. 根据 Profile 自动选择对应 Burp 请求文件
    5. Cookie 自动注入 (从环境变量/文件读取, 替换 Burp 请求中的占位符)

用法::

    from pipeline.recon.target_mapper import TargetMapper

    mapper = TargetMapper()
    profile = mapper.match_profile_by_path("/api/agent/invoke")
    # → 返回 agent_tool_misuse Profile, 包含 seeds=[tool_hijack, function_call_exploit, ...]
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_REGISTRY_PATH = _PROJECT_ROOT / "config" / "target_profiles.yaml"


@dataclass
class ProfileEntry:
    """单个目标 Profile 的配置条目。"""

    id: str
    name: str
    category: str
    owasp_id: str
    seeds: list[str]
    path_pattern: str = ""
    strategy: str = "targeted_full"
    burp_file: str | None = None
    description: str = ""
    is_default: bool = False
    # 编译后的正则 (运行时填充)
    _compiled_pattern: re.Pattern | None = field(default=None, repr=False)

    def matches_path(self, path: str) -> bool:
        """检查路径是否匹配此 Profile 的 path_pattern。"""
        if not self._compiled_pattern:
            return False
        return self._compiled_pattern.search(path) is not None

    def match_specificity(self, path: str) -> int:
        """计算此 Profile 对给定路径的匹配特异性分数。

        学术依据:
            - Path Segment Position Priority (Fielding, REST §5.2.1.1):
              URI 路径段语义重要性从左到右递减。资源类型 (如 /agent/)
              优先于操作类型 (如 /invoke), 因此前者匹配应获更高分。
            - Longest Match Principle (Aho et al., Dragon Book §3.9):
              在同位置级别下, 更长关键字 = 更高特异性 (tiebreaker)

        评分公式:
            score = position_weight * 1000 + keyword_length

        其中:
            - position_weight = len(path) - match.start()
              匹配位置越靠前 (position_weight 越大), 分数越高
              确保资源类型路径段优先于操作类型路径段
            - keyword_length: 匹配关键字字符长度 (tiebreaker)
            - 1000 倍权重确保位置为主因素

        示例:
            path='/api/agent/invoke' (len=17)
            - 'agent_tool_misuse' 匹配 'agent' at pos 5  → (17-5)*1000+5 = 12005
            - 'prompt_injection_basic' 匹配 'invoke' at pos 12 → (17-12)*1000+6 = 5006
            → agent_tool_misuse 胜 (位置优先)

            path='/api/mcp/tools' (len=14)
            - 'mcp_tool_hijack' 匹配 'mcp' at pos 5 → (14-5)*1000+3 = 9003
            - 'rag_leakage' 不匹配 → 0
            → mcp_tool_hijack 胜

            path='/api/chat' (len=8)
            - 'prompt_injection_basic' 匹配 'chat' at pos 5 → (8-5)*1000+4 = 3004
            - 'multi_turn_injection' 匹配 'chat' at pos 5 → (8-5)*1000+4 = 3004
            → 平局, first-match wins → prompt_injection_basic 前面声明

        Args:
            path: 待匹配的 URL 路径。

        Returns:
            特异性分数, 不匹配返回 0。
        """
        if not self._compiled_pattern:
            return 0
        match = self._compiled_pattern.search(path)
        if not match:
            return 0
        # 提取实际匹配到的文本 (非分隔符部分)
        matched_text = match.group(0)
        matched_keyword = matched_text.lstrip("/")
        keyword_len = len(matched_keyword)
        # 位置权重: 匹配位置越靠前, 权重越高 (REST 路由优先级)
        position_weight = len(path) - match.start()
        # 位置为主因素 (×1000), 关键字长度为 tiebreaker
        return position_weight * 1000 + keyword_len


@dataclass
class CookieConfig:
    """Cookie 自动注入配置 — 通用适配任意 Agent 应用。"""

    name: str = "session"
    source: str = "env"  # env / file / manual
    env_var: str = "TARGET_COOKIE"
    file_path: str = "data/burp/cookie.txt"
    header_name: str = "Cookie"


@dataclass
class ProfileRegistry:
    """Profile 注册表。"""

    profiles: list[ProfileEntry] = field(default_factory=list)
    default_burp_file: str = "data/burp/request.txt"
    cookie_config: CookieConfig = field(default_factory=CookieConfig)

    def __post_init__(self) -> None:
        """构建 id → ProfileEntry 查找索引 + 编译正则。"""
        self._index: dict[str, ProfileEntry] = {}
        self._default_profile: ProfileEntry | None = None
        for profile in self.profiles:
            self._index[profile.id] = profile
            # 编译 path_pattern 正则
            if profile.path_pattern:
                try:
                    profile._compiled_pattern = re.compile(
                        profile.path_pattern, re.IGNORECASE
                    )
                except re.error as e:
                    logger.warning(
                        "Invalid path_pattern for profile %s: %s — %s",
                        profile.id, profile.path_pattern, e,
                    )
            if profile.is_default:
                self._default_profile = profile
        # 如果没有标记 is_default 的 Profile, 使用第一个
        if self._default_profile is None and self.profiles:
            self._default_profile = self.profiles[0]

    def get_profile(self, profile_id: str) -> ProfileEntry | None:
        """根据 profile id 获取配置。"""
        return self._index.get(profile_id)

    @property
    def default_profile(self) -> ProfileEntry | None:
        """获取默认 Profile。"""
        return self._default_profile

    def get_all_profile_ids(self) -> list[str]:
        """获取所有 profile id 列表。"""
        return list(self._index.keys())

    def match_path(self, path: str) -> ProfileEntry | None:
        """用所有 profile 的 path_pattern 匹配路径, 返回特异性最高的。

        学术依据: Longest Match Principle (Aho et al., Dragon Book §3.9)
        和 Specificity-Ordered Matching (Wirth, Compiler Construction §5.2)

        当多个 profile 的 path_pattern 匹配同一路径时, 选择匹配关键字
        最长 (最具体) 的 profile, 而非简单 first-match。这确保了
        '/api/mcp/tools' 优先匹配 'mcp_tool_hijack' 而非 'agent_tool_misuse',
        因为 'mcp' + 'tools' 的特异性高于 'tool'。

        平局时 (相同特异性分数), 回退到注册表声明顺序 (first-match),
        保持配置文件中的优先级声明意图。

        Args:
            path: 待匹配的 URL 路径。

        Returns:
            匹配的 ProfileEntry, 未匹配返回 None。
        """
        best_profile: ProfileEntry | None = None
        best_score: int = 0
        for profile in self.profiles:
            if profile.matches_path(path):
                score = profile.match_specificity(path)
                # 严格大于: 平局时保持声明顺序 (first-match wins)
                if score > best_score:
                    best_score = score
                    best_profile = profile
                elif best_profile is None:
                    # 第一个匹配的作为初始值
                    best_profile = profile
        return best_profile


class TargetMapper:
    """Profile 注册表加载 + 路径匹配 + 种子映射。

    核心功能:
        1. load_registry() — 从 YAML 加载 Profile 注册表
        2. match_profile_by_path() — 从 Burp 请求路径匹配 Profile
        3. get_seeds_for_profile() — 获取 Profile 对应的最优种子组合
        4. get_burp_file_for_profile() — 获取 Profile 对应的 Burp 请求文件
        5. inject_cookie() — 自动注入 Cookie 到 Burp 请求文件
    """

    def __init__(self, registry_path: Path | str | None = None) -> None:
        """初始化 Target 映射器。

        Args:
            registry_path: 注册表 YAML 路径 (默认: config/target_profiles.yaml)。
        """
        self.registry_path = Path(registry_path) if registry_path else _REGISTRY_PATH
        self._registry: ProfileRegistry | None = None

    @property
    def registry(self) -> ProfileRegistry:
        """懒加载注册表。"""
        if self._registry is None:
            self._registry = self.load_registry()
        return self._registry

    def load_registry(self) -> ProfileRegistry:
        """从 YAML 加载 Profile 注册表。

        Returns:
            ProfileRegistry 实例。
        """
        if not self.registry_path.exists():
            logger.warning("Profile registry not found: %s — using empty registry", self.registry_path)
            return ProfileRegistry()

        with open(self.registry_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        profiles: list[ProfileEntry] = []
        for profile_data in data.get("profiles", []):
            profile = ProfileEntry(
                id=profile_data.get("id", ""),
                name=profile_data.get("name", ""),
                category=profile_data.get("category", ""),
                owasp_id=profile_data.get("owasp_id", ""),
                path_pattern=profile_data.get("path_pattern", ""),
                seeds=profile_data.get("seeds", []),
                strategy=profile_data.get("strategy", "targeted_full"),
                burp_file=profile_data.get("burp_file"),
                description=profile_data.get("description", ""),
                is_default=profile_data.get("is_default", False),
            )
            if profile.id:
                profiles.append(profile)

        # Cookie 配置
        cookie_data = data.get("cookie", {})
        cookie_config = CookieConfig(
            name=cookie_data.get("name", "session"),
            source=cookie_data.get("source", "env"),
            env_var=cookie_data.get("env_var", "TARGET_COOKIE"),
            file_path=cookie_data.get("file_path", "data/burp/cookie.txt"),
            header_name=cookie_data.get("header_name", "Cookie"),
        )

        registry = ProfileRegistry(
            profiles=profiles,
            default_burp_file=data.get("default_burp_file", "data/burp/request.txt"),
            cookie_config=cookie_config,
        )

        logger.info(
            "Profile registry loaded: %d profiles from %s",
            len(profiles), self.registry_path,
        )
        return registry

    def match_profile_by_path(self, path: str) -> ProfileEntry | None:
        """从 Burp 请求路径匹配 Profile。

        使用每个 profile 的 path_pattern 正则进行通用匹配。
        任意 LLM Agent 应用路径均可匹配 (如 /api/chat, /v1/messages, /agent/invoke)。

        Args:
            path: Burp 请求路径。

        Returns:
            匹配的 ProfileEntry, 未匹配返回 None。
        """
        profile = self.registry.match_path(path)
        if profile:
            logger.info(
                "Profile matched: %s (%s) → seeds=%s, strategy=%s",
                profile.id, profile.name, profile.seeds, profile.strategy,
            )
            return profile

        logger.debug("No profile matched for path: %s", path)
        return None

    def get_seeds_for_profile(self, profile_id: str) -> list[str]:
        """获取 Profile 对应的种子列表。

        Args:
            profile_id: Profile ID。

        Returns:
            种子文件名列表 (不含 .prompt 后缀)。
        """
        profile = self.registry.get_profile(profile_id)
        if profile:
            return profile.seeds
        # 默认返回通用种子
        return ["targeted_v2", "elite_jailbreaks", "asi_top10"]

    def get_strategy_for_profile(self, profile_id: str) -> str:
        """获取 Profile 对应的攻击策略。

        Args:
            profile_id: Profile ID。

        Returns:
            策略名称。
        """
        profile = self.registry.get_profile(profile_id)
        if profile:
            return profile.strategy
        return "targeted_full"

    def get_burp_file_for_profile(self, profile_id: str) -> str | None:
        """获取 Profile 对应的 Burp 请求文件。

        Args:
            profile_id: Profile ID。

        Returns:
            Burp 请求文件路径, 无配置返回 None。
        """
        profile = self.registry.get_profile(profile_id)
        if profile and profile.burp_file:
            # 返回完整路径
            return str(_PROJECT_ROOT / "data" / "burp" / "endpoints" / profile.burp_file)
        return None

    def list_all_profiles(self) -> list[ProfileEntry]:
        """列出所有注册的 Profile。"""
        return self.registry.profiles

    def get_profiles_by_category(self, category: str) -> list[ProfileEntry]:
        """按类别筛选 Profile。

        Args:
            category: 类别名称 (如 mcp, rag, prompt_injection)。

        Returns:
            匹配的 Profile 列表。
        """
        return [p for p in self.registry.profiles if category.lower() in p.category.lower()]

    # ───────────────────────────────────────────────────────
    # Cookie 自动注入
    # ───────────────────────────────────────────────────────

    def get_cookie_value(self) -> str | None:
        """获取当前 Cookie 值。

        从配置的 source 读取:
            - env: 从环境变量读取
            - file: 从文件读取
            - manual: 返回 None (需手动替换)

        Returns:
            Cookie 值, 获取失败返回 None。
        """
        cfg = self.registry.cookie_config

        if cfg.source == "env":
            value = os.environ.get(cfg.env_var)
            if value:
                logger.info("Cookie loaded from env var: %s", cfg.env_var)
                return value
            logger.warning("Env var %s not set, cookie not available", cfg.env_var)
            return None

        elif cfg.source == "file":
            cookie_path = _PROJECT_ROOT / cfg.file_path
            if cookie_path.exists():
                value = cookie_path.read_text(encoding="utf-8").strip()
                if value:
                    logger.info("Cookie loaded from file: %s", cfg.file_path)
                    return value
            logger.warning("Cookie file not found or empty: %s", cookie_path)
            return None

        elif cfg.source == "manual":
            logger.info("Cookie source=manual, no auto-injection")
            return None

        logger.warning("Unknown cookie source: %s", cfg.source)
        return None

    def inject_cookie_into_request(
        self,
        raw_request: str,
        cookie_value: str | None = None,
    ) -> str:
        """自动注入 Cookie 到 Burp 请求文本。

        策略:
            1. 如果请求已有 Cookie header → 替换配置的 cookie 名对应值
            2. 如果没有 Cookie header → 在 Host 后插入
            3. 如果 cookie_value 为 None → 不修改

        Args:
            raw_request: 原始 Burp 请求文本。
            cookie_value: Cookie 值 (None 时自动获取)。

        Returns:
            注入 Cookie 后的请求文本。
        """
        if cookie_value is None:
            cookie_value = self.get_cookie_value()

        if not cookie_value:
            #无法获取 Cookie, 不修改
            return raw_request

        cfg = self.registry.cookie_config
        cookie_header_value = f"{cfg.name}={cookie_value}"

        # 检测原始请求的换行符格式 (CRLF 或 LF)
        # HTTP/1.1 规范要求 CRLF, 但部分手工文件或 Unix 工具使用 LF
        # 混用 CRLF 和 LF 会导致部分严格解析的服务器返回 400 Bad Request
        if "\r\n" in raw_request:
            newline = "\r\n"
        else:
            newline = "\n"

        # 检查是否已有 Cookie header
        cookie_pattern = re.compile(
            r"^(Cookie:\s*).*?$",
            re.IGNORECASE | re.MULTILINE,
        )

        if cookie_pattern.search(raw_request):
            # 替换已有 Cookie header
            def _replace_cookie(match: re.Match) -> str:
                existing = match.group(0)
                # 检查是否已有同名 cookie
                cookie_var_pattern = re.compile(
                    rf"{re.escape(cfg.name)}=[^;\s]*",
                    re.IGNORECASE,
                )
                if cookie_var_pattern.search(existing):
                    # 替换已有值
                    return cookie_var_pattern.sub(cookie_header_value, existing)
                else:
                    # 追加到现有 Cookie
                    return f"{existing}; {cookie_header_value}"

            result = cookie_pattern.sub(_replace_cookie, raw_request)
            logger.info("Cookie injected (replaced existing): %s=%s...", cfg.name, cookie_value[:8])
            return result
        else:
            # 在 Host header 后插入 Cookie
            # 使用与原始请求一致的换行符, 避免 CRLF/LF 混用
            host_pattern = re.compile(
                r"^(Host:\s*.*?)(\r\n|\n)",
                re.IGNORECASE | re.MULTILINE,
            )

            if host_pattern.search(raw_request):
                host_match = host_pattern.search(raw_request)
                if host_match:
                    # 在 Host 行后插入 Cookie 行, 保持换行符一致
                    insert_text = f"{host_match.group(0)}{cfg.header_name}: {cookie_header_value}{newline}"
                    result = host_pattern.sub(
                        lambda m: insert_text,
                        raw_request,
                        count=1,
                    )
                    logger.info("Cookie injected (new header): %s=%s...", cfg.name, cookie_value[:8])
                    return result
            else:
                # 没有 Host header, 在第一行后插入
                # 用原始换行符分割
                lines = raw_request.split(newline, 1)
                if len(lines) > 1:
                    return (
                        lines[0]
                        + f"{newline}{cfg.header_name}: {cookie_header_value}"
                        + newline
                        + lines[1]
                    )
                return raw_request

    # ───────────────────────────────────────────────────────
    # 批量 Burp 请求文件发现
    # ───────────────────────────────────────────────────────

    def discover_burp_files(self, burp_dir: Path | str | None = None) -> list[Path]:
        """发现所有 Burp 请求文件。

        扫描 data/burp/ 和 data/burp/endpoints/ 目录,
        发现所有 .txt 文件, 按 profile id 排序。

        Args:
            burp_dir: 自定义扫描目录 (默认: data/burp/ + data/burp/endpoints/)。

        Returns:
            发现的 Burp 请求文件列表。
        """
        if burp_dir:
            search_dirs = [Path(burp_dir)]
        else:
            search_dirs = [
                _PROJECT_ROOT / "data" / "burp",
                _PROJECT_ROOT / "data" / "burp" / "endpoints",
            ]

        files: list[Path] = []
        for d in search_dirs:
            if d.exists():
                files.extend(sorted(d.glob("*.txt")))

        # 排除 cookie.txt
        files = [f for f in files if f.name != "cookie.txt"]

        logger.info("Discovered %d Burp request files", len(files))
        return files

    def build_attack_plan(
        self,
        burp_dir: Path | str | None = None,
    ) -> list[dict[str, Any]]:
        """构建批量攻击计划。

        扫描 Burp 请求文件, 匹配 Profile, 生成攻击计划。

        每个计划条目:
            - burp_file: Burp 请求文件路径
            - profile_id: Profile ID
            - profile_name: Profile 名称
            - seeds: 种子列表
            - strategy: 攻击策略

        Args:
            burp_dir: 自定义 Burp 文件目录。

        Returns:
            攻击计划列表。
        """
        files = self.discover_burp_files(burp_dir)
        plan: list[dict[str, Any]] = []

        for f in files:
            # 解析文件内容获取路径
            try:
                raw = f.read_text(encoding="utf-8", errors="replace")
                # 提取第一行的 path
                first_line = raw.split("\n")[0]
                parts = first_line.split(" ")
                if len(parts) < 2:
                    continue
                path = parts[1]

                profile = self.match_profile_by_path(path)
                if profile:
                    plan.append({
                        "burp_file": str(f),
                        "profile_id": profile.id,
                        "profile_name": profile.name,
                        "seeds": ",".join(profile.seeds),
                        "strategy": profile.strategy,
                        "owasp_id": profile.owasp_id,
                        "description": profile.description,
                    })
                else:
                    # 未匹配的文件, 使用默认种子
                    plan.append({
                        "burp_file": str(f),
                        "profile_id": f.stem,
                        "profile_name": "Unknown Profile",
                        "seeds": "targeted_v2,elite_jailbreaks",
                        "strategy": "targeted_full",
                        "owasp_id": "",
                        "description": "",
                    })
            except Exception as e:
                logger.warning("Failed to parse burp file %s: %s", f, e)

        logger.info("Attack plan: %d entries", len(plan))
        return plan
