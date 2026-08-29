"""目标 Profile 注册表 + 路径→种子精准映射 — 通用 Agent 应用场景自动化。
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
    """

    def __init__(self, registry_path: Path | str | None = None) -> None:
        """初始化 Target 映射器。
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
        """
        profile = self.registry.get_profile(profile_id)
        if profile:
            return profile.seeds
        # 默认返回通用种子
        return ["targeted_v2", "elite_jailbreaks", "asi_top10"]

    def get_strategy_for_profile(self, profile_id: str) -> str:
        """获取 Profile 对应的攻击策略。
        """
        profile = self.registry.get_profile(profile_id)
        if profile:
            return profile.strategy
        return "targeted_full"

    def get_burp_file_for_profile(self, profile_id: str) -> str | None:
        """获取 Profile 对应的 Burp 请求文件。
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
        """
        return [p for p in self.registry.profiles if category.lower() in p.category.lower()]

    # Cookie 自动注入

    def get_cookie_value(self) -> str | None:
        """获取当前 Cookie 值。
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

    # 批量 Burp 请求文件发现

    def discover_burp_files(self, burp_dir: Path | str | None = None) -> list[Path]:
        """发现所有 Burp 请求文件。
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
