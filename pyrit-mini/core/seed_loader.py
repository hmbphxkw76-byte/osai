"""core/seed_loader.py — 统一种子加载器

根据 --seeds 和 --target 参数智能加载种子文件。
与 strike/ 和 recon/ 目录结构对齐。

组件目录映射:
    a2a       → data/seeds/a2a/       (Agent-to-Agent 攻击)
    mcp       → data/seeds/mcp/       (Model Context Protocol 攻击)
    rag       → data/seeds/rag/       (RAG 攻击)
    model     → data/seeds/model/     (模型直接攻击)
    web       → data/seeds/web/       (Web 攻击)
    memory    → data/seeds/memory/    (记忆攻击)
    session   → data/seeds/session/   (会话攻击)

Usage:
    from core.seed_loader import SeedLoader

    loader = SeedLoader()
    seeds = loader.load()                          # 加载所有匹配的种子
    seeds = loader.load(component="mcp")           # 只加载 MCP 相关种子
    seeds = loader.load(seed_names=["elite_jailbreaks"])  # 按文件名加载

Academic basis:
    - NIST SP 800-115 Sec4: Attack surface enumeration
    - OWASP LLM Top 10 (2025): Attack vector classification
    - PyRIT (arXiv:2407.01232): Native seed loading
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "seeds"

# 组件 → 种子目录映射 (与 strike/ recon/ 对齐)
COMPONENT_SEED_DIRS: dict[str, list[str]] = {
    "a2a": ["a2a"],
    "mcp": ["mcp"],
    "rag": ["rag"],
    "session": ["session"],
    "memory": ["memory"],
    "web": ["web"],
    "model": ["model"],  # model 单独目录
}

# 兼容旧名称映射 (向后兼容)
LEGACY_NAME_MAP: dict[str, list[str]] = {
    "elite_jailbreaks": ["_core/T1_LLM01_elite_jailbreaks"],
    "asi_top10": ["_core/T1_ASI01-10_agent_security_comprehensive"],
    "owasp_full_coverage": [
        "_core/T1_LLM01_advanced_injection",
        "_core/T1_LLM01_indirect_injection",
        "_core/T1_LLM01_web_injection",
    ],
    "a2a_multi_agent": ["a2a"],
    "a2a_trust_chain": ["a2a"],
    "agent_card_spoofing": ["a2a/a2a_agent_card_spoofing"],
    "a2a_agent_card_spoofing": ["a2a/a2a_agent_card_spoofing"],
    "mcp_protocol": ["mcp"],
    "tool_injection": ["mcp"],
    "mcpsec": ["mcp"],
    "rag_poisoning": ["rag"],
    "knowledge_base": ["rag"],
    "vector_injection": ["rag"],
    "session_enumeration": ["session"],
    "idor": ["session"],
    "auth_bypass": ["session"],
    "memory_injection": ["memory"],
    "context_poisoning": ["memory"],
    "forensics": ["memory"],
    "web_injection": ["web"],
    "css_hidden": ["web"],
    "xss_vector": ["web"],
    "jailbreak": ["model"],
    "prompt_leak": ["model"],
    "instruction_override": ["model"],
}


class SeedLoader:
    """统一种子加载器

    支持三种加载模式:
    1. 组件模式: --target mcp → 加载 seeds/mcp/ 下所有种子
    2. 名称模式: --seeds elite_jailbreaks → 加载特定文件
    3. 混合模式: --seeds mcp,tool_hijack → 加载 MCP 目录 + 特定文件

    Attributes:
        seeds_dir: 种子文件根目录
        ctx: PipelineContext (可选)
    """

    def __init__(self, ctx: Any = None, seeds_dir: Path | None = None):
        self.ctx = ctx
        self._seeds_dir = seeds_dir or _SEEDS_DIR

    def load(
        self,
        component: str | None = None,
        seed_names: list[str] | None = None,
        include_core: bool = True,
    ) -> list[Path]:
        """加载种子文件

        Args:
            component: 组件类型 (a2a/mcp/rag/model/web/memory/session)
            seed_names: 特定种子文件名列表
            include_core: 是否包含核心种子

        Returns:
            Path 列表，指向加载的种子文件
        """
        loaded_files: set[Path] = set()
        result: list[Path] = []

        # 1. 按组件加载
        if component:
            component_dirs = COMPONENT_SEED_DIRS.get(component, [component])
            for dir_name in component_dirs:
                dir_path = self._seeds_dir / dir_name
                if dir_path.is_dir():
                    for f in sorted(dir_path.glob("*.prompt")):
                        if f not in loaded_files:
                            loaded_files.add(f)
                            result.append(f)

        # 2. 按名称加载
        if seed_names:
            for name in seed_names:
                # 检查是否是组件名
                if name in COMPONENT_SEED_DIRS:
                    component_dirs = COMPONENT_SEED_DIRS[name]
                    for dir_name in component_dirs:
                        dir_path = self._seeds_dir / dir_name
                        if dir_path.is_dir():
                            for f in sorted(dir_path.glob("*.prompt")):
                                if f not in loaded_files:
                                    loaded_files.add(f)
                                    result.append(f)
                # 检查是否是旧名称
                elif name in LEGACY_NAME_MAP:
                    for legacy_path in LEGACY_NAME_MAP[name]:
                        file_path = self._seeds_dir / f"{legacy_path}.prompt"
                        if file_path.exists() and file_path not in loaded_files:
                            loaded_files.add(file_path)
                            result.append(file_path)
                else:
                    # 尝试作为直接文件名
                    # 先检查根目录
                    file_path = self._seeds_dir / f"{name}.prompt"
                    if file_path.exists() and file_path not in loaded_files:
                        loaded_files.add(file_path)
                        result.append(file_path)
                        continue
                    # 检查特殊目录
                    for special_dir in ["_core", "_encoding_evasion", "_experimental", "_multilingual"]:
                        file_path = self._seeds_dir / special_dir / f"{name}.prompt"
                        if file_path.exists() and file_path not in loaded_files:
                            loaded_files.add(file_path)
                            result.append(file_path)
                            break
                    # 检查组件目录
                    for comp_dir in COMPONENT_SEED_DIRS.values():
                        for dir_name in comp_dir:
                            file_path = self._seeds_dir / dir_name / f"{name}.prompt"
                            if file_path.exists() and file_path not in loaded_files:
                                loaded_files.add(file_path)
                                result.append(file_path)
                                break

        # 3. 默认加载核心种子
        if include_core and not component and not seed_names:
            core_dir = self._seeds_dir / "_core"
            if core_dir.is_dir():
                for f in sorted(core_dir.glob("*.prompt")):
                    if f not in loaded_files:
                        loaded_files.add(f)
                        result.append(f)

        logger.info(
            "Loaded %d seed files (component=%s, names=%s)",
            len(result),
            component,
            seed_names,
        )
        return result

    def list_available(self) -> dict[str, list[str]]:
        """列出所有可用的种子文件和目录

        Returns:
            字典，键为目录名，值为文件列表
        """
        result: dict[str, list[str]] = {}

        # 组件目录
        for component, dirs in COMPONENT_SEED_DIRS.items():
            files: list[str] = []
            for dir_name in dirs:
                dir_path = self._seeds_dir / dir_name
                if dir_path.is_dir():
                    files.extend(f.name for f in sorted(dir_path.glob("*.prompt")))
            if files:
                result[component] = files

        # 特殊目录
        for special in ["_core", "_encoding_evasion", "_experimental", "_multilingual"]:
            dir_path = self._seeds_dir / special
            if dir_path.is_dir():
                files = [f.name for f in sorted(dir_path.glob("*.prompt"))]
                if files:
                    result[special] = files

        return result

    def validate_seed_files(self) -> dict[str, Any]:
        """验证所有种子文件的 metadata 格式

        Returns:
            验证报告字典
        """
        report: dict[str, Any] = {
            "total_files": 0,
            "valid_files": 0,
            "warnings": [],
            "errors": [],
        }

        # 检查所有组件目录的所有文件
        all_dirs = list(COMPONENT_SEED_DIRS.values())
        all_dirs.append(["_core"])
        all_dirs.append(["_encoding_evasion"])
        all_dirs.append(["_experimental"])
        all_dirs.append(["_multilingual"])

        for dir_list in all_dirs:
            for dir_name in dir_list:
                dir_path = self._seeds_dir / dir_name
                if not dir_path.is_dir():
                    continue
                for f in sorted(dir_path.glob("*.prompt")):
                    report["total_files"] += 1
                    try:
                        import yaml

                        content = f.read_text(encoding="utf-8")
                        data = yaml.safe_load(content)
                        if isinstance(data, list):
                            report["valid_files"] += 1
                    except Exception as e:
                        report["errors"].append(f"{dir_name}/{f.name}: {e}")

        return report


# ============================================================================
# 便捷函数
# ============================================================================


def load_seeds_by_target(target: str | None, seeds_arg: str | None) -> list[Path]:
    """根据 target 和 seeds 参数加载种子

    Args:
        target: --target 参数值
        seeds_arg: --seeds 参数值

    Returns:
        Path 列表
    """
    loader = SeedLoader()

    if seeds_arg:
        seed_names = [s.strip() for s in seeds_arg.split(",") if s.strip()]
    else:
        seed_names = None

    return loader.load(component=target, seed_names=seed_names)


def list_all_seeds() -> dict[str, list[str]]:
    """列出所有可用的种子

    Returns:
        目录到文件列表的映射
    """
    loader = SeedLoader()
    return loader.list_available()


# 测试示例移入 tests/test_seed_loader.py
