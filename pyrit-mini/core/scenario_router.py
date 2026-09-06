"""core/scenario_router.py — 攻击面→技术标签适配器 (v61 合并 synergy_orchestrator)。

v61 重构:
  - 合并原 data/synergy_orchestrator.py 的 SynergyOrchestrator + SynergyConfig
  - data/ 层只保留声明式资产, 无 Python 代码
  - "场景选择" 转化为 "技术过滤": 攻击面类型 → technique_tags → TextAdaptive
  - 保持对外 API 兼容 (select_scenario 返回 (name, config) 元组)

决策流:
    攻击面分类 (ClassificationResult)
           ↓
    config/defaults.yaml → scenario_technique_filters 映射
           ↓
    (scenario_name, {technique_tags, description, ...})

数据流:
    classification → router.select_scenario()
                   → (name, {technique_tags, description, ...})
                   → main.py: synergy_config.technique_tags = config["technique_tags"]

向后兼容:
    SynergyOrchestrator 和 SynergyConfig 保留, 用于 main.py 集成

学术依据:
    - NIST SP 800-115: 威胁建模驱动测试策略
    - PyRIT (arXiv:2407.01232): TextAdaptive + technique_tags 过滤
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "defaults.yaml"


class ScenarioRouter:
    """攻击面→技术标签适配器 (v60)。

    职责:
        - 从 config/defaults.yaml 加载 scenario_technique_filters 映射
        - 基于 ClassificationResult 自动匹配技术过滤标签
        - 支持用户强制覆盖 (--scenario)

    与 v59 的区别:
        - 不再加载 scenarios.yaml
        - 不再管理 seeds/converters/scorer 配置
        - 仅负责攻击面→technique_tags 映射
    """

    def __init__(self, config_path: Path | None = None):
        """
        初始化适配器

        Args:
            config_path: defaults.yaml 路径 (默认: config/defaults.yaml)
        """
        self._config_path = config_path or CONFIG_PATH
        self._scenario_filters: dict[str, Any] = {}
        self._default_scenario = "model_scenario"
        self._load_config()

    def _load_config(self) -> None:
        """从 defaults.yaml 加载 scenario_technique_filters 映射.

        防御性设计: 配置缺失时使用硬编码默认值.
        """
        # v60: 硬编码默认映射 (防御性)
        default_filters: dict[str, Any] = {
            "mcp_scenario": {
                "description": "MCP Server 定向攻击链 (Tag: mcp_targeted)",
                "triggers": {"attack_surface": "mcp_server", "min_confidence": 0.6},
                "technique_tags": ["mcp_targeted"],
            },
            "agent_scenario": {
                "description": "多智能体系统定向攻击链 (Tag: agent_targeted)",
                "triggers": {"attack_surface": "multi_agent_system", "min_confidence": 0.6},
                "technique_tags": ["agent_targeted"],
            },
            "rag_scenario": {
                "description": "RAG 知识库定向攻击链 (Tag: rag_targeted)",
                "triggers": {"attack_surface": "rag_system", "min_confidence": 0.6},
                "technique_tags": ["rag_targeted"],
            },
            "model_scenario": {
                "description": "标准 LLM 渐进式攻击链 (默认, 全量技术)",
                "triggers": {"attack_surface": "standard_llm_api", "min_confidence": 0.0},
                "technique_tags": None,  # None = 使用全部技术
            },
        }

        try:
            import yaml

            if self._config_path.exists():
                with open(self._config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                if isinstance(config, dict):
                    scenario_filters = config.get("scenario_technique_filters", {})
                    # 将 scenario_technique_filters 转换为 scenario 格式
                    surface_to_name = {
                        "mcp_server": "mcp_scenario",
                        "multi_agent_system": "agent_scenario",
                        "rag_system": "rag_scenario",
                        "standard_llm_api": "model_scenario",
                    }
                    for surface_name, surface_cfg in scenario_filters.items():
                        scenario_name = surface_to_name.get(surface_name, f"{surface_name}_scenario")
                        if isinstance(surface_cfg, dict):
                            default_filters[scenario_name] = {
                                "description": surface_cfg.get(
                                    "description",
                                    f"{surface_name} 定向攻击链"
                                ),
                                "triggers": {
                                    "attack_surface": surface_name,
                                    "min_confidence": 0.6,
                                },
                                "technique_tags": surface_cfg.get("technique_tags"),
                            }
                    logger.debug(
                        "Loaded scenario_technique_filters from defaults.yaml: %d scenarios",
                        len(scenario_filters),
                    )
        except Exception as e:
            logger.warning("Failed to load scenario config: %s, using defaults", e)

        self._scenario_filters = default_filters

    def select_scenario(
        self,
        classification: Any,
        user_override: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """选择最优 Scenario (攻击面→技术标签映射)

        Args:
            classification: 攻击面分类结果 (需有 attack_surface, confidence 属性)
            user_override: 用户强制指定的 Scenario 名 (--scenario)

        Returns:
            (scenario_name, scenario_config) 元组
        """
        # 1. 用户强制覆盖优先级最高
        if user_override:
            if self._validate_scenario(user_override):
                logger.info("Scenario forced by user: %s", user_override)
                return user_override, self._get_scenario_config(user_override)
            else:
                logger.warning("Invalid scenario '%s', falling back to auto", user_override)

        # 2. 自动匹配: 遍历所有 Scenario 的 triggers
        for name, config in self._scenario_filters.items():
            if self._matches_trigger(classification, config):
                logger.info(
                    "Auto-selected scenario: %s (attack_surface=%s, confidence=%.2f, technique_tags=%s)",
                    name, classification.attack_surface, classification.confidence,
                    config.get("technique_tags"),
                )
                return name, config

        # 3. Fallback: 默认 Scenario
        default_name = self._default_scenario
        logger.info("No scenario matched, using default: %s", default_name)
        return default_name, self._get_scenario_config(default_name)

    def _matches_trigger(
        self,
        classification: Any,
        scenario_config: dict[str, Any],
    ) -> bool:
        """检查 Scenario 的 triggers 是否匹配分类结果.

        Args:
            classification: 攻击面分类结果
            scenario_config: Scenario 配置

        Returns:
            是否匹配
        """
        triggers = scenario_config.get("triggers", {})

        # 攻击面类型必须匹配
        if triggers.get("attack_surface") != classification.attack_surface:
            return False

        # 置信度必须达到最小阈值
        min_conf = triggers.get("min_confidence", 0.0)
        if classification.confidence < min_conf:
            return False

        return True

    def list_scenarios(self) -> list[dict[str, Any]]:
        """列出所有可用 Scenario

        Returns:
            Scenario 信息列表
        """
        result = []
        for name, config in self._scenario_filters.items():
            result.append({
                "name": name,
                "description": config.get("description", ""),
                "triggers": config.get("triggers", {}),
                "technique_tags": config.get("technique_tags"),
            })
        return result

    def _validate_scenario(self, name: str) -> bool:
        """验证 Scenario 名称是否有效

        Args:
            name: Scenario 名称

        Returns:
            是否有效
        """
        return name in self._scenario_filters

    def _get_scenario_config(self, name: str) -> dict[str, Any]:
        """获取指定 Scenario 的配置

        Args:
            name: Scenario 名称

        Returns:
            Scenario 配置字典，不存在则返回默认 model_scenario
        """
        return self._scenario_filters.get(name, self._scenario_filters.get(self._default_scenario, {}))

    def format_scenarios_display(self) -> str:
        """格式化所有 Scenario 为可读字符串 (供 --list-scenarios 使用)

        Returns:
            格式化的 Scenario 列表字符串
        """
        scenarios = self.list_scenarios()
        if not scenarios:
            return "No scenarios configured."

        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                    Available Scenarios (v60 Tag-Based)                       ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
        ]

        for i, sc in enumerate(scenarios, 1):
            triggers = sc.get("triggers", {})
            surface = triggers.get("attack_surface", "any")
            min_conf = triggers.get("min_confidence", 0.0)
            tags = sc.get("technique_tags")
            tags_str = ", ".join(tags) if tags else "all (no filter)"

            lines.extend([
                "║                                                                              ║",
                f"║  {i}. {sc['name']:<68}║",
                f"║     Description: {sc['description'][:50]:<52}║",
                f"║     Triggers: surface={surface}, min_conf={min_conf:<36}║",
                f"║     Technique Tags: {tags_str[:48]:<50}║",
            ])

        lines.extend([
            "║                                                                              ║",
            "╚══════════════════════════════════════════════════════════════════════════════╝",
        ])

        return "\n".join(lines)


def apply_scenario_overrides(ctx: Any, scenario_config: dict[str, Any], args: Any) -> None:
    """应用 Scenario 配置覆盖到 ctx.args (v60 简化版).

    v60 变更:
        - 不再覆盖 seeds/scorer/converters 配置
        - 仅覆盖 adaptive_technique_filter (技术过滤标签)

    核心原则:
        - 仅覆盖用户未在 CLI 显式指定的参数
        - 优先级: CLI --technique-filter > Scenario > defaults.yaml > 硬编码

    Args:
        ctx: 全局上下文对象 (PipelineContext)
        scenario_config: 选中的 Scenario 配置 (含 technique_tags)
        args: CLI 参数命名空间
    """
    # v60: 仅覆盖 technique_filter (技术过滤)
    if not hasattr(args, "adaptive_technique_filter") or args.adaptive_technique_filter is None:
        technique_tags = scenario_config.get("technique_tags")
        if technique_tags is not None:
            # 将 scenario's technique_tags 设置为 adaptive_technique_filter
            ctx.args.adaptive_technique_filter = technique_tags
            logger.info(
                "Applied scenario technique filter: %s", technique_tags
            )
        # 如果 technique_tags 为 None, 则不设置 (使用全部技术)

    logger.info(
        "Applied scenario overrides (v60): technique_filter=%s",
        getattr(ctx.args, "adaptive_technique_filter", "not set (use all)"),
    )


# ──────────────────────────────────────────────────────────────────────────────
# 全局单例
# ──────────────────────────────────────────────────────────────────────────────
_default_router: ScenarioRouter | None = None


def get_router() -> ScenarioRouter:
    """获取全局 Scenario 路由器单例

    Returns:
        全局 ScenarioRouter 实例
    """
    global _default_router
    if _default_router is None:
        _default_router = ScenarioRouter()
    return _default_router


def reset_router() -> None:
    """重置全局路由器单例 (供测试使用)"""
    global _default_router
    _default_router = None


# ──────────────────────────────────────────────────────────────────────────────
# Synergy 攻击面分类器 (v61 从 data/synergy_orchestrator.py 合并)
# ──────────────────────────────────────────────────────────────────────────────
from dataclasses import dataclass, field


@dataclass
class SynergyConfig:
    """协同配置 (v60 精简版).

    语义: 攻击面分析结果 + 过滤标签.
    v61: 从 data/synergy_orchestrator.py 迁至 core/scenario_router.py.
    """

    # 来源信息
    burp_profile: str
    attack_surface: str
    confidence: float

    # v60: 场景技术过滤标签 (由 config/defaults.yaml → scenario_technique_filters 映射)
    technique_tags: list[str] | None = None  # None = 使用全部技术

    # 元数据
    evidence: list[str] = field(default_factory=list)
    synergy_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """转换为字典."""
        return {
            "burp_profile": self.burp_profile,
            "attack_surface": self.attack_surface,
            "confidence": self.confidence,
            "technique_tags": self.technique_tags,
            "evidence": self.evidence,
            "synergy_enabled": self.synergy_enabled,
        }

    def summary(self) -> str:
        """生成摘要字符串."""
        return (
            f"SynergyConfig(\n"
            f"  burp_profile={self.burp_profile},\n"
            f"  attack_surface={self.attack_surface},\n"
            f"  confidence={self.confidence:.2f},\n"
            f"  technique_tags={self.technique_tags},\n"
            f"  synergy_enabled={self.synergy_enabled}\n"
            f")"
        )


def _split_burp_content(burp_content: str) -> tuple[str, str]:
    """从 Burp 文件内容分离 HTTP 请求和响应.

    Burp 保存的文件格式:
        HTTP 请求 (headers + body)
        (空行)
        HTTP/1.1 200 OK
        ... (响应 headers + body)

    Args:
        burp_content: Burp 文件完整内容

    Returns:
        (http_request, http_response) 元组
    """
    lines = burp_content.split("\n")
    response_start = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("HTTP/1."):
            response_start = i
            break

    if response_start == -1:
        return burp_content, ""

    http_request = "\n".join(lines[:response_start]).strip()
    http_response = "\n".join(lines[response_start:]).strip()
    return http_request, http_response


class SynergyOrchestrator:
    """攻击面→技术标签适配器 (v61 合并至 core/).

    职责:
      1. 攻击面分类 (文件名 + HTTP 内容)
      2. 攻击面 → technique_tags 映射 (读取 config/defaults.yaml)

    v61: 从 data/synergy_orchestrator.py 迁至 core/scenario_router.py.
    """

    def __init__(
        self,
        data_root: Path | None = None,
        burp_dir: Path | None = None,
    ):
        """
        初始化适配器.

        Args:
            data_root: 数据根目录 (默认: project/data)
            burp_dir: Burp 文件目录 (默认: config/targets/burp)
        """
        self._data_root = data_root or PROJECT_ROOT / "data"
        # v61: burp 文件迁移到 config/targets/burp
        self._burp_dir = burp_dir or (PROJECT_ROOT / "config" / "targets" / "burp")

        # 延迟加载子组件
        self._mapper = None
        self._tag_mapping: dict[str, list[str] | None] | None = None

    @property
    def mapper(self):
        """延迟加载 AssetMapper."""
        if self._mapper is None:
            from core.asset_mapper import AssetMapper
            self._mapper = AssetMapper()
        return self._mapper

    def _load_tag_mapping(self) -> dict[str, list[str] | None]:
        """从 config/defaults.yaml 加载攻击面→technique_tags 映射.

        v60: 统一配置入口, 消除 scenarios.yaml 重复定义.

        Returns:
            攻击面类型 → technique_tags 映射字典
        """
        if self._tag_mapping is not None:
            return self._tag_mapping

        default_mapping: dict[str, list[str] | None] = {
            "mcp_server": ["mcp_targeted"],
            "multi_agent_system": ["agent_targeted"],
            "rag_system": ["rag_targeted"],
            "standard_llm_api": None,  # None = 使用全部技术
        }

        try:
            import yaml

            config_path = PROJECT_ROOT / "config" / "defaults.yaml"
            if config_path.exists():
                with open(config_path, encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                scenario_filters = config.get("scenario_technique_filters", {})
                if scenario_filters:
                    for surface, cfg in scenario_filters.items():
                        if isinstance(cfg, dict) and "technique_tags" in cfg:
                            default_mapping[surface] = cfg["technique_tags"]
                    logger.debug(
                        "Loaded scenario_technique_filters from defaults.yaml: %d surfaces",
                        len(scenario_filters),
                    )
        except Exception as e:
            logger.warning("Failed to load scenario_technique_filters: %s, using defaults", e)

        self._tag_mapping = default_mapping
        return default_mapping

    def build_synergy_config(
        self,
        burp_profile_name: str,
        burp_content: str | None = None,
        force_surface: str | None = None,
    ) -> SynergyConfig:
        """构建精简协同配置 (攻击面 + 技术标签).

        主入口: 基于 Burp 配置文件生成攻击面分析 + 技术过滤标签.

        Args:
            burp_profile_name: Burp 配置文件名 (如 "mcp05")
            burp_content: Burp 文件原始内容 (可选)
            force_surface: 强制指定攻击面类型 (覆盖自动检测)

        Returns:
            SynergyConfig: 包含 attack_surface + technique_tags
        """
        logger.info("Building synergy config for burp profile: %s", burp_profile_name)

        # ── Step 1: 分类攻击面 ──
        if force_surface:
            attack_surface = force_surface
            confidence = 1.0
            evidence = [f"Forced surface type: {force_surface}"]
        elif burp_content:
            # 基于内容的深度分类
            from recon.attack_surface_classifier import classify_http_content

            url = self._extract_url(burp_content)
            http_request, http_response = _split_burp_content(burp_content)
            result = classify_http_content(
                http_request=http_request,
                http_response=http_response,
                url=url,
            )
            attack_surface = result.attack_surface
            confidence = result.confidence
            evidence = result.evidence
        else:
            # 基于文件名的快速分类
            attack_surface = self.mapper.classify_attack_surface(burp_profile_name)
            confidence = 0.6
            evidence = ["File-name based classification"]

        # ── Step 2: 攻击面 → technique_tags 映射 ──
        tag_mapping = self._load_tag_mapping()
        technique_tags = tag_mapping.get(attack_surface)

        logger.info(
            "Synergy config ready: surface=%s, technique_tags=%s, confidence=%.2f",
            attack_surface, technique_tags, confidence,
        )

        return SynergyConfig(
            burp_profile=burp_profile_name,
            attack_surface=attack_surface,
            confidence=confidence,
            technique_tags=technique_tags,
            evidence=evidence,
            synergy_enabled=True,
        )

    def build_from_burp_file(self, burp_filename: str) -> SynergyConfig:
        """从 Burp 文件构建协同配置.

        便捷方法: 自动读取 Burp 文件内容.

        Args:
            burp_filename: Burp 文件名 (如 "mcp05.txt")

        Returns:
            SynergyConfig
        """
        profile_name = burp_filename.replace(".txt", "")

        burp_content = None
        burp_file = self._burp_dir / burp_filename
        if burp_file.exists():
            try:
                burp_content = burp_file.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                logger.warning("Failed to read burp file %s: %s", burp_file, e)
        else:
            logger.debug("Burp file not found: %s", burp_file)

        return self.build_synergy_config(profile_name, burp_content)

    @staticmethod
    def _extract_url(http_content: str) -> str | None:
        """从 HTTP 内容提取 URL."""
        first_line = http_content.split("\n", 1)[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            return parts[1]
        return None


# ──────────────────────────────────────────────
# 全局便捷函数 (Synergy 兼容层)
# ──────────────────────────────────────────────
_default_orchestrator: SynergyOrchestrator | None = None


def get_orchestrator() -> SynergyOrchestrator:
    """获取全局默认适配器."""
    global _default_orchestrator
    if _default_orchestrator is None:
        _default_orchestrator = SynergyOrchestrator()
    return _default_orchestrator


def quick_build(burp_profile_name: str) -> SynergyConfig:
    """快速构建协同配置.

    Args:
        burp_profile_name: Burp 配置文件名

    Returns:
        SynergyConfig
    """
    return get_orchestrator().build_synergy_config(burp_profile_name)


def build_from_burp_file(burp_filename: str) -> SynergyConfig:
    """从 Burp 文件构建协同配置.

    Args:
        burp_filename: Burp 文件名

    Returns:
        SynergyConfig
    """
    return get_orchestrator().build_from_burp_file(burp_filename)


def get_cli_overrides(burp_profile_name: str) -> dict[str, Any]:
    """获取 CLI 参数覆盖 (用于 main.py 集成).

    v60: 仅返回 attack_surface + technique_tags, 不再包含 seeds/scorer.

    Args:
        burp_profile_name: Burp 配置文件名

    Returns:
        参数覆盖字典
    """
    config = quick_build(burp_profile_name)

    return {
        "attack_surface": config.attack_surface,
        "technique_filter": config.technique_tags,
        "synergy_enabled": config.synergy_enabled,
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI 入口: --list-scenarios
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    """CLI 入口: 列出所有可用 Scenario"""
    router = get_router()
    print(router.format_scenarios_display())


if __name__ == "__main__":
    # 支持作为脚本运行: python -m core.scenario_router
    logging.basicConfig(level=logging.INFO)
    main()
