"""synergy_orchestrator.py — 攻击面→技术标签适配器 (v60 轻量化)。

迁移说明:
    v61 计划合并入 core/scenario_router.py, 临时保留此文件以兼容现有 import.
    新代码请直接使用 core.scenario_router.

v60 重构: 从"完整攻击配置生成器"简化为"攻击面→technique_tags适配器"。

职责:
  - 输入: Burp Profile Name → 输出: 攻击面类型 + 匹配的技术过滤标签
  - 种子选择/评分器选择逻辑移除 (已通过 SSOT config/defaults.yaml 管理)

数据流:
  burp_profile → classify_attack_surface → synergy_config
                                          → attack_surface (攻击面类型)
                                          → technique_tags (用于 TextAdaptive 过滤)
                                          → confidence (分类置信度)

学术依据:
  - NIST SP 800-115 §4: 基于发现的攻击面动态调整测试策略
  - MITRE ATLAS: TTP 与资产能力映射
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "data"
BURP_ROOT = DATA_ROOT / "burp"


@dataclass
class SynergyConfig:
    """协同配置 (v60 精简版)。

    语义: 攻击面分析结果 + 过滤标签。
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


class SynergyOrchestrator:
    """攻击面→技术标签适配器 (v60 简化)。

    职责:
      1. 攻击面分类 (文件名 + HTTP 内容)
      2. 攻击面 → technique_tags 映射 (读取 config/defaults.yaml)
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
            burp_dir: Burp 文件目录 (默认: data/burp)
        """
        self._data_root = data_root or DATA_ROOT
        self._burp_dir = burp_dir or BURP_ROOT

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


# ──────────────────────────────────────────────
# 全局便捷函数
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


# ──────────────────────────────────────────────
# CLI 集成辅助
# ──────────────────────────────────────────────
def get_cli_overrides(burp_profile_name: str) -> dict[str, Any]:
    """获取 CLI 参数覆盖 (用于 main.py 集成).

    v60: 仅返回 attack_surface + technique_tags, 不再包含 seeds/scorer.

    Args:
        burp_profile_name: Burp 配置文件名

    Returns:
        参数覆盖字典:
        {
            "attack_surface": "surface_type",
            "technique_filter": ["tag1", "tag2"],
        }
    """
    config = quick_build(burp_profile_name)

    return {
        "attack_surface": config.attack_surface,
        "technique_filter": config.technique_tags,
        "synergy_enabled": config.synergy_enabled,
    }
