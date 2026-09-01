"""synergy_orchestrator.py — Burp + Scores + Seeds 协同编排器.

统一协调 AssetMapper + AttackSurfaceClassifier + ScorerSelector.
提供一站式协同入口.

理论依据:
  - NIST SP 800-115 §4: 渗透测试执行流程 (Planning → Discovery → Attack → Reporting)
  - PTES (Penetration Testing Execution Standard): 预交互 → 情报收集 → 威胁建模 → 漏洞分析 → 利用

工作流:
  ┌──────────────────────────────────────────────────────────────────┐
  │                    Synergy Orchestrator v2                        │
  ├──────────────────────────────────────────────────────────────────┤
  │  Input: Burp Profile Name (e.g., "mcp05")                        │
  │                          ↓                                        │
  │  ① Classify Attack Surface (文件名 + HTTP 内容)                   │
  │                          ↓                                        │
  │  ② Select Seeds (基于攻击面类型匹配种子库)                        │
  │                          ↓                                        │
  │  ③ Select Scorer (基于攻击面类型匹配评分器)                       │
  │                          ↓                                        │
  │  ④ Build Complete Config (完整攻击配置)                           │
  │                          ↓                                        │
  │  Output: 完整配置字典 (可直接传递给 attack executor)              │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 项目根目录 (相对路径计算的基准)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "data"
SEEDS_ROOT = DATA_ROOT / "seeds"
SCORERS_ROOT = DATA_ROOT / "scorers"
BURP_ROOT = DATA_ROOT / "burp"


@dataclass
class SynergyConfig:
    """协同配置 — 完整的攻击配置."""

    # 来源信息
    burp_profile: str
    attack_surface: str
    confidence: float

    # 种子配置
    seed_names: list[str] = field(default_factory=list)
    seed_files: list[str] = field(default_factory=list)  # 实际文件路径

    # 评分器配置
    scorer_name: str = "blackbox_task_achieved"
    scorer_file: str = ""

    # 元数据
    evidence: list[str] = field(default_factory=list)
    synergy_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """转换为字典."""
        return {
            "burp_profile": self.burp_profile,
            "attack_surface": self.attack_surface,
            "confidence": self.confidence,
            "seed_names": self.seed_names,
            "seed_files": self.seed_files,
            "scorer_name": self.scorer_name,
            "scorer_file": self.scorer_file,
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
            f"  seeds={len(self.seed_names)},\n"
            f"  scorer={self.scorer_name},\n"
            f"  synergy_enabled={self.synergy_enabled}\n"
            f")"
        )


class SynergyOrchestrator:
    """协同编排器 — 协调各组件生成完整攻击配置."""

    def __init__(
        self,
        data_root: Path | None = None,
        burp_dir: Path | None = None,
        allow_fallback: bool = True,
    ):
        """
        初始化协同编排器.

        Args:
            data_root: 数据根目录 (默认: project/data)
            burp_dir: Burp 文件目录 (默认: data/burp)
            allow_fallback: 是否允许回退到默认配置
        """
        self._data_root = data_root or DATA_ROOT
        self._burp_dir = burp_dir or BURP_ROOT
        self._allow_fallback = allow_fallback

        # 延迟加载子组件
        self._mapper = None
        self._classifier = None
        self._scorer_selector = None

    @property
    def mapper(self):
        """延迟加载 AssetMapper."""
        if self._mapper is None:
            from data.asset_mapper import AssetMapper
            self._mapper = AssetMapper()
        return self._mapper

    @property
    def scorer_selector(self):
        """延迟加载 ScorerSelector."""
        if self._scorer_selector is None:
            from data import scorer_selector as ss
            self._scorer_selector = ss
        return self._scorer_selector

    def build_synergy_config(
        self,
        burp_profile_name: str,
        burp_content: str | None = None,
        force_surface: str | None = None,
    ) -> SynergyConfig:
        """构建完整协同配置.

        主入口: 基于 Burp 配置文件生成完整攻击配置.

        Args:
            burp_profile_name: Burp 配置文件名 (如 "mcp05")
            burp_content: Burp 文件原始内容 (可选)
            force_surface: 强制指定攻击面类型 (覆盖自动检测)

        Returns:
            SynergyConfig 完整配置对象
        """
        logger.info("Building synergy config for burp profile: %s", burp_profile_name)

        # ── Step 1: 分类攻击面 ──
        if force_surface:
            attack_surface = force_surface
            confidence = 1.0
            evidence = [f"Forced surface type: {force_surface}"]
        elif burp_content:
            # 基于内容的深度分类
            from data.attack_surface_classifier import classify_http_content
            url = self._extract_url(burp_content)
            result = classify_http_content(
                http_request=burp_content,
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

        logger.debug("Attack surface: %s (confidence=%.2f)", attack_surface, confidence)

        # ── Step 2: 选择种子 ──
        seed_names = self.mapper.get_seeds_for_attack_surface(attack_surface)

        # 转换为实际文件路径
        seed_files = []
        for seed_name in seed_names:
            file_path = self.mapper.get_seed_file_path(seed_name)
            if file_path:
                seed_files.append(file_path)

        # 验证种子文件是否存在
        seed_files_existing = self._filter_existing_files(seed_files)
        missing_seeds = set(seed_files) - set(seed_files_existing)
        if missing_seeds:
            logger.warning("Missing seed files (skipped): %s", missing_seeds)

        # ── Step 3: 选择评分器 ──
        scorer_name = self.scorer_selector.select_scorer_for_surface(attack_surface)
        scorer_file = self.scorer_selector.get_scorer_path(scorer_name)

        # ── Step 4: 回退检测 ──
        synergy_enabled = True
        if not seed_files_existing:
            logger.warning(
                "No seed files found for surface '%s', falling back to generic mode",
                attack_surface,
            )
            if self._allow_fallback:
                seed_names = self.mapper.get_seeds_for_attack_surface("standard_llm_api")
                seed_files_existing = self._filter_existing_files([
                    self.mapper.get_seed_file_path(s) for s in seed_names
                    if self.mapper.get_seed_file_path(s)
                ])
                synergy_enabled = False
                evidence.append("Fallback to generic mode (no matching seeds)")

        logger.info(
            "Synergy config ready: surface=%s, seeds=%d, scorer=%s",
            attack_surface, len(seed_files_existing), scorer_name,
        )

        return SynergyConfig(
            burp_profile=burp_profile_name,
            attack_surface=attack_surface,
            confidence=confidence,
            seed_names=seed_names,
            seed_files=seed_files_existing,
            scorer_name=scorer_name,
            scorer_file=scorer_file or "",
            evidence=evidence,
            synergy_enabled=synergy_enabled,
        )

    def build_from_burp_file(self, burp_filename: str) -> SynergyConfig:
        """从 Burp 文件构建协同配置.

        便捷方法: 自动读取 Burp 文件内容.

        Args:
            burp_filename: Burp 文件名 (如 "mcp05.txt")

        Returns:
            SynergyConfig
        """
        # 去除 .txt 后缀 (如果有)
        profile_name = burp_filename.replace(".txt", "")

        # 尝试读取文件内容
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

    def _filter_existing_files(self, paths: list[str]) -> list[str]:
        """过滤出存在的文件路径."""
        if not paths:
            return []

        existing = []
        for p in paths:
            # 路径可能已有扩展名，需要检查
            full_path = SEEDS_ROOT / p
            if full_path.exists():
                existing.append(str(full_path))
                continue
            # 尝试添加 .prompt 扩展名
            if not p.endswith(".prompt") and not p.endswith(".yaml"):
                prompt_path = SEEDS_ROOT / f"{p}.prompt"
                if prompt_path.exists():
                    existing.append(str(prompt_path))
                    continue
                # 尝试 yaml
                yaml_path = SEEDS_ROOT / f"{p}.yaml"
                if yaml_path.exists():
                    existing.append(str(yaml_path))

        return existing

    @staticmethod
    def _extract_url(http_content: str) -> str | None:
        """从 HTTP 内容提取 URL."""
        first_line = http_content.split("\n", 1)[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            return parts[1]
        return None


# ──────────────────────────────────────────────
# 全局便捷函数
# ──────────────────────────────────────────────
_default_orchestrator: SynergyOrchestrator | None = None


def get_orchestrator() -> SynergyOrchestrator:
    """获取全局默认编排器."""
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

    返回可直接覆盖 CLI 参数的配置字典.

    Args:
        burp_profile_name: Burp 配置文件名

    Returns:
        参数覆盖字典:
        {
            "seeds": "seed1,seed2,...",
            "scorer": "scorer_name",
            "attack_surface": "surface_type",
        }
    """
    config = quick_build(burp_profile_name)

    return {
        "seeds": ",".join(config.seed_names) if config.seed_names else None,
        "scorer": config.scorer_name,
        "attack_surface": config.attack_surface,
        "synergy_enabled": config.synergy_enabled,
    }
