"""
===============================================================================
前沿 AI 漏洞注册中心 — 自动发现 + 动态注册 + Payload 加载
===============================================================================
核心职责:
  1. 扫描 vulns/ 目录自动发现所有活跃的前沿漏洞
  2. 动态注册到系统管道（AttackStrategy 映射 + Generator 路由）
  3. 提供统一的 payload 加载接口

用法:
  registry = get_registry()
  registry.discover()                           # 自动扫描
  vulns = registry.get_active()                 # 获取活跃漏洞列表
  payloads = registry.get_payloads("FRONTIER-2026-003", "basic")  # 获取 payload
===============================================================================
"""
from __future__ import annotations

import logging
import os
import yaml
from glob import glob
from pathlib import Path
from typing import Optional

from scenarios.frontier.base import (
    FrontierVuln, FrontierPayload, FrontierStatus,
)

logger = logging.getLogger(__name__)

# ── 依赖导入（延迟，避免循环）──
_FRONTIER_STRATEGIES: dict[str, str] = {}   # {strategy_name: vuln_id}


class FrontierRegistry:
    """前沿漏洞注册中心。

    自动扫描 scenarios/frontier/vulns/ 下的所有 manifest.yaml，
    将 status=active 的漏洞注册到攻击管道。

    Singleton 模式 — 全局唯一实例。
    """

    def __init__(self):
        self._vulns: dict[str, FrontierVuln] = {}
        self._discovered = False
        self._active_strategies: set[str] = set()
        self._payload_cache: dict[str, dict[str, list[str]]] = {}
        self._base_dir: str = ""

    # ═══════════════════════════════════════════════════════════════
    # 自动发现
    # ═══════════════════════════════════════════════════════════════

    def discover(self, base_dir: str | None = None, *, include_experimental: bool = False) -> int:
        """扫描 vulns/ 目录，加载所有前沿漏洞。

        Args:
            base_dir: vulns/ 的父目录路径（None 则自动推断）
            include_experimental: 是否包含 experimental 状态的漏洞

        Returns:
            成功加载的漏洞数量
        """
        if base_dir is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        self._base_dir = base_dir

        vulns_dir = os.path.join(base_dir, "vulns")
        if not os.path.isdir(vulns_dir):
            logger.warning("FrontierRegistry: vulns/ 目录不存在: %s", vulns_dir)
            return 0

        manifest_pattern = os.path.join(vulns_dir, "*", "manifest.yaml")
        count = 0
        for manifest_path in sorted(glob(manifest_pattern)):
            try:
                vuln_dir = os.path.dirname(manifest_path)
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not data:
                    logger.warning("FrontierRegistry: manifest 为空: %s", manifest_path)
                    continue

                vuln = FrontierVuln.from_manifest(data, source_dir=vuln_dir)
                if not vuln.id:
                    logger.warning("FrontierRegistry: manifest 缺少 id: %s", manifest_path)
                    continue

                # 过滤规则
                if vuln.status == FrontierStatus.RETIRED:
                    logger.debug("FrontierRegistry: 跳过 retired vuln %s", vuln.id)
                    continue
                if vuln.status == FrontierStatus.DEPRECATED and not include_experimental:
                    logger.debug("FrontierRegistry: 跳过 deprecated vuln %s", vuln.id)
                    continue
                if vuln.status == FrontierStatus.EXPERIMENTAL and not include_experimental:
                    logger.debug("FrontierRegistry: 跳过 experimental vuln %s", vuln.id)
                    continue

                self._vulns[vuln.id] = vuln
                if vuln.is_active:
                    self._active_strategies.add(vuln.attack_strategy)
                count += 1
                logger.info(
                    "FrontierRegistry: 注册前沿漏洞 %s (%s) status=%s confidence=%.2f",
                    vuln.id, vuln.name, vuln.status.value, vuln.confidence,
                )

            except Exception as e:
                logger.error("FrontierRegistry: 加载 manifest 失败 %s: %s", manifest_path, e)

        self._discovered = True
        logger.info("FrontierRegistry: 发现 %d 个前沿漏洞 (active=%d)",
                     count, len(self._active_strategies))
        return count

    # ═══════════════════════════════════════════════════════════════
    # 查询 API
    # ═══════════════════════════════════════════════════════════════

    def get_active(self) -> list[FrontierVuln]:
        """获取所有活跃（status=active）的前沿漏洞"""
        return [v for v in self._vulns.values() if v.is_active]

    def get_all_loaded(self) -> list[FrontierVuln]:
        """获取所有已加载的漏洞（包括 experimental）"""
        return list(self._vulns.values())

    def get(self, vuln_id: str) -> Optional[FrontierVuln]:
        """按 ID 获取漏洞"""
        return self._vulns.get(vuln_id)

    def get_active_strategy_names(self) -> set[str]:
        """获取所有活跃的策略名称"""
        return set(self._active_strategies)

    def get_global_strategy_map(self) -> dict[str, str]:
        """获取全局 {strategy_name: vuln_id} 映射。

        供外部模块使用（如 orchestrator 路由）。
        """
        result = {}
        for v in self._vulns.values():
            if v.is_active and v.attack_strategy:
                result[v.attack_strategy] = v.id
        return result

    def has_active_vulns(self) -> bool:
        """是否有活跃的前沿漏洞"""
        return len(self._active_strategies) > 0

    # ═══════════════════════════════════════════════════════════════
    # Payload 加载
    # ═══════════════════════════════════════════════════════════════

    def get_payloads(self, vuln_id: str, section_key: str = "basic") -> list[str]:
        """获取指定漏洞 + section 的 payload 文本列表。

        Args:
            vuln_id: 漏洞 ID
            section_key: YAML section 名（basic/advanced/stealth）

        Returns:
            payload 文本列表
        """
        sections = self._load_payloads(vuln_id)
        return sections.get(section_key, [])

    def get_all_payloads(self, vuln_id: str) -> list[FrontierPayload]:
        """获取指定漏洞的所有 payload（全部 section）"""
        sections = self._load_payloads(vuln_id)
        result = []
        for section_key, texts in sections.items():
            for text in texts:
                result.append(FrontierPayload(
                    text=text,
                    section_key=section_key,
                    vuln_id=vuln_id,
                    description=f"Frontier-{vuln_id}-{section_key}",
                ))
        return result

    def get_payload_for_strategy(self, strategy_name: str, max_payloads: int = 8) -> list[FrontierPayload]:
        """按策略名称获取 payload（用于 orchestrator 路由）"""
        strategy_map = self.get_global_strategy_map()
        if strategy_name not in strategy_map:
            return []
        vuln_id = strategy_map[strategy_name]
        return self.get_all_payloads(vuln_id)[:max_payloads]

    def list_sections(self, vuln_id: str) -> list[str]:
        """列出指定漏洞 payloads.yaml 中的所有 section 名称"""
        sections = self._load_payloads(vuln_id)
        return list(sections.keys())

    def _load_payloads(self, vuln_id: str) -> dict[str, list[str]]:
        """加载 vuln 的 payloads.yaml（带缓存）"""
        if vuln_id in self._payload_cache:
            return self._payload_cache[vuln_id]

        vuln = self._vulns.get(vuln_id)
        if not vuln:
            logger.warning("FrontierRegistry: 未知 vuln ID: %s", vuln_id)
            return {}

        payloads_path = os.path.join(vuln.source_dir, "payloads.yaml")
        if not os.path.isfile(payloads_path):
            logger.warning("FrontierRegistry: payloads.yaml 不存在: %s", payloads_path)
            return {}

        try:
            with open(payloads_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data:
                return {}

            # payloads.yaml 结构: { "payloads": { "basic": [...], "advanced": [...], ... } }
            sections = data.get("payloads", {})
            self._payload_cache[vuln_id] = sections
            return sections
        except Exception as e:
            logger.error("FrontierRegistry: 加载 payloads 失败 %s: %s", payloads_path, e)
            return {}

    # ═══════════════════════════════════════════════════════════════
    # 统计与摘要
    # ═══════════════════════════════════════════════════════════════

    def get_summary(self) -> dict:
        """获取注册表统计摘要"""
        status_counts = {}
        tag_counts = {}
        for v in self._vulns.values():
            status_counts[v.status.value] = status_counts.get(v.status.value, 0) + 1
            for tag in v.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "total_vulns": len(self._vulns),
            "active_count": len(self.get_active()),
            "experimental_count": status_counts.get("experimental", 0),
            "deprecated_count": status_counts.get("deprecated", 0),
            "retired_count": status_counts.get("retired", 0),
            "active_strategies": sorted(self._active_strategies),
            "top_tags": sorted(tag_counts.items(), key=lambda x: -x[1])[:10],
        }

    def print_summary(self, console=None):
        """打印注册表概览（可选传入 rich Console）"""
        summary = self.get_summary()
        lines = [
            f"前沿漏洞注册表: {summary['active_count']}/{summary['total_vulns']} 活跃",
            f"状态分布: active={summary['active_count']}, "
            f"experimental={summary['experimental_count']}, "
            f"deprecated={summary['deprecated_count']}, "
            f"retired={summary['retired_count']}",
            f"活跃策略: {', '.join(summary['active_strategies']) or '(无)'}",
        ]
        if console:
            for line in lines:
                console.print(f"[dim]{line}[/dim]")
        else:
            for line in lines:
                print(line)


# ═══════════════════════════════════════════════════════════════════
# 全局单例
# ═══════════════════════════════════════════════════════════════════

_registry: Optional[FrontierRegistry] = None


def get_registry(auto_discover: bool = True) -> FrontierRegistry:
    """获取全局 FrontierRegistry 单例。

    Args:
        auto_discover: 是否自动扫描 vulns/ 目录（默认 True）
    """
    global _registry
    if _registry is None:
        _registry = FrontierRegistry()
        if auto_discover:
            _registry.discover()
    return _registry


def get_frontier_vulns() -> list[FrontierVuln]:
    """快捷函数：获取所有活跃的前沿漏洞"""
    return get_registry().get_active()


def get_frontier_strategies() -> set[str]:
    """快捷函数：获取所有活跃的前沿策略名称"""
    return get_registry().get_active_strategy_names()
