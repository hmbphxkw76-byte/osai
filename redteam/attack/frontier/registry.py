"""前沿漏洞注册表 — 自动发现和加载漏洞。

核心功能：
  - 扫描 vulns/ 目录，自动加载所有 manifest.yaml
  - 支持按 ID、标签、严重程度过滤
  - 热插拔：新增漏洞目录无需重启
  - 生命周期管理：experimental → active → deprecated → retired

使用方式：
  registry = get_registry()
  active_vulns = registry.get_active()
  vuln = registry.get("FRONTIER-2025-001")
  payloads = registry.get_payloads("FRONTIER-2025-001", "basic")
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import yaml

from .schema import FrontierVuln, FrontierPayloads, VulnStatus

logger = logging.getLogger(__name__)

DEFAULT_VULNS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "config",
    "frontier",
    "vulns",
)


class FrontierRegistry:
    def __init__(self, vulns_dir: str = DEFAULT_VULNS_DIR):
        self._vulns_dir = vulns_dir
        self._vulns: dict[str, FrontierVuln] = {}
        self._payloads: dict[str, FrontierPayloads] = {}
        self._loaded = False

    def _scan_vulns_dir(self) -> list[str]:
        if not os.path.isdir(self._vulns_dir):
            logger.warning(f"Vulns directory not found: {self._vulns_dir}")
            return []

        vuln_dirs = []
        for entry in os.listdir(self._vulns_dir):
            if entry.startswith("_"):
                continue

            entry_path = os.path.join(self._vulns_dir, entry)
            if os.path.isdir(entry_path):
                manifest_path = os.path.join(entry_path, "manifest.yaml")
                if os.path.isfile(manifest_path):
                    vuln_dirs.append(entry_path)
        return vuln_dirs

    def _load_vuln(self, vuln_dir: str) -> Optional[FrontierVuln]:
        manifest_path = os.path.join(vuln_dir, "manifest.yaml")
        payloads_path = os.path.join(vuln_dir, "payloads.yaml")

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = yaml.safe_load(f)

            vuln = FrontierVuln.model_validate(manifest_data)
            self._vulns[vuln.id] = vuln

            if os.path.isfile(payloads_path):
                with open(payloads_path, "r", encoding="utf-8") as f:
                    payloads_data = yaml.safe_load(f)
                self._payloads[vuln.id] = FrontierPayloads.model_validate(payloads_data)

            logger.info(f"Loaded frontier vuln: {vuln.id} ({vuln.name})")
            return vuln
        except Exception as e:
            logger.error(f"Failed to load vuln from {vuln_dir}: {e}")
            return None

    def load(self) -> int:
        self._vulns.clear()
        self._payloads.clear()

        vuln_dirs = self._scan_vulns_dir()
        for vuln_dir in vuln_dirs:
            self._load_vuln(vuln_dir)

        self._loaded = True
        logger.info(f"FrontierRegistry loaded {len(self._vulns)} vulns")
        return len(self._vulns)

    def get(self, vuln_id: str) -> Optional[FrontierVuln]:
        if not self._loaded:
            self.load()
        return self._vulns.get(vuln_id)

    def get_active(self) -> list[FrontierVuln]:
        if not self._loaded:
            self.load()
        return [v for v in self._vulns.values() if v.is_active()]

    def get_by_tag(self, tag: str) -> list[FrontierVuln]:
        if not self._loaded:
            self.load()
        return [v for v in self._vulns.values() if tag.lower() in (t.lower() for t in v.tags)]

    def get_by_severity(self, severity: str) -> list[FrontierVuln]:
        if not self._loaded:
            self.load()
        return [v for v in self._vulns.values() if v.severity.lower() == severity.lower()]

    def get_payloads(self, vuln_id: str, payload_type: str = "basic") -> list[str]:
        if not self._loaded:
            self.load()
        payloads = self._payloads.get(vuln_id)
        if not payloads:
            return []
        return payloads.get_by_type(payload_type)

    def get_all_payloads(self, vuln_id: str) -> list[str]:
        if not self._loaded:
            self.load()
        payloads = self._payloads.get(vuln_id)
        if not payloads:
            return []
        return payloads.get_all()

    def list_all(self) -> list[FrontierVuln]:
        if not self._loaded:
            self.load()
        return list(self._vulns.values())

    def list_active_ids(self) -> list[str]:
        return [v.id for v in self.get_active()]


_registry_instance: Optional[FrontierRegistry] = None


def get_registry(vulns_dir: str = DEFAULT_VULNS_DIR) -> FrontierRegistry:
    global _registry_instance
    if _registry_instance is None or _registry_instance._vulns_dir != vulns_dir:
        _registry_instance = FrontierRegistry(vulns_dir)
        _registry_instance.load()
    return _registry_instance
