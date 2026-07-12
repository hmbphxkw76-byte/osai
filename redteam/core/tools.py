"""工具解析器（简化版）。

本模块解析系统中可用工具的路径，并依据 config/settings.yaml 的开关判断功能是否启用。
"""
from __future__ import annotations

import shutil
from pathlib import Path

import yaml

DEFAULT_SETTINGS = Path("config/settings.yaml")


class ToolResolver:
    def __init__(self, settings_path: Path = DEFAULT_SETTINGS):
        self.settings = self._load(settings_path)
        self.tools: dict[str, str] = self.settings.get("tools", {}) or {}

    @staticmethod
    def _load(p: Path) -> dict:
        if p.exists():
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return {}

    def resolve(self, name: str) -> str:
        cmd = self.tools.get(name, name)
        candidate = Path(cmd)
        if candidate.exists():
            return str(candidate)
        found = shutil.which(cmd)
        return found or cmd

    def available(self, name: str) -> bool:
        cmd = self.tools.get(name, name)
        if Path(cmd).exists():
            return True
        return shutil.which(cmd) is not None

    def enabled(self, key: str) -> bool:
        recon = self.settings.get("recon", {}) or {}
        val = recon.get(key, "auto")
        if isinstance(val, bool):
            return val
        if val == "auto":
            tool_name = key.replace("enable_", "")
            return self.available(tool_name)
        return bool(val)
