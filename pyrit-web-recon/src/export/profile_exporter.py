# -*- coding: utf-8 -*-
"""
Profile Exporter
================

将 TargetProfile 导出为 JSON / YAML，供攻击阶段复用。
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class ProfileExporter:
    """TargetProfile 导出器：JSON / YAML"""

    def __init__(self, output_dir: str = "results/recon/profiles"):
        self.output_dir = output_dir

    def export(
        self,
        profile: Any,
        fmt: str = "json",
        filename: str = "",
    ) -> str:
        """
        导出 TargetProfile 到文件。

        Args:
            profile: TargetProfile 实例
            fmt: json / yaml
            filename: 自定义文件名（可选）

        Returns:
            导出的文件路径
        """
        os.makedirs(self.output_dir, exist_ok=True)

        if not filename:
            from src.auth import normalize_domain

            domain = "unknown"
            if hasattr(profile, "fingerprint") and profile.fingerprint.domain:
                domain = normalize_domain(profile.fingerprint.domain)
            elif hasattr(profile, "target"):
                domain = normalize_domain(profile.target)
            ts = str(int(time.time()))
            filename = f"{domain}_{ts}.{fmt}"

        path = os.path.join(self.output_dir, filename)
        data = profile.to_dict() if hasattr(profile, "to_dict") else dict(profile)

        if fmt.lower() == "yaml":
            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info("Profile exported: %s", path)
        return path
