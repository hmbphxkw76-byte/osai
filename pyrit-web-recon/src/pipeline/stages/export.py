# -*- coding: utf-8 -*-
"""
阶段 10：导出

将侦察结果输出为多种格式：
  - TargetProfile JSON / YAML
  - Burp / Repeater 攻击模板
  - PyRIT 兼容 target 配置
  - 摘要文本
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

from src.export import ProfileExporter, TemplateExporter
from src.utils import truncate_error

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class ExportStage(PipelineStage):
    """结果导出阶段"""

    name = "export"
    description = "导出 TargetProfile / 模板 / PyRIT 配置"

    async def run(self, context: PipelineContext) -> StageResult:
        profile = context.profile
        if not profile:
            return StageResult(
                success=False,
                message="未生成 TargetProfile，无法导出",
                data={},
            )

        output_dir = self._config(context, "output_dir", "results/recon")
        profile_dir = self._config(context, "profile_dir", "results/recon/profiles")
        template_dir = self._config(context, "template_dir", "templates/burp")
        pyrit_dir = os.path.join(output_dir, "pyrit")

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(profile_dir, exist_ok=True)
        os.makedirs(template_dir, exist_ok=True)
        os.makedirs(pyrit_dir, exist_ok=True)

        exported: List[str] = []
        json_path = ""
        summary_path = ""

        # 1. 导出 TargetProfile JSON
        if self._config(context, "export_profile", True):
            profile_exporter = ProfileExporter(output_dir=profile_dir)
            json_path = profile_exporter.export(profile, fmt="json")
            exported.append(json_path)

            # 同时导出 YAML
            yaml_path = profile_exporter.export(profile, fmt="yaml")
            exported.append(yaml_path)

        # 2. 导出攻击模板
        if self._config(context, "export_template", True):
            template_exporter = TemplateExporter(output_dir=template_dir)
            template_paths = template_exporter.export(profile)
            exported.extend(template_paths)

        # 3. 导出 PyRIT 兼容 target 配置
        if self._config(context, "export_pyrit", True):
            pyrit_path = self._export_pyrit_target(profile, pyrit_dir)
            exported.append(pyrit_path)

        # 4. 保存摘要
        summary_path = os.path.join(output_dir, "latest_summary.txt")
        self._save_summary(profile, summary_path)
        exported.append(summary_path)

        # 5. 保存浏览器状态与截图（如浏览器仍在运行）
        await self._save_browser_artifacts(context, output_dir)

        return StageResult(
            success=True,
            message=f"导出完成: {len(exported)} 个文件",
            data={
                "exported_files": exported,
                "profile_path": json_path if exported else "",
                "summary_path": summary_path,
            },
        )

    def _export_pyrit_target(self, profile: Any, pyrit_dir: str) -> str:
        """导出 PyRIT 兼容 target 配置"""
        from src.auth import normalize_domain

        domain = normalize_domain(profile.target)
        filename = f"{domain}_pyrit_target.json"
        path = os.path.join(pyrit_dir, filename)

        pyrit_config = profile.to_pyrit_target()
        pyrit_config["source"] = profile.target
        pyrit_config["risk_level"] = profile.risk_level
        pyrit_config["surfaces"] = profile.surfaces

        with open(path, "w", encoding="utf-8") as f:
            json.dump(pyrit_config, f, ensure_ascii=False, indent=2)

        logger.info("PyRIT target exported: %s", path)
        return path

    def _save_summary(self, profile: Any, path: str) -> None:
        """保存文本摘要"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(profile.summarize())
            f.write("\n\nRaw Profile:\n")
            json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)
            f.write("\n\nPyRIT Target:\n")
            json.dump(profile.to_pyrit_target(), f, ensure_ascii=False, indent=2)

    async def _save_browser_artifacts(self, context: PipelineContext, output_dir: str) -> None:
        """保存浏览器状态与截图"""
        browser_manager = context.browser_manager
        if not browser_manager:
            return

        try:
            storage_path = await browser_manager.save_storage_state()
            if storage_path and context.profile:
                context.profile.raw_results["storage_state_path"] = storage_path
        except Exception as exc:
            logger.warning("Failed to save storage state: %s", truncate_error(str(exc), context.config))

        try:
            screenshot_path = await browser_manager.screenshot()
            if screenshot_path and context.profile:
                context.profile.raw_results["screenshot_path"] = screenshot_path
        except Exception as exc:
            logger.warning("Failed to save screenshot: %s", truncate_error(str(exc), context.config))
