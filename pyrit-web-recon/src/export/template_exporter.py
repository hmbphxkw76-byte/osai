# -*- coding: utf-8 -*-
"""
Template Exporter
=================

导出 Burp / Repeater / 攻击工具可用的模板文件。

支持：
  - API 端点模板（OpenAI 兼容格式）
  - Web UI 选择器模板
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class TemplateExporter:
    """导出 Burp / Repeater / 攻击工具可用的模板"""

    def __init__(self, output_dir: str = "data/burp"):
        self.output_dir = output_dir

    def export(
        self,
        profile: Any,
        template: str = "{PROMPT}",
    ) -> List[str]:
        """
        根据 TargetProfile 导出攻击模板。

        输出文件：
          - data/burp/{domain}_api.txt
          - data/burp/{domain}_webui.txt
        """
        os.makedirs(self.output_dir, exist_ok=True)
        created = []

        data = self._build_template_data(profile, template)
        domain = data["domain"] or "unknown"

        # API 模板
        api_entries = [ep for ep in profile.entry_points if ep.get("type") == "api"]
        if api_entries:
            api_path = os.path.join(self.output_dir, f"{domain}_api.txt")
            with open(api_path, "w", encoding="utf-8") as f:
                for ep in api_entries:
                    f.write(f"URL: {ep.get('url', '')}\n")
                    f.write(f"TYPE: {ep.get('api_type', 'unknown')}\n")
                    f.write(f"MODEL: {ep.get('model_name', '')}\n")
                    f.write(f"BODY: {self._api_body_template(template)}\n")
                    f.write("-" * 40 + "\n")
            created.append(api_path)

        # Web UI 模板
        web_entries = [ep for ep in profile.entry_points if ep.get("type") == "web_ui"]
        if web_entries:
            web_path = os.path.join(self.output_dir, f"{domain}_webui.txt")
            with open(web_path, "w", encoding="utf-8") as f:
                for ep in web_entries:
                    f.write(f"URL: {profile.target}\n")
                    f.write(f"INPUT: {ep.get('selector', '')}\n")
                    f.write(f"SEND: {ep.get('extra', {}).get('send_selector', '')}\n")
                    f.write(f"RESPONSE: {ep.get('extra', {}).get('response_selector', '')}\n")
                    f.write(f"TEMPLATE: {template}\n")
                    f.write("-" * 40 + "\n")
            created.append(web_path)

        return created

    def _build_template_data(self, profile: Any, template: str) -> Dict[str, Any]:
        """构建模板变量"""
        from src.auth import extract_domain_from_url, normalize_domain

        domain = ""
        if hasattr(profile, "fingerprint"):
            domain = profile.fingerprint.domain
        if not domain and hasattr(profile, "target"):
            domain = normalize_domain(extract_domain_from_url(profile.target))

        return {
            "domain": domain,
            "target": getattr(profile, "target", ""),
            "template": template,
        }

    @staticmethod
    def _api_body_template(template: str) -> str:
        """OpenAI 兼容 API 请求体模板"""
        import json

        return json.dumps(
            {
                "model": "{MODEL}",
                "messages": [{"role": "user", "content": template}],
                "temperature": 0.7,
            },
            ensure_ascii=False,
            indent=2,
        )
