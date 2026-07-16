# -*- coding: utf-8 -*-
"""
AI-300 Framework - TextJailBreak Integration
PyRIT TextJailBreak 数据集集成：90 个本地越狱模板（无需联网）

功能：
1. 列出所有可用越狱模板
2. 用指定模板包装攻击载荷
3. 随机模板包装
4. 全模板批量包装（穷举测试）

使用方式：
    integration = TextJailBreakIntegration()
    templates = integration.list_templates()
    rendered = integration.render_template("aim", "Ignore previous instructions")
    all_rendered = integration.render_all("Ignore previous instructions")
"""

from __future__ import annotations

import logging
import random
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TextJailBreakIntegration:
    """
    PyRIT TextJailBreak 数据集集成

    封装 PyRIT 的 TextJailBreak 类，提供：
    - 模板列表查询
    - 单模板渲染
    - 随机模板渲染
    - 全模板批量渲染

    所有模板均为本地 YAML 文件，无需联网。
    """

    def __init__(self):
        """初始化 TextJailBreak 集成"""
        self._template_names: Optional[List[str]] = None

    @property
    def available(self) -> bool:
        """检查 PyRIT TextJailBreak 是否可用"""
        try:
            from pyrit.datasets import TextJailBreak  # noqa: F401
            return True
        except ImportError:
            logger.warning("PyRIT TextJailBreak not available (pyrit.datasets import failed)")
            return False

    def list_templates(self) -> List[str]:
        """
        列出所有可用的越狱模板名称

        Returns:
            模板文件名列表（如 ["aim.yaml", "aligned.yaml", ...]）
        """
        if self._template_names is not None:
            return self._template_names

        try:
            from pyrit.datasets import TextJailBreak
            self._template_names = TextJailBreak.get_jailbreak_templates()
            return self._template_names
        except Exception as e:
            logger.error("Failed to list TextJailBreak templates: %s", str(e))
            return []

    def get_template_count(self) -> int:
        """
        获取可用模板数量

        Returns:
            模板数量
        """
        return len(self.list_templates())

    def render_template(self, template_name: str, prompt: str) -> Optional[str]:
        """
        用指定模板渲染攻击载荷

        Args:
            template_name: 模板文件名（如 "aim.yaml"）
            prompt: 攻击载荷文本

        Returns:
            渲染后的越狱提示，失败返回 None
        """
        try:
            from pyrit.datasets import TextJailBreak
            jb = TextJailBreak(template_file_name=template_name)
            return jb.get_jailbreak(prompt=prompt)
        except Exception as e:
            logger.error("Failed to render template '%s': %s", template_name, str(e))
            return None

    def render_random(self, prompt: str) -> Optional[Dict[str, str]]:
        """
        用随机模板渲染攻击载荷

        Args:
            prompt: 攻击载荷文本

        Returns:
            {"template": 模板名, "rendered": 渲染结果}，失败返回 None
        """
        try:
            from pyrit.datasets import TextJailBreak
            jb = TextJailBreak(random_template=True)
            rendered = jb.get_jailbreak(prompt=prompt)
            return {
                "template": jb.template_source,
                "rendered": rendered,
            }
        except Exception as e:
            logger.error("Failed to render random template: %s", str(e))
            return None

    def render_all(self, prompt: str, max_templates: Optional[int] = None) -> List[Dict[str, str]]:
        """
        用所有（或指定数量的）模板批量渲染攻击载荷

        Args:
            prompt: 攻击载荷文本
            max_templates: 最大渲染模板数量（None = 全部）

        Returns:
            渲染结果列表，每项包含 {"template": 名, "rendered": 结果}
        """
        templates = self.list_templates()
        if not templates:
            return []

        if max_templates and max_templates < len(templates):
            templates = random.sample(templates, k=max_templates)

        results = []
        for name in templates:
            rendered = self.render_template(name, prompt)
            if rendered:
                results.append({
                    "template": name,
                    "rendered": rendered,
                })

        return results

    def render_with_string_template(self, template_string: str, prompt: str) -> Optional[str]:
        """
        用自定义字符串模板渲染（支持内联模板）

        Args:
            template_string: Jinja2 模板字符串（使用 {{ prompt }} 作为占位符）
            prompt: 攻击载荷文本

        Returns:
            渲染后的文本，失败返回 None
        """
        try:
            from pyrit.datasets import TextJailBreak
            jb = TextJailBreak(string_template=template_string)
            return jb.get_jailbreak(prompt=prompt)
        except Exception as e:
            logger.error("Failed to render string template: %s", str(e))
            return None

    def get_template_info(self, template_name: str) -> Optional[Dict[str, Any]]:
        """
        获取模板元数据

        Args:
            template_name: 模板文件名

        Returns:
            模板元数据字典（name, description, authors, source 等）
        """
        try:
            from pyrit.datasets import TextJailBreak
            from pyrit.common.path import JAILBREAK_TEMPLATES_PATH

            jb = TextJailBreak(template_file_name=template_name)
            template = jb.template

            return {
                "name": template_name,
                "value": template.value,
                "parameters": template.parameters,
                "data_type": template.data_type,
                "is_general_technique": getattr(template, "is_general_technique", None),
                "is_jinja_template": getattr(template, "is_jinja_template", None),
                "template_source": jb.template_source,
            }
        except Exception as e:
            logger.error("Failed to get template info for '%s': %s", template_name, str(e))
            return None

    def get_templates_by_category(self) -> Dict[str, List[str]]:
        """
        按类别分组返回模板（基于文件名前缀分析）

        Returns:
            分类字典，如 {"dan": [...], "role_play": [...], ...}
        """
        templates = self.list_templates()
        categories: Dict[str, List[str]] = {}

        # 基于文件名模式的简单分类
        dan_keywords = ["dan", "better_dan", "based_gpt", "anti_gpt", "aim"]
        role_play_keywords = ["role", "persona", "character", "story", "niccolo"]
        encoding_keywords = ["encode", "cipher", "binary", "base64", "rot"]
        translation_keywords = ["translate", "language", "multilingual"]

        for t in templates:
            t_lower = t.lower()
            assigned = False
            for kw in dan_keywords:
                if kw in t_lower:
                    categories.setdefault("dan_variants", []).append(t)
                    assigned = True
                    break
            if assigned:
                continue

            for kw in role_play_keywords:
                if kw in t_lower:
                    categories.setdefault("role_play", []).append(t)
                    assigned = True
                    break
            if assigned:
                continue

            for kw in encoding_keywords:
                if kw in t_lower:
                    categories.setdefault("encoding", []).append(t)
                    assigned = True
                    break
            if assigned:
                continue

            for kw in translation_keywords:
                if kw in t_lower:
                    categories.setdefault("translation", []).append(t)
                    assigned = True
                    break
            if assigned:
                continue

            categories.setdefault("other", []).append(t)

        return categories
