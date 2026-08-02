# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""HTML/PDF 报告生成器 — 基于 Jinja2 模板引擎.

R-2: 将 f-string 字符串拼接迁移到 Jinja2 模板, 提高可维护性.

核心能力:
1. Jinja2TemplateRenderer: 基于模板引擎的报告渲染器
2. 内置模板: html_wrapper.html (HTML 包装器), evidence_card.html (证据卡片)

学术依据:
  - OWASP Top 10 for LLM Applications 2025: 报告格式最佳实践
  - 红队评估报告标准: 结构化、可审计、可追溯

> **日期**: 2026-8-2
> **更新记录**:
>   2026-8-2 00:00 — R-2: 从 f-string 迁移到 Jinja2 模板引擎
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Jinja2TemplateRenderer:
    """基于 Jinja2 模板引擎的报告渲染器.

    提供统一的模板渲染接口, 自动搜索 pipeline/reporting/templates/ 目录.
    支持自定义模板目录和变量注入.

    用法::

        renderer = Jinja2TemplateRenderer()
        html = renderer.render("html_wrapper.html", content=markdown_content, title="Report")
    """

    def __init__(self, template_dir: str | Path | None = None) -> None:
        """初始化模板渲染器.

        Args:
            template_dir: 模板目录路径 (默认: pipeline/reporting/templates/)
        """
        template_dir = Path(__file__).parent / "templates" if template_dir is None else Path(template_dir)

        self._template_dir = template_dir
        self._env = None

    def _get_jinja_env(self) -> Any:
        """延迟初始化 Jinja2 环境 (惰性加载)."""
        if self._env is not None:
            return self._env

        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape

            self._env = Environment(
                loader=FileSystemLoader(str(self._template_dir)),
                autoescape=select_autoescape(["html"]),
                enable_async=True,
            )
            # 注册自定义过滤器
            self._env.filters["zfill"] = lambda s, width: str(s).zfill(width)
            logger.debug(f"Jinja2 环境初始化完成: {self._template_dir}")
        except ImportError:
            logger.warning("Jinja2 未安装, 回退到 f-string 模式")
            self._env = None
        except (RuntimeError, OSError, ValueError) as e:
            logger.warning(f"Jinja2 初始化失败: {e}, 回退到 f-string 模式")
            self._env = None

        return self._env

    async def render(self, template_name: str, **context: Any) -> str:
        """渲染模板 (异步接口).

        Args:
            template_name: 模板文件名 (如: "html_wrapper.html")
            **context: 模板上下文变量

        Returns:
            渲染后的字符串 (Jinja2 可用时) 或占位符 (Jinja2 不可用时)
        """
        env = self._get_jinja_env()
        if env is None:
            # Jinja2 不可用, 返回简单占位符
            return f"[Jinja2 不可用] 模板: {template_name}, 上下文: {list(context.keys())}"

        try:
            template = env.get_template(template_name)
            result = await template.render_async(**context)
            return result
        except (RuntimeError, OSError, ValueError) as e:
            logger.warning(f"模板渲染失败: {e}")
            return f"[渲染失败] {template_name}: {e}"

    def render_sync(self, template_name: str, **context: Any) -> str:
        """渲染模板 (同步接口).

        Args:
            template_name: 模板文件名
            **context: 模板上下文变量

        Returns:
            渲染后的字符串
        """
        env = self._get_jinja_env()
        if env is None:
            return f"[Jinja2 不可用] 模板: {template_name}"

        try:
            template = env.get_template(template_name)
            return template.render(**context)
        except (RuntimeError, OSError, ValueError) as e:
            logger.warning(f"模板渲染失败: {e}")
            return f"[渲染失败] {template_name}: {e}"

    def has_jinja2(self) -> bool:
        """检查 Jinja2 是否可用."""
        return self._get_jinja_env() is not None


# 单例渲染器 (全局共享)
_global_renderer: Jinja2TemplateRenderer | None = None


def get_renderer() -> Jinja2TemplateRenderer:
    """获取全局渲染器实例."""
    global _global_renderer
    if _global_renderer is None:
        _global_renderer = Jinja2TemplateRenderer()
    return _global_renderer

