# ============================================================================
# Sphinx API 文档配置 (G-11)
# ============================================================================
# 使用方式:
#   pip install sphinx sphinx-rtd-theme
#   cd docs/api && sphinx-apidoc -o . ../../pipeline ../../web_redteam
#   make html
# ============================================================================

import os
import sys

# ── 项目路径 ──
sys.path.insert(0, os.path.abspath("../.."))

# ── Sphinx 配置 ──
project = "PyRIT-Pipeline"
copyright = "2026, OSAI Project"
author = "OSAI Project"
release = "5.0.0"

# ── 扩展 ──
extensions = [
    "sphinx.ext.autodoc",        # 自动从 docstring 生成 API
    "sphinx.ext.napoleon",       # Google style docstring 支持
    "sphinx.ext.viewcode",       # 添加 [source] 链接
    "sphinx.ext.intersphinx",    # 跨项目链接
    "sphinx.ext.todo",           # TODO 支持
]

# ── 主题 ──
html_theme = "sphinx_rtd_theme"

# ── autodoc 配置 ──
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "member-order": "bysource",
}

# ── Napoleon 配置 (Google style) ──
napoleon_google_docstring = True
napoleon_numpy_docstring = False

# ── Intersphinx ──
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ── TODO ──
todo_include_todos = True

# ── 输出选项 ──
html_static_path = ["_static"]
templates_path = ["_templates"]

# ── 排除 ──
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
