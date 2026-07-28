"""
Format Converter
================

报告格式转换器 — 将 Markdown 报告转换为 HTML 和 PDF 格式。

设计原则：
  1. 渐进增强：HTML 为基础输出（零系统依赖），PDF 为可选输出（需要额外库）
  2. 优雅降级：如果 PDF 依赖库未安装，跳过 PDF 生成并记录警告，不影响 HTML 输出
  3. 独立模块：不依赖 ReportGenerator 内部状态，纯函数设计
  4. CSS 内嵌：HTML 文件自带样式，无需外部 CSS 文件

依赖：
  - markdown（必需，HTML 转换）：pip install markdown
  - xhtml2pdf（可选，PDF 转换）：pip install xhtml2pdf
  - weasyprint（可选，高质量 PDF）：pip install weasyprint

优先级：weasyprint > xhtml2pdf > 仅 HTML（浏览器打印为 PDF）
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================
# CSS 样式
# ============================================================

_REPORT_CSS = """
/* AI Red Team Assessment Report Styles */
* { box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: #333;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    background-color: #fafafa;
}
h1 {
    color: #1a1a2e;
    border-bottom: 3px solid #0f3460;
    padding-bottom: 10px;
    font-size: 1.8em;
}
h2 {
    color: #0f3460;
    border-bottom: 1px solid #ccc;
    padding-bottom: 5px;
    margin-top: 2em;
    font-size: 1.4em;
}
h3 {
    color: #16213e;
    margin-top: 1.5em;
    font-size: 1.2em;
}
h4 {
    color: #333;
    font-size: 1.05em;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    font-size: 0.9em;
    background: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
th, td {
    border: 1px solid #ddd;
    padding: 8px 12px;
    text-align: left;
}
th {
    background-color: #0f3460;
    color: white;
    font-weight: 600;
}
tr:nth-child(even) {
    background-color: #f8f9fa;
}
tr:hover {
    background-color: #e8f4f8;
}
code {
    background-color: #f1f1f1;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
    color: #c0392b;
}
pre {
    background-color: #2d2d2d;
    color: #f8f8f2;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    line-height: 1.5;
}
pre code {
    background-color: transparent;
    color: inherit;
    padding: 0;
}
blockquote {
    border-left: 4px solid #0f3460;
    margin: 1em 0;
    padding: 10px 20px;
    background-color: #eef2f7;
    color: #555;
}
strong {
    color: #1a1a2e;
}
hr {
    border: none;
    border-top: 2px solid #e0e0e0;
    margin: 2em 0;
}
ul, ol {
    padding-left: 25px;
}
li {
    margin-bottom: 5px;
}
a {
    color: #0f3460;
    text-decoration: none;
}
a:hover {
    text-decoration: underline;
}
/* Print-specific styles */
@media print {
    body {
        max-width: none;
        background-color: #fff;
        padding: 0;
    }
    table, pre {
        page-break-inside: avoid;
    }
    h2, h3 {
        page-break-after: avoid;
    }
}
"""


# ============================================================
# Markdown → HTML 转换
# ============================================================


def convert_markdown_to_html(
    markdown_content: str,
    output_path: str | Path,
    *,
    title: str = "AI Red Team Assessment Report",
) -> Path:
    """
    将 Markdown 内容转换为带样式的 HTML 文件

    Args:
        markdown_content: Markdown 格式的报告内容字符串
        output_path: 输出 HTML 文件路径
        title: HTML 页面标题

    Returns:
        生成的 HTML 文件路径

    Raises:
        ImportError: 如果 markdown 库未安装
    """
    try:
        import markdown as md
    except ImportError:
        raise ImportError(
            "markdown 库未安装。请运行: pip install markdown"
        )

    # 使用扩展增强 Markdown 渲染
    html_body = md.markdown(
        markdown_content,
        extensions=[
            "tables",        # 表格支持
            "fenced_code",   # ``` 代码块
            "codehilite",    # 代码高亮
            "toc",           # 目录生成
            "nl2br",         # 换行转 <br>
            "sane_lists",    # 智能列表
            "smarty",        # 智能引号
        ],
        extension_configs={
            "codehilite": {
                "noclasses": True,
                "pygments_style": "monokai",
            },
        },
    )

    # 构建完整 HTML 文档
    html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
{_REPORT_CSS}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_document, encoding="utf-8")

    logger.info(f"HTML report generated: {output_path}")
    return output_path


# ============================================================
# Markdown → PDF 转换
# ============================================================


def convert_markdown_to_pdf(
    markdown_content: str,
    output_path: str | Path,
    *,
    title: str = "AI Red Team Assessment Report",
    engine: str = "auto",
) -> Optional[Path]:
    """
    将 Markdown 内容转换为 PDF 文件

    自动选择可用的 PDF 引擎：
      1. weasyprint（高质量，需要系统依赖）
      2. xhtml2pdf（纯 Python，质量略低）
      3. 如果都不可用，返回 None 并记录警告

    Args:
        markdown_content: Markdown 格式的报告内容字符串
        output_path: 输出 PDF 文件路径
        title: PDF 文档标题
        engine: PDF 引擎（"weasyprint" / "xhtml2pdf" / "auto"）

    Returns:
        生成的 PDF 文件路径，如果无可用引擎则返回 None
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 先转换为 HTML
    html_content = _markdown_to_html_string(markdown_content, title)

    if engine == "auto":
        # Windows 上 weasyprint 需要 GTK 系统依赖，优先使用 xhtml2pdf（纯 Python）
        # 其他平台 weasyprint 质量更高，优先使用
        import sys
        if sys.platform == "win32":
            engines = ("xhtml2pdf", "weasyprint")
        else:
            engines = ("weasyprint", "xhtml2pdf")
        for eng in engines:
            result = _try_generate_pdf(html_content, output_path, eng)
            if result is not None:
                return result

        logger.warning(
            "No PDF engine available. Install one of: "
            "pip install weasyprint (recommended) or pip install xhtml2pdf"
        )
        return None

    return _try_generate_pdf(html_content, output_path, engine)


def _markdown_to_html_string(markdown_content: str, title: str) -> str:
    """将 Markdown 转换为完整 HTML 字符串（内部使用）"""
    try:
        import markdown as md
    except ImportError:
        raise ImportError(
            "markdown 库未安装。请运行: pip install markdown"
        )

    html_body = md.markdown(
        markdown_content,
        extensions=[
            "tables",
            "fenced_code",
            "codehilite",
            "toc",
            "nl2br",
            "sane_lists",
            "smarty",
        ],
        extension_configs={
            "codehilite": {
                "noclasses": True,
                "pygments_style": "monokai",
            },
        },
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
{_REPORT_CSS}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""


def _try_generate_pdf(
    html_content: str,
    output_path: Path,
    engine: str,
) -> Optional[Path]:
    """尝试使用指定引擎生成 PDF"""
    try:
        if engine == "weasyprint":
            return _generate_pdf_weasyprint(html_content, output_path)
        elif engine == "xhtml2pdf":
            return _generate_pdf_xhtml2pdf(html_content, output_path)
        else:
            logger.warning(f"Unknown PDF engine: {engine}")
            return None
    except ImportError:
        logger.debug(f"PDF engine '{engine}' not available")
        return None
    except Exception as e:
        logger.warning(f"PDF generation with '{engine}' failed: {e}")
        return None


def _generate_pdf_weasyprint(html_content: str, output_path: Path) -> Path:
    """使用 WeasyPrint 生成 PDF（高质量）"""
    from weasyprint import HTML

    HTML(string=html_content).write_pdf(str(output_path))
    logger.info(f"PDF report generated (weasyprint): {output_path}")
    return output_path


def _generate_pdf_xhtml2pdf(html_content: str, output_path: Path) -> Path:
    """使用 xhtml2pdf 生成 PDF（纯 Python，无需系统依赖）"""
    from xhtml2pdf import pisa

    # xhtml2pdf 需要内联 CSS（不支持 <style> 标签的某些特性）
    # 将 CSS 内联到 body 元素上
    inline_html = html_content.replace(
        '<body>',
        '<body style="font-family: Helvetica, Arial, sans-serif; font-size: 12px; line-height: 1.5;">',
    )

    with open(output_path, "wb") as f:
        pisa_status = pisa.CreatePDF(
            inline_html,
            dest=f,
            encoding="utf-8",
        )

    if pisa_status.err:
        raise RuntimeError(f"xhtml2pdf reported {pisa_status.err} errors")

    logger.info(f"PDF report generated (xhtml2pdf): {output_path}")
    return output_path


# ============================================================
# 批量转换（便捷方法）
# ============================================================


def convert_report_formats(
    markdown_content: str,
    base_path: str | Path,
    *,
    generate_html: bool = True,
    generate_pdf: bool = True,
    title: str = "AI Red Team Assessment Report",
    pdf_engine: str = "auto",
) -> dict:
    """
    批量转换报告格式

    根据传入的 Markdown 内容生成 HTML 和/或 PDF 报告。

    Args:
        markdown_content: Markdown 格式的报告内容
        base_path: 基础路径（不含扩展名），如 "output/reports/exam001_report"
        generate_html: 是否生成 HTML 报告
        generate_pdf: 是否生成 PDF 报告
        title: 文档标题
        pdf_engine: PDF 引擎（"weasyprint" / "xhtml2pdf" / "auto"）

    Returns:
        包含生成文件路径的字典：
        {
            "markdown": Path,  # 始终包含原始 Markdown 路径（如果存在）
            "html": Optional[Path],
            "pdf": Optional[Path],
        }
    """
    base_path = Path(base_path)
    result: dict = {}

    if generate_html:
        html_path = base_path.with_suffix(".html")
        result["html"] = convert_markdown_to_html(
            markdown_content, html_path, title=title
        )

    if generate_pdf:
        pdf_path = base_path.with_suffix(".pdf")
        result["pdf"] = convert_markdown_to_pdf(
            markdown_content, pdf_path, title=title, engine=pdf_engine
        )

    return result


# ============================================================
# 引擎可用性检测
# ============================================================


def check_pdf_engine_available() -> dict:
    """
    检查可用的 PDF 转换引擎

    Returns:
        {
            "weasyprint": bool,
            "xhtml2pdf": bool,
            "markdown": bool,
            "recommended": str | None,  # 推荐引擎
        }
    """
    availability = {
        "weasyprint": False,
        "xhtml2pdf": False,
        "markdown": False,
        "recommended": None,
    }

    # 检查 markdown 库
    try:
        import markdown  # noqa: F401
        availability["markdown"] = True
    except ImportError:
        pass

    # 检查 weasyprint
    try:
        import weasyprint  # noqa: F401
        availability["weasyprint"] = True
    except ImportError:
        pass

    # 检查 xhtml2pdf
    try:
        import xhtml2pdf  # noqa: F401
        availability["xhtml2pdf"] = True
    except ImportError:
        pass

    # 推荐引擎
    if availability["weasyprint"]:
        availability["recommended"] = "weasyprint"
    elif availability["xhtml2pdf"]:
        availability["recommended"] = "xhtml2pdf"

    return availability
