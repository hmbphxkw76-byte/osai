# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""格式转换器 — Markdown → HTML → PDF。.

从 pipeline/html_report.py 提取，优先使用 PyRIT 原生 output 体系。

学术依据:
  - OWASP Top 10 for LLM Applications 2025: 报告格式最佳实践
  - 红队评估报告标准: 结构化、可审计、可追溯
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================
# 内嵌 CSS 样式 (从 html_report.py 迁移)
# ============================================================

_HTML_CSS = """
<style>
  /* AI Red Team Assessment Report Styles — L5 对齐深蓝主题 */
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px;
    background-color: #fafafa;
  }
  h1 {
    color: #1a1a2e; border-bottom: 3px solid #0f3460; padding-bottom: 10px;
    font-size: 1.8em;
  }
  h2 {
    color: #0f3460; border-bottom: 1px solid #ccc; padding-bottom: 5px;
    margin-top: 2em; font-size: 1.4em;
  }
  h3 { color: #16213e; margin-top: 1.5em; font-size: 1.2em; }
  h4 { color: #333; font-size: 1.05em; }
  table {
    border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 0.9em;
    background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
  th { background-color: #0f3460; color: white; font-weight: 600; }
  tr:nth-child(even) { background-color: #f8f9fa; }
  tr:hover { background-color: #e8f4f8; }
  code {
    background-color: #f1f1f1; padding: 2px 6px; border-radius: 3px;
    font-family: "Fira Code", "Courier New", monospace; font-size: 0.9em;
    color: #c0392b;
  }
  pre {
    background-color: #2d2d2d; color: #f8f8f2; padding: 15px;
    border-radius: 5px; overflow-x: auto; font-size: 0.85em; line-height: 1.5;
  }
  pre code { background-color: transparent; color: inherit; padding: 0; }
  blockquote {
    border-left: 4px solid #0f3460; margin: 1em 0; padding: 10px 20px;
    background-color: #eef2f7; color: #555;
  }
  strong { color: #1a1a2e; }
  hr { border: none; border-top: 2px solid #e0e0e0; margin: 2em 0; }
  ul, ol { padding-left: 25px; }
  li { margin-bottom: 5px; }
  a { color: #0f3460; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Custom component styles (stage_output section builders) */
  .asr-high { color: #e74c3c; font-weight: bold; }
  .asr-medium { color: #f39c12; font-weight: bold; }
  .asr-low { color: #27ae60; }
  .asr-bar {
    display: inline-block; height: 12px; border-radius: 3px;
    vertical-align: middle; min-width: 4px;
  }
  .asr-bar-high { background: #e74c3c; }
  .asr-bar-medium { background: #f39c12; }
  .asr-bar-low { background: #27ae60; }
  .metric-box {
    display: inline-block; background: #f8f9fa; border: 1px solid #dee2e6;
    border-radius: 8px; padding: 15px 25px; margin: 10px; text-align: center;
  }
  .metric-value { font-size: 2em; font-weight: bold; display: block; }
  .metric-label { font-size: 0.85em; color: #6c757d; text-transform: uppercase; }
  .summary-grid { display: flex; flex-wrap: wrap; justify-content: center; margin: 20px 0; }
  .evidence-card {
    border: 1px solid #dee2e6; border-radius: 8px; padding: 15px;
    margin: 10px 0; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05);
  }
  .evidence-card h4 { margin-top: 0; color: #0f3460; }
  .vulnerability { border-left: 4px solid #e74c3c; }
  .safe { border-left: 4px solid #27ae60; }
  .owasp-badge {
    display: inline-block; padding: 3px 10px; border-radius: 12px;
    font-size: 0.85em; font-weight: 600; color: #fff; margin: 2px;
  }
  .owasp-llm { background: #0f3460; }
  .owasp-asi { background: #6c5ce7; }
  .asr-cell { text-align: center; font-weight: 600; }
  .asr-cell-high { background-color: #fde8e8; color: #e74c3c; }
  .asr-cell-medium { background-color: #fef3e2; color: #f39c12; }
  .asr-cell-low { background-color: #e8f8f0; color: #27ae60; }
  .asr-cell-zero { background-color: #f0f0f0; color: #999; }
  .attack-chain { list-style: none; padding-left: 0; margin: 10px 0; }
  .attack-chain li {
    padding: 8px 12px; margin: 4px 0; border-radius: 4px;
    border-left: 3px solid #ddd; background: #f8f9fa;
  }
  .attack-chain li.success { border-left-color: #27ae60; }
  .attack-chain li.failure { border-left-color: #e74c3c; }
  .converter-entry {
    padding: 8px 12px; margin: 4px 0; border-radius: 4px;
    background: #f1f3f5; border-left: 3px solid #6c5ce7;
  }
  .converter-entry .arrow { color: #6c5ce7; font-weight: bold; }

  /* Print-specific styles */
  @media print {
    body { max-width: none; background-color: #fff; padding: 0; }
    table, pre { page-break-inside: avoid; }
    h2, h3 { page-break-after: avoid; }
  }
</style>
"""


def convert_markdown_to_html(markdown_content: str, *, title: str = "AI Red Team Report") -> str:
    """将 Markdown 转换为 HTML (内嵌 CSS)。.

    L5 对齐 pyrit_ai300/src/reporting/format_converter.py:
      - 使用 7 个 Markdown 扩展 (tables, fenced_code, codehilite, toc, nl2br, sane_lists, smarty)
      - codehilite 配置 monokai 主题 + noclasses
    """
    try:
        import markdown as md

        html_body = md.markdown(
            markdown_content,
            extensions=[
                "tables",       # 表格支持
                "fenced_code",  # ``` 代码块
                "codehilite",   # 代码高亮
                "toc",          # 目录生成
                "nl2br",        # 换行转 <br>
                "sane_lists",   # 智能列表
                "smarty",       # 智能引号
            ],
            extension_configs={
                "codehilite": {
                    "noclasses": True,
                    "pygments_style": "monokai",
                },
            },
        )
    except ImportError:
        import html
        html_body = f"<pre>{html.escape(markdown_content)}</pre>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  {_HTML_CSS}
</head>
<body>
{html_body}
</body>
</html>"""


def convert_markdown_to_pdf(html_content: str, output_path: Path) -> bool:
    """将 HTML 转换为 PDF (优先 weasyprint, 回退 xhtml2pdf)。."""
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(output_path))
        logger.info(f"PDF generated (weasyprint): {output_path}")
        return True
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"weasyprint failed: {e}")

    try:
        from xhtml2pdf import pisa

        with open(output_path, "wb") as f:
            pisa_status = pisa.CreatePDF(html_content, dest=f)
        if not pisa_status.err:
            logger.info(f"PDF generated (xhtml2pdf): {output_path}")
            return True
        else:
            logger.warning("xhtml2pdf failed with errors")
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"xhtml2pdf failed: {e}")

    logger.error("No PDF library available (install weasyprint or xhtml2pdf)")
    return False


def check_pdf_engine_available() -> str | None:
    """检查可用的 PDF 引擎。返回引擎名称或 None。."""
    try:
        import weasyprint  # noqa: F401
        return "weasyprint"
    except ImportError:
        pass
    try:
        import xhtml2pdf  # noqa: F401
        return "xhtml2pdf"
    except ImportError:
        pass
    return None


def convert_report_formats(
    markdown_content: str,
    base_path: Path,
    *,
    generate_html: bool = True,
    generate_pdf: bool = True,
    title: str = "AI Red Team Report",
) -> dict[str, Path | None]:
    """生成 HTML 和 PDF 报告。.

    Args:
        markdown_content: Markdown 报告内容。
        base_path: 输出基础路径 (不含扩展名)。
        generate_html: 是否生成 HTML。
        generate_pdf: 是否生成 PDF。
        title: 报告标题。

    Returns:
        字典: {"html": Path | None, "pdf": Path | None}
    """
    base_path = Path(base_path)
    base_path.parent.mkdir(parents=True, exist_ok=True)

    result: dict[str, Path | None] = {"html": None, "pdf": None}

    html_content = None
    if generate_html:
        html_content = convert_markdown_to_html(markdown_content, title=title)
        html_path = Path(f"{base_path}.html")
        html_path.write_text(html_content, encoding="utf-8")
        result["html"] = html_path
        logger.info(f"HTML report generated: {html_path}")

    if generate_pdf:
        if html_content is None:
            html_content = convert_markdown_to_html(markdown_content, title=title)
        pdf_path = Path(f"{base_path}.pdf")
        if convert_markdown_to_pdf(html_content, pdf_path):
            result["pdf"] = pdf_path

    return result
