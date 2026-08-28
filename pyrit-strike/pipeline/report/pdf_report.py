"""PDF 报告导出 — 从 HTML 报告生成 PDF。

使用以下库 (按优先级尝试):
    1. weasyprint — 纯 Python，无需外部依赖 (但需要 GTK)
    2. playwright — 浏览器自动化，高质量 PDF (需要安装浏览器)
    3. pdfkit — 需要 wkhtmltopdf 系统依赖

如果都不可用，则跳过 PDF 生成并记录警告。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_pdf_report(html_content: str, output_path: Path) -> Path | None:
    """从 HTML 内容生成 PDF 报告。

    尝试使用以下库 (按优先级):
        1. weasyprint — 纯 Python，无需外部依赖 (但需要 GTK)
        2. playwright — 浏览器自动化，高质量 PDF
        3. pdfkit — 需要 wkhtmltopdf 系统依赖

    PDF 增强:
        - 注入打印专用 CSS (确保热力图/仪表盘在 PDF 中正确渲染)
        - 移除 mermaid <script> 标签 (PDF 不执行 JS)
        - 强制背景色打印 (print_background=True)

    Args:
        html_content: HTML 报告内容。
        output_path: PDF 输出路径。

    Returns:
        PDF 文件路径，如果生成失败则返回 None。
    """
    # 预处理 HTML: 注入打印 CSS + 移除 mermaid script
    html_content = _prepare_html_for_pdf(html_content)

    # 尝试 weasyprint
    try:
        from weasyprint import HTML

        HTML(string=html_content).write_pdf(str(output_path))
        logger.info("PDF report saved to %s (weasyprint)", output_path)
        return output_path
    except ImportError:
        logger.debug("weasyprint not available, trying playwright")
    except Exception as e:
        logger.warning("weasyprint PDF generation failed: %s, trying playwright", e)

    # 尝试 playwright (异步, 需要在事件循环中运行)
    try:
        result = _generate_pdf_with_playwright(html_content, output_path)
        if result:
            logger.info("PDF report saved to %s (playwright)", output_path)
            return result
    except Exception as e:
        logger.warning("playwright PDF generation failed: %s, trying pdfkit", e)

    # 尝试 pdfkit
    try:
        import pdfkit

        pdfkit.from_string(html_content, str(output_path), options={"enable-local-file-access": None, "print-media-type": None})
        logger.info("PDF report saved to %s (pdfkit)", output_path)
        return output_path
    except ImportError:
        logger.debug("pdfkit not available")
    except Exception as e:
        logger.warning("pdfkit PDF generation failed: %s", e)

    logger.warning(
        "PDF generation skipped — install one of: "
        "weasyprint (pip install weasyprint), "
        "playwright (pip install playwright && playwright install chromium), "
        "or pdfkit+wkhtmltopdf"
    )
    return None


# 打印专用 CSS — 确保热力图和仪表盘在 PDF 中正确渲染
_PRINT_CSS = """
<style type="text/css" media="print">
@page { size: A4; margin: 15mm; }
body { font-size: 11px; }
.heatmap th, .heatmap td { padding: 4px 6px; font-size: 0.75em; }
.gauge-bar { height: 18px; }
.gauge-label { font-size: 0.7em; }
table { width: 100%; }
code, pre { font-size: 10px; }
</style>
"""


def _prepare_html_for_pdf(html_content: str) -> str:
    """预处理 HTML 以优化 PDF 渲染。

    1. 注入打印专用 CSS (确保热力图/仪表盘正确渲染)
    2. 移除 mermaid <script> 标签 (PDF 不执行 JS)
    3. 将 mermaid div 替换为静态文本
    """
    import re

    # 注入打印 CSS (在 </head> 之前)
    html_content = html_content.replace("</head>", f"{_PRINT_CSS}</head>")

    # 移除 mermaid script 标签
    html_content = re.sub(
        r'<script type="module">.*?mermaid.*?</script>',
        "",
        html_content,
        flags=re.DOTALL,
    )

    return html_content


def _generate_pdf_with_playwright(html_content: str, output_path: Path) -> Path | None:
    """使用 playwright 生成 PDF。

    Playwright 使用 Chromium 浏览器渲染 HTML 并导出 PDF，
    不需要 GTK 系统依赖，适合 Windows 环境。

    Args:
        html_content: HTML 报告内容。
        output_path: PDF 输出路径。

    Returns:
        PDF 文件路径，如果生成失败则返回 None。
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.debug("playwright not available")
        return None

    # 将 HTML 写入临时文件 (playwright 需要文件路径或 URL)
    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        f.write(html_content)
        temp_html_path = f.name

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"file:///{temp_html_path.replace(os.sep, '/')}")
            # 等待 DOM 完全加载 (不需要等待 networkidle, 因为 mermaid script 已移除)
            page.wait_for_load_state("domcontentloaded")
            page.pdf(
                path=str(output_path),
                format="A4",
                print_background=True,
                margin={"top": "20mm", "bottom": "20mm", "left": "15mm", "right": "15mm"},
            )
            browser.close()

        return output_path
    except Exception as e:
        logger.warning("playwright PDF generation error: %s", e)
        return None
    finally:
        # 清理临时文件
        try:
            os.unlink(temp_html_path)
        except OSError:
            pass
