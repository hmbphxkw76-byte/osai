"""
格式转换器测试
==============

测试 Markdown → HTML / PDF 格式转换功能。

覆盖范围：
  1. HTML 转换（基础 Markdown、表格、代码块、标题）
  2. PDF 转换（自动引擎选择、优雅降级）
  3. 批量转换（convert_report_formats）
  4. 引擎可用性检测
  5. 异常处理（缺少依赖时的行为）
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.reporting.format_converter import (
    convert_markdown_to_html,
    convert_markdown_to_pdf,
    convert_report_formats,
    check_pdf_engine_available,
    _markdown_to_html_string,
)


# ============================================================
# 测试数据
# ============================================================


SAMPLE_MARKDOWN = """# AI Red Team Assessment Report

## 1. Executive Summary

This is a test report with **bold** and `code` text.

### Findings Summary

| OWASP ID | Severity | Count |
|----------|----------|-------|
| LLM01    | HIGH     | 3     |
| ASI01    | CRITICAL | 1     |

- Item 1
- Item 2
- Item 3

```python
print("Hello, World!")
```

> This is a blockquote with important information.
"""


COMPLEX_MARKDOWN = """# Report Title

## Section A

Some text with a [link](https://example.com).

### Subsection

1. First item
2. Second item with `inline code`
3. Third item

## Section B

| Col1 | Col2 | Col3 |
|------|------|------|
| a    | b    | c    |
| d    | e    | f    |

---

End of report.
"""


# ============================================================
# HTML 转换测试
# ============================================================


class TestMarkdownToHtml:
    """测试 Markdown → HTML 转换"""

    def test_basic_html_conversion(self, tmp_path):
        """测试基础 Markdown 转 HTML"""
        output = tmp_path / "report.html"
        result = convert_markdown_to_html(SAMPLE_MARKDOWN, output)

        assert result == output
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "<h1" in content and "AI Red Team Assessment Report</h1>" in content
        assert "<table>" in content
        assert "<code>" in content
        assert "<blockquote>" in content

    def test_html_contains_css(self, tmp_path):
        """测试 HTML 包含内嵌 CSS 样式"""
        output = tmp_path / "report.html"
        convert_markdown_to_html(SAMPLE_MARKDOWN, output)

        content = output.read_text(encoding="utf-8")
        assert "<style>" in content
        assert "font-family" in content
        assert "border-collapse" in content

    def test_html_title(self, tmp_path):
        """测试 HTML 页面标题"""
        output = tmp_path / "report.html"
        convert_markdown_to_html(
            SAMPLE_MARKDOWN, output, title="Custom Report Title"
        )

        content = output.read_text(encoding="utf-8")
        assert "<title>Custom Report Title</title>" in content

    def test_html_creates_parent_dirs(self, tmp_path):
        """测试自动创建父目录"""
        output = tmp_path / "nested" / "deep" / "path" / "report.html"
        convert_markdown_to_html(SAMPLE_MARKDOWN, output)
        assert output.exists()

    def test_complex_markdown_html(self, tmp_path):
        """测试复杂 Markdown 转 HTML（表格+列表+链接）"""
        output = tmp_path / "complex.html"
        convert_markdown_to_html(COMPLEX_MARKDOWN, output)

        content = output.read_text(encoding="utf-8")
        assert "<table>" in content
        assert "<ol>" in content
        assert '<a href="https://example.com">link</a>' in content
        assert "<hr" in content

    def test_empty_markdown(self, tmp_path):
        """测试空 Markdown 输入"""
        output = tmp_path / "empty.html"
        convert_markdown_to_html("", output)
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<body>" in content

    def test_markdown_to_html_string(self):
        """测试内部 HTML 字符串生成"""
        html = _markdown_to_html_string("# Title", "Test Title")
        assert "<!DOCTYPE html>" in html
        assert "<title>Test Title</title>" in html
        assert "<h1" in html and "Title</h1>" in html


# ============================================================
# PDF 转换测试
# ============================================================


class TestMarkdownToPdf:
    """测试 Markdown → PDF 转换"""

    def test_pdf_auto_engine(self, tmp_path):
        """测试自动引擎选择生成 PDF"""
        output = tmp_path / "report.pdf"
        result = convert_markdown_to_pdf(SAMPLE_MARKDOWN, output, engine="auto")

        # 如果有可用引擎，应该生成 PDF
        if result is not None:
            assert result == output
            assert output.exists()
            assert output.stat().st_size > 0
            # PDF 文件应该以 %PDF 开头
            with open(output, "rb") as f:
                header = f.read(5)
            assert header == b"%PDF-"

    def test_pdf_xhtml2pdf_engine(self, tmp_path):
        """测试 xhtml2pdf 引擎生成 PDF"""
        try:
            import xhtml2pdf  # noqa: F401
        except ImportError:
            pytest.skip("xhtml2pdf not installed")

        output = tmp_path / "report_xhtml2pdf.pdf"
        result = convert_markdown_to_pdf(
            SAMPLE_MARKDOWN, output, engine="xhtml2pdf"
        )

        assert result is not None
        assert output.exists()
        assert output.stat().st_size > 0

    def test_pdf_unknown_engine_returns_none(self, tmp_path):
        """测试未知引擎返回 None"""
        output = tmp_path / "report.pdf"
        result = convert_markdown_to_pdf(
            SAMPLE_MARKDOWN, output, engine="nonexistent"
        )
        assert result is None

    def test_pdf_no_engine_available(self, tmp_path):
        """测试无可用 PDF 引擎时优雅降级"""
        output = tmp_path / "report.pdf"

        with patch("src.reporting.format_converter._try_generate_pdf", return_value=None):
            result = convert_markdown_to_pdf(
                SAMPLE_MARKDOWN, output, engine="auto"
            )
            assert result is None

    def test_pdf_creates_parent_dirs(self, tmp_path):
        """测试 PDF 自动创建父目录"""
        try:
            import xhtml2pdf  # noqa: F401
        except ImportError:
            pytest.skip("xhtml2pdf not installed")

        output = tmp_path / "nested" / "report.pdf"
        result = convert_markdown_to_pdf(
            SAMPLE_MARKDOWN, output, engine="xhtml2pdf"
        )
        if result is not None:
            assert output.exists()


# ============================================================
# 批量转换测试
# ============================================================


class TestConvertReportFormats:
    """测试批量格式转换"""

    def test_generate_html_only(self, tmp_path):
        """测试仅生成 HTML"""
        base = tmp_path / "report"
        result = convert_report_formats(
            SAMPLE_MARKDOWN, base, generate_html=True, generate_pdf=False
        )

        assert "html" in result
        assert result["html"] is not None
        assert result["html"].exists()
        assert "pdf" not in result or result.get("pdf") is None

    def test_generate_both(self, tmp_path):
        """测试同时生成 HTML 和 PDF"""
        base = tmp_path / "report"
        result = convert_report_formats(
            SAMPLE_MARKDOWN, base, generate_html=True, generate_pdf=True
        )

        assert result["html"] is not None
        assert result["html"].exists()
        assert result["html"].suffix == ".html"

        # PDF 可能有也可能没有（取决于安装的引擎）
        if result.get("pdf") is not None:
            assert result["pdf"].exists()
            assert result["pdf"].suffix == ".pdf"

    def test_generate_neither(self, tmp_path):
        """测试不生成任何格式"""
        base = tmp_path / "report"
        result = convert_report_formats(
            SAMPLE_MARKDOWN, base, generate_html=False, generate_pdf=False
        )

        assert result.get("html") is None
        assert result.get("pdf") is None

    def test_html_and_pdf_different_extensions(self, tmp_path):
        """测试 HTML 和 PDF 文件扩展名正确"""
        base = tmp_path / "exam001_report"
        result = convert_report_formats(
            SAMPLE_MARKDOWN, base, generate_html=True, generate_pdf=True
        )

        if result.get("html"):
            assert result["html"].name == "exam001_report.html"
        if result.get("pdf"):
            assert result["pdf"].name == "exam001_report.pdf"


# ============================================================
# 引擎检测测试
# ============================================================


class TestCheckPdfEngine:
    """测试 PDF 引擎可用性检测"""

    def test_check_returns_dict(self):
        """测试返回字典结构"""
        result = check_pdf_engine_available()
        assert isinstance(result, dict)
        assert "weasyprint" in result
        assert "xhtml2pdf" in result
        assert "markdown" in result
        assert "recommended" in result

    def test_markdown_available(self):
        """测试 markdown 库已安装（测试环境必备）"""
        result = check_pdf_engine_available()
        assert result["markdown"] is True

    def test_recommended_engine_logic(self):
        """测试推荐引擎逻辑"""
        result = check_pdf_engine_available()
        if result["weasyprint"]:
            assert result["recommended"] == "weasyprint"
        elif result["xhtml2pdf"]:
            assert result["recommended"] == "xhtml2pdf"
        else:
            assert result["recommended"] is None


# ============================================================
# 异常处理测试
# ============================================================


class TestErrorHandling:
    """测试异常处理"""

    def test_html_conversion_missing_markdown_lib(self, tmp_path):
        """测试缺少 markdown 库时抛出 ImportError"""
        output = tmp_path / "report.html"

        with patch.dict("sys.modules", {"markdown": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module named 'markdown'")):
                with pytest.raises(ImportError):
                    convert_markdown_to_html("# Test", output)

    def test_pdf_conversion_graceful_degradation(self, tmp_path):
        """测试 PDF 转换优雅降级"""
        output = tmp_path / "report.pdf"

        # 模拟所有引擎都不可用
        with patch("src.reporting.format_converter._try_generate_pdf", return_value=None):
            result = convert_markdown_to_pdf(
                SAMPLE_MARKDOWN, output, engine="auto"
            )
            # 应该返回 None 而不是抛出异常
            assert result is None
