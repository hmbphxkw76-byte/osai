# -*- coding: utf-8 -*-
# arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection via Documents
# arXiv:2403.07860 - Gong et al., FigStep: Jailbreaking VLMs
# arXiv:2306.13254 - Shayegani et al., Multimodal Cybersecurity Risks
"""document_poisoner — Document payload generator for indirect injection attacks.

Closes Gap: Generate poisoned PDF/DOCX/Markdown files with embedded attack
instructions that execute when processed by AI document parsers.

3 Poison Channels:
    1. PDF Metadata Injection — Hide directives in PDF metadata fields
    2. DOCX Macro Injection — Embed attack instructions in document macros
    3. Markdown Watermark — Invisible Unicode directives in markdown

Academic basis:
    - Greshake et al. (arXiv:2302.12173): Indirect injection ASR 60-90%
    - Shayegani et al. (arXiv:2306.13254): Multimodal document attacks
    - PyRIT (arXiv:2407.01232): Native PDFConverter/WordDocConverter

Constitution compliance:
    - R-NATIVE-1: Uses PyRIT native PDFConverter/WordDocConverter for actual attack
    - R-SIZE: < 300 lines (Glue layer only)
    - C4: No side effects in arm phase (only generation utilities)
    - Glue role: Generates poisoned files consumed by PyRIT attack execution

Data Flow:
    document_poisoner → poisoned_file → PyRIT PDFConverter → PromptSendingAttack
"""
from __future__ import annotations

import logging
import os
import zipfile
from typing import Any

logger = logging.getLogger(__name__)

# === PDF Poisoning ===


def generate_pdf_with_payload(
    payload: str,
    output_path: str,
    *,
    title: str = "Security Assessment Document",
    author: str = "Authorized Security Audit System",
    subject: str = "AI System Security Evaluation",
) -> str:
    """Generate a PDF file with embedded payload in metadata and visible content.

    The payload appears in:
    1. PDF Subject/Keywords metadata fields
    2. Hidden text layer (white-on-white text)

    Academic basis: Greshake et al. (arXiv:2302.12173) indirect injection

    Args:
        payload: Attack instruction to embed
        output_path: Path for generated PDF
        title: Document title (visible)
        author: PDF Author metadata
        subject: PDF Subject metadata (contains payload)

    Returns:
        Absolute path to generated PDF
    """
    try:
        # Try reportlab if available (better PDF generation)
        return _generate_pdf_reportlab(payload, output_path, title, author, subject)
    except ImportError:
        # Fallback: minimal pure-PDF generator
        return _generate_pdf_minimal(payload, output_path, title, author, subject)


def _generate_pdf_reportlab(
    payload: str,
    output_path: str,
    title: str,
    author: str,
    subject: str,
) -> str:
    """Generate PDF using reportlab library."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(output_path, pagesize=A4)
    c.setTitle(title)
    c.setAuthor(author)
    c.setSubject(f"{subject} | {payload[:200]}")

    # Visible content (appears benign)
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, f"Document: {title}")
    c.drawString(100, 720, f"Author: {author}")
    c.drawString(100, 690, "This document is for authorized security review.")

    # Hidden payload (white text on white background)
    c.setFont("Helvetica", 1)
    c.setFillColorRGB(1, 1, 1)  # white
    c.drawString(100, 660, payload)

    c.save()
    logger.info("[DocPoisoner] PDF generated (reportlab): %s", output_path)
    return os.path.abspath(output_path)


def _generate_pdf_minimal(
    payload: str,
    output_path: str,
    title: str,
    author: str,
    subject: str,
) -> str:
    """Generate minimal PDF using pure Python (no external deps).

    Creates a valid PDF 1.4 document with payload in metadata and content.
    """
    # Truncate payload for PDF safety (PDF has limits on string length)
    safe_payload = payload[:500].replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    combined_subject = f"{subject} | {safe_payload[:200]}"

    pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj

4 0 obj
<< /Length {len(safe_payload) + 100} >>
stream
BT
/F1 12 Tf
100 700 Td
({title}) Tj
0 -20 Td
(Author: {author}) Tj
0 -20 Td
(Subject: {combined_subject}) Tj
ET
endstream
endobj

5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

xref
0 6
0000000000 65535 f
000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000266 00000 n
0000000416 00000 n

trailer
<< /Size 6 /Root 1 0 R >>
startxref
495
%%EOF"""

    with open(output_path, "w", encoding="latin-1") as f:
        f.write(pdf_content)

    logger.info("[DocPoisoner] PDF generated (minimal): %s", output_path)
    return os.path.abspath(output_path)


# === DOCX Poisoning ===


def generate_docx_with_payload(
    payload: str,
    output_path: str,
    *,
    visible_text: str = "Security Assessment Document",
    macro_text: str | None = None,
) -> str:
    """Generate a DOCX file with embedded payload.

    The payload appears in:
    1. Document properties (custom properties)
    2. Hidden text (white text)
    3. Optional macro text (if macro_text provided)

    Academic basis: Greshake et al. (arXiv:2302.12173) indirect injection

    Args:
        payload: Attack instruction to embed
        output_path: Path for generated DOCX
        visible_text: Visible document content (appears benign)
        macro_text: Optional VBA macro text

    Returns:
        Absolute path to generated DOCX
    """
    safe_payload = payload[:400].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Placeholder for future VBA macro injection
    _ = macro_text  # Currently unused but reserved for macro_text extension

    # Create minimal DOCX structure using zipfile
    docx_files = {
        "[Content_Types].xml": _content_types_xml(),
        "_rels/.rels": _rels_xml(),
        "word/document.xml": _document_xml(visible_text, safe_payload),
        "word/styles.xml": _styles_xml(),
        "docProps/custom.xml": _custom_props_xml(payload),
    }

    if macro_text:
        docx_files["word/vbaProject.bin"] = b""  # Placeholder for VBA

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in docx_files.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(fname, content)

    logger.info("[DocPoisoner] DOCX generated: %s", output_path)
    return os.path.abspath(output_path)


def _content_types_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>"""


def _rels_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>"""


def _document_xml(visible_text: str, payload: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{visible_text}</w:t></w:r></w:p>
    <w:p><w:r><w:t xml:space="preserve">{payload[:200]}</w:t></w:r></w:p>
  </w:body>
</w:document>"""


def _styles_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/><w:qFormat/>
  </w:style>
</w:styles>"""


def _custom_props_xml(payload: str) -> str:
    safe = payload[:300].replace("&", "&amp;").replace("<", "&lt;")
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" name="AIDirective">
    <vt:lpwstr>{safe}</vt:lpwstr>
  </property>
</Properties>"""


# === Markdown Poisoning ===


def generate_markdown_with_watermark(
    payload: str,
    output_path: str,
    *,
    visible_content: str = "# Security Assessment Report\n\nThis document contains authorized security findings.",
) -> str:
    """Generate a Markdown file with invisible Unicode watermark.

    Uses zero-width characters (U+200B,U+200C,U+200D,U+FEFF) to encode
    payload that invisible to humans but processed by AI parsers.

    Academic basis: Shayegani et al. (arXiv:2306.13254) Unicode watermarks

    Args:
        payload: Attack instruction to watermark
        output_path: Path for generated Markdown
        visible_content: Visible markdown content

    Returns:
        Absolute path to generated Markdown file
    """
    # Encode payload as zero-width characters
    watermark = _encode_zero_width(payload)

    content = f"""{visible_content}

---
*Watermark: {watermark}*
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info("[DocPoisoner] Markdown generated: %s", output_path)
    return os.path.abspath(output_path)


def _encode_zero_width(text: str) -> str:
    """Encode text as zero-width Unicode characters.

    Zero-width chars used:
        U+200B (zero-width space) = binary 0
        U+200C (zero-width non-joiner) = binary 1
        U+200D (zero-width joiner) = separator
    """
    ZERO = "\u200b"
    ONE = "\u200c"
    SEP = "\u200d"

    binary = "".join(format(ord(c), "08b") for c in text[:100])  # limit for safety
    encoded = ""
    for bit in binary:
        encoded += ONE if bit == "1" else ZERO
        encoded += SEP

    return encoded


def decode_zero_width(watermark: str) -> str:
    """Decode zero-width Unicode characters back to text."""
    ZERO = "\u200b"
    ONE = "\u200c"
    SEP = "\u200d"

    # Remove separators and convert to binary
    chars = watermark.replace(SEP, "")
    binary = ""
    for ch in chars:
        if ch == ONE:
            binary += "1"
        elif ch == ZERO:
            binary += "0"

    # Convert binary to text
    text = ""
    for i in range(0, len(binary), 8):
        byte = binary[i : i + 8]
        if len(byte) == 8:
            text += chr(int(byte, 2))

    return text


# === Public API ===


def create_poisoned_document(
    payload: str,
    output_dir: str,
    doc_type: str = "pdf",
) -> dict[str, Any]:
    """Factory function to create poisoned documents.

    Args:
        payload: Attack instruction to embed
        output_dir: Directory for output files
        doc_type: "pdf", "docx", or "markdown"

    Returns:
        Dict with file_path, doc_type, payload_preview
    """
    os.makedirs(output_dir, exist_ok=True)

    if doc_type == "pdf":
        path = os.path.join(output_dir, "poisoned.pdf")
        file_path = generate_pdf_with_payload(payload, path)
    elif doc_type == "docx":
        path = os.path.join(output_dir, "poisoned.docx")
        file_path = generate_docx_with_payload(payload, path)
    elif doc_type == "markdown":
        path = os.path.join(output_dir, "poisoned.md")
        file_path = generate_markdown_with_watermark(payload, path)
    else:
        raise ValueError(f"Unsupported doc_type: {doc_type}")

    return {
        "file_path": file_path,
        "doc_type": doc_type,
        "payload_preview": payload[:100],
        "status": "generated",
    }
