#!/usr/bin/env python3
"""Extract text from PDF files"""
import sys
import pymupdf

# Fix Windows encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def extract_pdf(path: str) -> str:
    doc = pymupdf.open(path)
    text = ""
    for i, page in enumerate(doc):
        text += f"\n--- PAGE {i+1} ---\n"
        text += page.get_text()
    doc.close()
    return text

if __name__ == "__main__":
    for pdf_path in sys.argv[1:]:
        text = extract_pdf(pdf_path)
        # Write to file instead of stdout to avoid encoding issues
        out_path = pdf_path.rsplit(".", 1)[0] + "_extracted.txt"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Extracted: {pdf_path} -> {out_path} ({len(text)} chars)")
