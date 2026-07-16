#!/usr/bin/env python3
"""为顶层聚合 YAML 文件添加 surfaces 和 ai300_chapters 元数据"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

from pathlib import Path

# 顶层聚合文件的元数据映射
TOP_LEVEL_MAPPING = {
    "llm/llm01.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm02.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm03.yaml": {"surfaces": ["rag", "agent"], "ai300_chapters": ["Ch5"]},
    "llm/llm04.yaml": {"surfaces": ["rag"], "ai300_chapters": ["Ch5"]},
    "llm/llm05.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch3", "Ch7"]},
    "llm/llm06.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch3", "Ch4", "Ch7"]},
    "llm/llm07.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch3", "Ch7"]},
    "llm/llm08.yaml": {"surfaces": ["embedding", "rag"], "ai300_chapters": ["Ch5", "Ch6"]},
    "llm/llm09.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3", "Ch5"]},
    "llm/llm10.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3"]},
}

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "owasp"


def add_metadata(rel_path: str, metadata: dict) -> bool:
    file_path = DATA_DIR / rel_path
    if not file_path.exists():
        print(f"  SKIP (not found): {rel_path}")
        return False

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    if 'surfaces:' in content and 'ai300_chapters:' in content:
        print(f"  SKIP (already has metadata): {rel_path}")
        return False

    lines = content.split('\n')
    
    # 找到 description 行，在其后插入
    insert_idx = None
    for i, line in enumerate(lines):
        if line.startswith('description:'):
            insert_idx = i + 1
            break
    
    if insert_idx is None:
        print(f"  SKIP (no description found): {rel_path}")
        return False

    surfaces_str = ", ".join(metadata["surfaces"])
    chapters_str = ", ".join(metadata["ai300_chapters"])
    insert_lines = [
        f"surfaces: [{surfaces_str}]",
        f"ai300_chapters: [{chapters_str}]",
        "",
    ]

    new_lines = lines[:insert_idx] + insert_lines + lines[insert_idx:]
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))
    
    print(f"  OK: {rel_path}")
    return True


def main():
    print(f"Data dir: {DATA_DIR}")
    print(f"Files to process: {len(TOP_LEVEL_MAPPING)}")
    print()
    
    success = 0
    for rel_path, metadata in TOP_LEVEL_MAPPING.items():
        if add_metadata(rel_path, metadata):
            success += 1
    
    print(f"\nDone: {success} updated")


if __name__ == "__main__":
    main()
