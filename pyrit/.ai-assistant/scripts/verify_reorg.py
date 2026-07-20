#!/usr/bin/env python3
"""验证 data/ 目录重组后的正确性"""
import sys
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pyrit_ai300.payloads import PayloadManager

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"

def main():
    # 1. 验证目录结构
    print("=== 目录结构验证 ===")
    assert (DATA_DIR / "owasp").exists(), "owasp/ must exist"
    assert not (DATA_DIR / "by_surface").exists(), "by_surface/ must be removed"
    assert (DATA_DIR / "surfaces").exists(), "surfaces/ must exist"
    print("OK: 目录结构正确")

    # 2. 验证 PayloadManager 加载
    print("\n=== PayloadManager 加载验证 ===")
    manager = PayloadManager()
    manager.load_data_dir(str(DATA_DIR))

    refs = manager.get_all_refs()
    print(f"Total refs: {len(refs)}")
    assert len(refs) > 0, "Must load payloads"

    cats = manager.list_categories()
    print(f"Categories: {cats}")
    assert "owasp" in cats, "owasp must be in categories"
    assert "by_surface" not in cats, "by_surface must NOT be in categories"
    print("OK: 类别结构正确")

    # 3. 验证 surfaces 查询
    print("\n=== Surfaces 查询验证 ===")
    for surface in ["rag", "mcp", "agent", "embedding"]:
        payloads = manager.get_payloads_by_surface(surface)
        print(f"  {surface}: {len(payloads)} payloads")
        assert len(payloads) > 0, f"{surface} must have payloads"
    print("OK: surfaces 查询正常")

    # 4. 验证 chapters 查询
    print("\n=== Chapters 查询验证 ===")
    for ch in ["Ch3", "Ch4", "Ch5", "Ch6", "Ch7", "Ch8"]:
        payloads = manager.get_payloads_by_chapter(ch)
        print(f"  {ch}: {len(payloads)} payloads")
        assert len(payloads) > 0, f"{ch} must have payloads"
    print("OK: chapters 查询正常")

    # 5. 验证 stats
    print("\n=== 统计信息 ===")
    stats = manager.get_stats()
    print(f"  Files: {stats['total_files']}")
    print(f"  Payloads: {stats['total_payloads']}")
    print(f"  Categories: {list(stats['by_category'].keys())}")
    assert stats['total_payloads'] > 500, "Should have 500+ payloads"
    print("OK: 统计信息正常")

    # 6. 验证 surfaces 文档
    print("\n=== Surfaces 文档验证 ===")
    surfaces_dir = DATA_DIR / "surfaces"
    for doc in ["README.md", "rag.md", "mcp.md", "agent.md", "embedding.md"]:
        doc_path = surfaces_dir / doc
        assert doc_path.exists(), f"{doc} must exist"
        content = doc_path.read_text(encoding='utf-8')
        assert len(content) > 100, f"{doc} should have content"
    print("OK: surfaces 文档完整")

    # 7. 验证 payload 文件元数据
    print("\n=== Payload 元数据验证 ===")
    import yaml
    owasp_dir = DATA_DIR / "owasp"
    files_with_metadata = 0
    files_without_metadata = 0
    for yml in owasp_dir.rglob("*.yaml"):
        if yml.name.startswith("_"):
            continue
        with open(yml, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if data and 'surfaces' in data and 'ai300_chapters' in data:
            files_with_metadata += 1
        else:
            files_without_metadata += 1
            print(f"  MISSING: {yml.relative_to(DATA_DIR)}")
    print(f"  With metadata: {files_with_metadata}")
    print(f"  Without metadata: {files_without_metadata}")
    assert files_with_metadata > 0, "Must have files with metadata"
    print("OK: 元数据验证完成")

    print("\n" + "=" * 50)
    print("ALL CHECKS PASSED")
    print("=" * 50)

if __name__ == "__main__":
    main()
