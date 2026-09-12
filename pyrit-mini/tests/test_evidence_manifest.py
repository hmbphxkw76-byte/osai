# -*- coding: utf-8 -*-
"""tests/test_evidence_manifest.py — report/evidence_manifest.py 单元测试（证据完整性）。"""

from __future__ import annotations

import tempfile
from pathlib import Path

from report.evidence_manifest import (
    build_evidence_manifest,
    sha256_bytes,
    verify_evidence_manifest,
    write_evidence_manifest,
)


def test_sha256_bytes_deterministic():
    """相同字节 → 相同哈希（取证可复现）。"""
    assert sha256_bytes(b"abc") == sha256_bytes(b"abc")
    assert sha256_bytes(b"abc") != sha256_bytes(b"abd")


def test_build_manifest_records_relative_paths_and_size():
    """build 返回确定性清单：相对路径 + 字节大小 + 哈希。"""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        f = root / "x.txt"
        f.write_text("hello", encoding="utf-8")
        manifest = build_evidence_manifest(root)
        assert manifest["schema_version"] == "1.0"
        assert manifest["count"] == 1
        entry = manifest["files"][0]
        assert entry["path"] == "x.txt"
        assert entry["size"] == 5
        assert entry["sha256"] == sha256_bytes(b"hello")
        # 清单本身被排除（无自引用）
        assert manifest["count"] == 1


def test_write_and_verify_manifest():
    """写入证据后构建清单，再校验应全部通过。"""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "a.txt").write_text("alpha", encoding="utf-8")
        (root / "sub").mkdir()
        (root / "sub" / "b.txt").write_text("beta", encoding="utf-8")

        write_evidence_manifest(root)  # 落地清单文件
        result = verify_evidence_manifest(root)
        assert result["valid"] is True
        assert result["checked"] == 2
        assert result["mismatched"] == []


def test_verify_detects_modification():
    """证据被篡改时校验应标记失败（防篡改 / 防覆盖）。"""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        f = root / "a.txt"
        f.write_text("alpha", encoding="utf-8")
        write_evidence_manifest(root)

        f.write_text("tampered", encoding="utf-8")  # 篡改内容
        result = verify_evidence_manifest(root)
        assert result["valid"] is False
        assert result["mismatched"]
