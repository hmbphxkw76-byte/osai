"""report/evidence_manifest.py — 证据包 SHA-256 清单与离线校验（REQ-165 / NFR-18 / R-EVID-1）。

为交付物提供**不可否认性**：对证据目录逐文件计算 SHA-256，产出

    evidence_manifest.json     # 结构化清单（schema_version + files + root_hash）
    evidence_manifest.sha256   # sha256sum 兼容文本行（`<hash>  <relpath>`）

并提供 `verify_evidence_manifest(root)` 离线复算（不依赖网络，NFR-7），用于检出
交付后被篡改的证据文件。

设计约束：
    - 仅标准库（`hashlib` / `json`）—— NEG-4；
    - 幂等：重复生成结果一致（文件顺序确定 + 排除清单自身）。
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
MANIFEST_JSON = "evidence_manifest.json"
MANIFEST_TXT = "evidence_manifest.sha256"

_CHUNK = 1024 * 1024
# 清单自身不参与哈希（否则自引用无解）
_EXCLUDED_NAMES = frozenset({MANIFEST_JSON, MANIFEST_TXT})


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Streamed SHA-256 of a file (memory-safe for large evidence)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_evidence_files(root: Path) -> list[Path]:
    files = [p for p in root.rglob("*") if p.is_file() and p.name not in _EXCLUDED_NAMES]
    return sorted(files, key=lambda p: str(p.relative_to(root)).replace("\\", "/"))


def build_evidence_manifest(root: str | Path) -> dict[str, Any]:
    """Build the SHA-256 manifest for every file under `root` (sorted, deterministic)."""
    base = Path(root)
    entries: list[dict[str, Any]] = []
    if base.is_dir():
        for path in _iter_evidence_files(base):
            rel = str(path.relative_to(base)).replace("\\", "/")
            try:
                entries.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
            except OSError as e:  # 单文件不可读不得中断清单生成
                logger.warning("[Evidence] 无法哈希 %s: %s", rel, e)

    root_hash = sha256_bytes(
        "\n".join(f"{e['path']}:{e['sha256']}" for e in entries).encode("utf-8")
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(base),
        "count": len(entries),
        "root_hash": root_hash,
        "files": entries,
    }


def write_evidence_manifest(root: str | Path) -> dict[str, Any]:
    """Write `evidence_manifest.json` + `.sha256` into `root`; returns the manifest."""
    base = Path(root)
    base.mkdir(parents=True, exist_ok=True)
    manifest = build_evidence_manifest(base)

    (base / MANIFEST_JSON).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (base / MANIFEST_TXT).write_text(
        "\n".join(f"{e['sha256']}  {e['path']}" for e in manifest["files"]) + ("\n" if manifest["files"] else ""),
        encoding="utf-8",
    )
    logger.info("[Evidence] manifest written: %d files, root_hash=%s", manifest["count"], manifest["root_hash"][:16])
    return manifest


def verify_evidence_manifest(root: str | Path) -> dict[str, Any]:
    """Recompute hashes and report mismatches (offline tamper check).

    Returns:
        {"valid": bool, "checked": int, "missing": [..], "mismatched": [..], "unexpected": [..]}
    """
    base = Path(root)
    manifest_path = base / MANIFEST_JSON
    if not manifest_path.is_file():
        return {"valid": False, "reason": "manifest_not_found", "checked": 0, "missing": [], "mismatched": [], "unexpected": []}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"valid": False, "reason": "manifest_invalid_json", "checked": 0, "missing": [], "mismatched": [], "unexpected": []}

    expected: dict[str, str] = {str(e["path"]): str(e["sha256"]) for e in manifest.get("files", [])}
    actual_paths = {str(p.relative_to(base)).replace("\\", "/"): p for p in _iter_evidence_files(base)}

    missing: list[str] = []
    mismatched: list[str] = []
    for rel, digest in expected.items():
        path = actual_paths.get(rel)
        if path is None:
            missing.append(rel)
            continue
        try:
            if sha256_file(path) != digest:
                mismatched.append(rel)
        except OSError:
            missing.append(rel)

    unexpected = sorted(set(actual_paths) - set(expected))
    return {
        "valid": not missing and not mismatched,
        "reason": "ok" if not missing and not mismatched else "integrity_violation",
        "checked": len(expected),
        "missing": missing,
        "mismatched": mismatched,
        "unexpected": unexpected,
    }
