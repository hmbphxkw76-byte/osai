"""output — 报告输出目录管理.

从 config.py 中拆分出来, 专门处理报告输出目录的创建和管理.
"""

from __future__ import annotations

from pathlib import Path


def ensure_output_dir(output_dir: Path | str) -> Path:
    """创建输出目录及子目录.

    子目录:
        - evidence/ — 证据文件 (evidence.json, EVD-*.json)
        - db/ — SQLite 数据库

    Args:
        output_dir: 输出目录路径.

    Returns:
        创建后的输出目录路径。
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir
