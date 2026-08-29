"""output — 报告输出目录管理.
"""

from __future__ import annotations

from pathlib import Path


def ensure_output_dir(output_dir: Path | str) -> Path:
    """创建输出目录及子目录.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir
