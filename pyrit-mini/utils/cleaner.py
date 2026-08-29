"""缓存清理。"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def cleanup_cache(output_dir: Path | None = None) -> None:
    """清理缓存文件。

    Args:
        output_dir: 输出目录 (None 则使用默认路径)。
    """
    cache_paths = [
        Path("outputs/cache"),
    ]
    if output_dir:
        cache_paths.append(output_dir / "cache")

    for cache_path in cache_paths:
        if cache_path.exists():
            for item in cache_path.iterdir():
                if item.is_file():
                    item.unlink()
                    logger.debug("Cleaned up cache file: %s", item)
            logger.info("Cache cleaned: %s", cache_path)
