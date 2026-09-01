"""data/ — 测试资产统一入口.

提供 asset_index.yaml 的统一加载接口.
"""

from pathlib import Path

ASSET_INDEX_PATH = Path(__file__).parent / "asset_index.yaml"


def load_asset_index() -> dict:
    """加载 asset_index.yaml."""
    import yaml
    if not ASSET_INDEX_PATH.exists():
        return {}
    with open(ASSET_INDEX_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
