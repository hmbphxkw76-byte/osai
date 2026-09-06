"""output 鈥?鎶ュ憡杈撳嚭鐩綍绠＄悊.

浠?config.py 涓媶鍒嗗嚭鏉? 涓撻棬澶勭悊鎶ュ憡杈撳嚭鐩綍鐨勫垱寤哄拰绠＄悊.
"""

from __future__ import annotations

from pathlib import Path


def ensure_output_dir(output_dir: Path | str) -> Path:
    """鍒涘缓杈撳嚭鐩綍鍙婂瓙鐩綍.

    瀛愮洰褰?
        - evidence/ 鈥?璇佹嵁鏂囦欢 (evidence.json, EVD-*.json)
        - db/ 鈥?SQLite 鏁版嵁搴?

    Args:
        output_dir: 杈撳嚭鐩綍璺緞.

    Returns:
        鍒涘缓鍚庣殑杈撳嚭鐩綍璺緞銆?
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir

