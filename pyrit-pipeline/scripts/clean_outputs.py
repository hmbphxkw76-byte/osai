# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""清理 outputs/ 目录中的旧报告。.

默认保留最近 7 天的报告, 清理更早的目录。

Usage:
  python scripts/clean_outputs.py           # 保留最近 7 天
  python scripts/clean_outputs.py --days 3 # 保留最近 3 天
  python scripts/clean_outputs.py --dry-run # 仅展示, 不实际删除
"""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime, timedelta
from pathlib import Path


def clean_outputs(output_dir: Path, keep_days: int, dry_run: bool) -> int:
    """清理 outputs/ 目录, 返回清理的目录数。."""
    if not output_dir.exists():
        print(f"输出目录不存在: {output_dir}")
        return 0

    cutoff = datetime.now() - timedelta(days=keep_days)
    cleaned = 0

    for entry in output_dir.iterdir():
        if not entry.is_dir():
            continue
        if entry.name == ".gitkeep":
            continue

        stat_time = datetime.fromtimestamp(entry.stat().st_mtime)
        if stat_time < cutoff:
            if dry_run:
                print(f"  [DRY-RUN] 将删除: {entry.name} (修改于 {stat_time.strftime('%Y-%m-%d %H:%M')})")
            else:
                shutil.rmtree(entry)
                print(f"  已删除: {entry.name} (修改于 {stat_time.strftime('%Y-%m-%d %H:%M')})")
            cleaned += 1

    return cleaned


def main() -> None:
    """入口。."""
    parser = argparse.ArgumentParser(description="清理 outputs/ 目录中的旧报告")
    parser.add_argument("--days", type=int, default=7, help="保留最近 N 天的报告 (默认: 7)")
    parser.add_argument("--dry-run", action="store_true", help="仅展示, 不实际删除")
    parser.add_argument("--output-dir", type=str, default="outputs", help="输出目录 (默认: outputs)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir

    print(f"清理 outputs 目录: {output_dir}")
    print(f"  保留天数: {args.days}")
    print(f"  Dry-run: {args.dry_run}")

    cleaned = clean_outputs(output_dir, args.days, args.dry_run)
    print(f"\n清理完成: {cleaned} 个目录")


if __name__ == "__main__":
    main()
