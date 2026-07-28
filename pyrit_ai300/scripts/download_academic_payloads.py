#!/usr/bin/env python3
"""
学术载荷下载器 CLI
==================

从 JailbreakBench / HarmBench / AdvBench 等学术基准下载高 ASR 攻击载荷到本地。

Usage:
  python download_academic_payloads.py                      # 下载全部高 ASR 数据集
  python download_academic_payloads.py jailbreakbench       # 仅下载 JailbreakBench
  python download_academic_payloads.py --list               # 列出已下载的载荷
  python download_academic_payloads.py --model gpt-4o       # 指定模型（影响 ASR 过滤）

环境变量:
  TARGET_MODEL_FOR_ASR  — 影响下载时的 ASR 过滤阈值
"""

import asyncio
import sys
from pathlib import Path

# Fix Windows terminal Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv(project_root / ".env")


async def main():
    args = sys.argv[1:]

    # --list 模式
    if "--list" in args:
        from src.payloads.payload_downloader import list_local_academic_payloads
        payloads = list_local_academic_payloads()
        if not payloads:
            print("未找到已下载的学术载荷。请先运行下载。")
            return
        print(f"\n{'='*60}")
        print(f"  已下载学术载荷 ({len(payloads)} 个文件)")
        print(f"{'='*60}")
        # 按 Tier 分组
        by_tier = {}
        for p in payloads:
            tier = p["tier"]
            if tier not in by_tier:
                by_tier[tier] = []
            by_tier[tier].append(p)
        for tier in sorted(by_tier.keys()):
            print(f"\n  Tier {tier}:")
            for p in by_tier[tier]:
                print(f"    {p['source']:20s} {p['technique']:30s} {p['seed_count']:4d} seeds  {Path(p['file']).name}")
        total_seeds = sum(p["seed_count"] for p in payloads)
        print(f"\n  总计: {len(payloads)} 文件, {total_seeds} seeds")
        return

    # 解析参数
    datasets = None
    model_name = "gpt-4o"

    import os
    env_model = os.getenv("TARGET_MODEL_FOR_ASR", "")
    if env_model:
        model_name = env_model

    filtered_args = [a for a in args if not a.startswith("--")]
    for a in args:
        if a.startswith("--model="):
            model_name = a.split("=", 1)[1]
        elif a == "--model" and filtered_args:
            model_name = filtered_args[0]
            filtered_args = filtered_args[1:]

    if filtered_args:
        datasets = filtered_args

    from src.payloads.payload_downloader import download_academic_payloads_async
    await download_academic_payloads_async(
        datasets=datasets,
        model_name=model_name,
    )


if __name__ == "__main__":
    asyncio.run(main())
