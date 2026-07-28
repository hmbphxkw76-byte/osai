#!/usr/bin/env python3
"""
PyRIT 端到端全自动 AI 红队框架 — 主入口
========================================

Usage:
  python main.py                              # 使用 .env 中的目标
  python main.py http://192.168.0.22:11434    # 指定目标 URL
  python main.py http://192.168.0.22:11434 LLM01,LLM06  # 指定 OWASP IDs
"""

import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def main():
    """主入口"""
    project_root = Path(__file__).parent
    env_path = project_root / ".env"
    load_dotenv(env_path)
    print(f"加载环境变量: {env_path}")

    # 获取目标 URL
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_endpoint = os.getenv("TARGET_ENDPOINT", "http://localhost:11434/v1")
        target_url = target_endpoint[:-3] if target_endpoint.endswith("/v1") else target_endpoint

    # 解析 OWASP IDs
    owasp_ids = None
    if len(sys.argv) > 2:
        owasp_ids = [x.strip().upper() for x in sys.argv[2].split(",") if x.strip()]
        print(f"CLI 指定 OWASP IDs: {owasp_ids}")

    # 运行 pipeline
    from pipeline import run_attack_pipeline
    asyncio.run(run_attack_pipeline(target_url, owasp_ids=owasp_ids))


if __name__ == "__main__":
    main()
