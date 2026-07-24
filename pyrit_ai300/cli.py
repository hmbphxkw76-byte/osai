#!/usr/bin/env python3
"""
PyRIT AI-300 CLI - 命令行入口
================================

基于 argparse 的标准 CLI，支持选择 OWASP 分类、
自定义并发度、超时等参数。

Usage:
  # 运行全部 OWASP LLM 分类
  python cli.py

  # 仅运行 LLM01 (Prompt Injection)
  python cli.py --owasp llm01

  # 运行 LLM01 + LLM06 组合
  python cli.py --owasp llm01,llm06

  # 指定目标 URL
  python cli.py --target http://192.168.0.22:11434 --owasp llm01

  # 列出所有可用的 OWASP 分类
  python cli.py --list

  # 自定义并发和超时
  python cli.py --owasp llm01 --concurrency 2 --timeout 120
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv


# Fix Windows terminal Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ============================================================
# 常量
# ============================================================

OWASP_LLM_REGISTRY_PATH = Path(__file__).parent / "data" / "owasp" / "llm" / "_registry.yaml"
OWASP_AGENTIC_REGISTRY_PATH = Path(__file__).parent / "data" / "owasp" / "agentic" / "_registry.yaml"

# OWASP LLM Top 10 (2025) 简称映射
OWASP_LLM_INFO = {
    "llm01": "Prompt Injection",
    "llm02": "Sensitive Information Disclosure",
    "llm03": "Supply Chain",
    "llm04": "Data and Model Poisoning",
    "llm05": "Improper Output Handling",
    "llm06": "Excessive Agency",
    "llm07": "System Prompt Leakage",
    "llm08": "Vector and Embedding Weaknesses",
    "llm09": "Misinformation",
    "llm10": "Unbounded Consumption",
}

# OWASP Agentic AI Top 10 (2025) 简称映射
OWASP_ASI_INFO = {
    "asi01": "Goal Hijacking",
    "asi02": "Tool Misuse",
    "asi03": "Identity Abuse",
    "asi04": "Supply Chain (Agentic)",
    "asi05": "Code Execution",
    "asi06": "Agentic Memory Attack",
    "asi07": "Agent Communication",
    "asi08": "Cascading Failures",
    "asi09": "Trust Exploitation",
    "asi10": "Rogue AI Agent",
}


# ============================================================
# 辅助函数
# ============================================================


def load_owasp_registry(path: Path) -> dict:
    """加载 OWASP 注册表"""
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {"categories": {}}


def list_owasp_categories() -> None:
    """列出所有可用的 OWASP 分类"""
    llm_registry = load_owasp_registry(OWASP_LLM_REGISTRY_PATH)
    agentic_registry = load_owasp_registry(OWASP_AGENTIC_REGISTRY_PATH)

    print("\n" + "=" * 60)
    print("  OWASP LLM Top 10 (2025) 可用分类")
    print("=" * 60)

    llm_cats = llm_registry.get("categories", {})
    if not llm_cats:
        for owasp_id, name in OWASP_LLM_INFO.items():
            print(f"  {owasp_id.upper():<8}  {name}")
    else:
        for owasp_id, info in sorted(llm_cats.items()):
            name = info.get("name", "Unknown")
            print(f"  {owasp_id.upper():<8}  {name}")

    print("\n" + "=" * 60)
    print("  OWASP Agentic AI Top 10 (2025) 可用分类")
    print("=" * 60)

    agentic_cats = agentic_registry.get("categories", {})
    if not agentic_cats:
        for owasp_id, name in OWASP_ASI_INFO.items():
            print(f"  {owasp_id.upper():<8}  {name}")
    else:
        for owasp_id, info in sorted(agentic_cats.items()):
            name = info.get("name", "Unknown")
            print(f"  {owasp_id.upper():<8}  {name}")

    print("\n  用法示例:")
    print("    python cli.py --owasp llm01              # 仅 LLM01")
    print("    python cli.py --owasp llm01,llm06        # LLM01 + LLM06")
    print("    python cli.py --owasp asi01              # 仅 ASI01")
    print("    python cli.py --owasp llm01,asi01        # LLM01 + ASI01 组合")
    print("    python cli.py --owasp all                # 全部 (默认)")
    print("=" * 60 + "\n")


def parse_owasp_ids(owasp_str: str) -> list[str] | None:
    """
    解析 --owasp 参数

    支持格式:
      - "llm01"           → ["llm01"]
      - "llm01,llm06"     → ["llm01", "llm06"]
      - "all"             → None (全部)
      - "LLM01,LLM06"     → ["llm01", "llm06"] (自动转小写)
    """
    if not owasp_str or owasp_str.lower() == "all":
        return None

    ids = [s.strip().lower() for s in owasp_str.split(",") if s.strip()]
    return ids if ids else None


def validate_owasp_ids(owasp_ids: list[str] | None) -> list[str] | None:
    """验证 OWASP ID 是否合法"""
    if owasp_ids is None:
        return None

    valid_ids = set(OWASP_LLM_INFO.keys()) | set(OWASP_ASI_INFO.keys())
    invalid = [oid for oid in owasp_ids if oid not in valid_ids]

    if invalid:
        print(f"\n  [!] 无效的 OWASP ID: {', '.join(invalid)}")
        print(f"  [!] 可用 LLM ID: {', '.join(sorted(OWASP_LLM_INFO.keys()))}")
        print(f"  [!] 可用 ASI ID: {', '.join(sorted(OWASP_ASI_INFO.keys()))}")
        sys.exit(1)

    return owasp_ids


# ============================================================
# 参数解析
# ============================================================


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器"""
    parser = argparse.ArgumentParser(
        prog="pyrit-ai300",
        description="PyRIT 端到端全自动 AI 红队框架 - 批量多源提示词攻击",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cli.py                                    # 运行全部 OWASP 分类
  python cli.py --owasp llm01                      # 仅 LLM01 Prompt Injection
  python cli.py --owasp llm01,llm06                # LLM01 + LLM06 组合
  python cli.py --target http://host:11434         # 指定目标
  python cli.py --list                             # 列出可用分类
  python cli.py --owasp llm01 --concurrency 2      # 自定义并发
""",
    )

    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="目标 URL (如 http://192.168.0.22:11434)，默认从 .env 读取",
    )

    parser.add_argument(
        "--owasp", "-o",
        type=str,
        default=None,
        help=(
            "OWASP 分类筛选，逗号分隔 (如 llm01 或 llm01,llm06)，"
            "'all' 表示全部 (默认全部)"
        ),
    )

    parser.add_argument(
        "--list", "-l",
        action="store_true",
        dest="list_categories",
        help="列出所有可用的 OWASP 分类后退出",
    )

    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=None,
        help="最大并发攻击数 (默认从配置文件读取)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="单次攻击超时秒数 (默认从配置文件读取)",
    )

    return parser


# ============================================================
# 主入口
# ============================================================


def main():
    """CLI 主入口"""
    parser = build_parser()
    args = parser.parse_args()

    # --list 模式：列出分类后退出
    if args.list_categories:
        list_owasp_categories()
        return

    # 加载环境变量
    project_root = Path(__file__).parent
    env_path = project_root / ".env"
    load_dotenv(env_path)

    # 解析目标 URL
    target_url = args.target
    if not target_url:
        target_endpoint = os.getenv("TARGET_ENDPOINT", "http://localhost:11434/v1")
        if target_endpoint.endswith("/v1"):
            target_url = target_endpoint[:-3]
        else:
            target_url = target_endpoint

    # 解析 OWASP IDs
    owasp_ids = parse_owasp_ids(args.owasp) if args.owasp else None
    owasp_ids = validate_owasp_ids(owasp_ids)

    # 打印运行信息
    print("\n" + "=" * 60)
    print("  PyRIT AI-300 CLI")
    print("=" * 60)
    print(f"  目标: {target_url}")
    if owasp_ids:
        print(f"  OWASP: {', '.join(oid.upper() for oid in owasp_ids)}")
    else:
        print(f"  OWASP: 全部")
    if args.concurrency:
        print(f"  并发: {args.concurrency}")
    if args.timeout:
        print(f"  超时: {args.timeout}s")
    print("=" * 60)

    # 延迟导入 pipeline（避免 --list 时加载 PyRIT）
    from pipeline import run_attack_pipeline

    # 如果指定了并发/超时，通过环境变量覆盖配置文件
    if args.concurrency:
        os.environ["BATCH_MAX_CONCURRENCY"] = str(args.concurrency)
    if args.timeout:
        os.environ["BATCH_PER_ATTACK_TIMEOUT"] = str(args.timeout)

    # 运行管道
    asyncio.run(run_attack_pipeline(target_url, owasp_ids=owasp_ids))


if __name__ == "__main__":
    main()
