"""main.py — garak 侦察一键启动入口（纯编排）

职责：
    1. 解析 CLI 参数
    2. 加载配置
    3. 清理 __pycache__（防止 stale bytecode）
    4. 委托 Stage1Recon 执行目标侦察
    5. 打印结果

所有子功能从 pipeline 模块导入，本文件不包含任何业务逻辑。
"""

import argparse
import sys
from pathlib import Path

# Windows GBK 终端下 emoji 打印会触发 UnicodeEncodeError，强制 stdout/stderr 为 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from pipeline.utils import clean_pycache, load_config


def main() -> None:
    # ---- CLI 参数 ----
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="garak 目标侦察 — 枚举攻击面 (LLM 安全扫描前置)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                          # 使用 config/target.yaml 默认配置
  python main.py --config my_target.yaml  # 使用自定义配置文件
        """,
    )

    parser.add_argument(
        "--config", "-c",
        default="config/target.yaml",
        help="目标配置文件路径 [default: config/target.yaml]",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="启用详细日志",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=None,
        help="覆盖产物目录",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="仅清理 __pycache__ 后退出（不执行侦察）",
    )
    parser.add_argument(
        "--stage",
        default="all",
        choices=["1", "2", "3", "4", "5", "all", "1-3", "1-5"],
        help="执行阶段: 1(侦察)/2(配置)/3(攻击)/4(分析)/5(报告导出)/all(全链路)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="指定 run_id（analyze/export 复用历史批次，默认取最新时间戳）",
    )
    parser.add_argument(
        "--profile",
        default=None,
        choices=["full", "balanced", "quick"],
        help="覆盖 config 的 scan_profile（效果×时间权衡档位）",
    )

    args = parser.parse_args()

    # ---- 项目根 & pycache 清理规则 ----
    project_root = Path(__file__).resolve().parent

    # ---- 仅清理模式 ----
    if args.clean:
        cleaned = clean_pycache(project_root)
        print(f"🧹 已清理 {cleaned} 个 __pycache__ 目录")
        sys.exit(0)

    # ---- 加载配置 ----
    config = load_config(args.config)
    target = config["target"]
    mode = config.get("mode", "standard")
    artifacts_dir = args.artifacts_dir or config.get("artifacts_dir", "outputs")

    # ---- CLI --profile 覆盖 config 的 scan_profile ----
    if args.profile:
        config.setdefault("execute", {})["scan_profile"] = args.profile

    # ---- 清理 __pycache__（运行前） ----
    cleaned = clean_pycache(project_root)
    if cleaned:
        print(f"   🧹 清理 __pycache__: {cleaned} 个目录")

    success = True
    try:
        from pipeline.runner import PipelineRunner

        runner = PipelineRunner(
            target=target, mode=mode, artifacts_dir=artifacts_dir, config=config
        )
        runner.run(stages=args.stage)
        success = True
    except Exception as exc:
        success = False
        import logging
        logging.exception("流水线执行失败")
        print(f"\n❌ 流水线中断: {exc}")
    finally:
        # ---- 清理 __pycache__（运行后，异常也执行） ----
        clean_pycache(project_root)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
