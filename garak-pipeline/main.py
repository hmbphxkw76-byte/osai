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

# R-012: 始终使用 UTF-8 编码 — 在所有 import 之前强制设置,
# 确保 stdout/stderr 在 Windows GBK 终端下也能正确输出 Unicode 字符
import os as _os
import sys

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from pipeline.env import load_env
from pipeline.utils import clean_pycache, load_config

# 启动时加载项目根 .env（幂等），使 TARGET_USERNAME / OPENAICompatible_API_KEY 等
# 统一从 .env 读取，无需在命令行手动 set。
load_env()


def _register_shutdown_hooks() -> None:
    """注册进程退出兜底清理：atexit + 信号 handler

    覆盖三类退出路径：
      1. 正常结束（atexit）
      2. Ctrl+C（SIGINT）
      3. SIGTERM（kill / 外部终止）
    无论哪种，都触发 cleanup_garak() 回收 garak report 句柄与速率补丁，
    避免异常中断后资源泄漏（不直接抢救扫描，仅回收）。
    """
    import atexit
    import signal

    from pipeline.stage3_execute import cleanup_garak

    atexit.register(cleanup_garak)

    def _handler(signum, frame):
        logger = logging.getLogger(__name__)
        logger.warning("收到信号 %s，执行兜底清理后退出", signum)
        try:
            cleanup_garak()
        finally:
            # 重新抛默认行为：SIGINT → KeyboardInterrupt，SIGTERM → 退出
            if signum == signal.SIGINT:
                raise KeyboardInterrupt()
            sys.exit(1)

    try:
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):
        # 非主线程 / 不支持信号的平台：忽略，atexit 仍生效
        pass


def main() -> None:
    # ---- 进程退出兜底清理（atexit + 信号）----
    _register_shutdown_hooks()

    # ---- CLI 参数 ----
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="garak LLM 红队全链路扫描",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                         # 默认: Web 认证模式 (从 .env 读 WEB_TARGET_URL)
  python main.py --openai                # OpenAI 直连模式 (从 .env 读 OPENAI_TARGET_*)
  python main.py --openai --stage 1-3    # 仅跑前三个阶段
  python main.py --stage 4-5             # 复用历史产物做分析+导出
        """,
    )

    parser.add_argument(
        "--openai",
        action="store_true",
        help="切换为 OpenAI 直连模式（默认走 Web 认证模式）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="启用详细日志",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=None,
        help="覆盖产物目录 [default: outputs]",
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
        help="执行阶段: 1/2/3/4/5/all [default: all]",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="复用历史 run_id（analyze/export 复用旧批次）",
    )
    parser.add_argument(
        "--profile",
        default=None,
        choices=["full", "balanced", "quick"],
        help="扫描档位 [default: 取 yaml 配置]",
    )

    args = parser.parse_args()

    # ---- 项目根 & pycache 清理 ----
    project_root = Path(__file__).resolve().parent

    # ---- 仅清理模式 ----
    if args.clean:
        cleaned = clean_pycache(project_root)
        print(f"已清理 {cleaned} 个 __pycache__ 目录")
        sys.exit(0)

    # ---- 确定模式：默认 Web，--openai 切换到 OpenAI 直连 ----
    from pipeline.env import get_env

    if args.openai:
        config_path = "config/openai_target.yaml"
        print("模式: OpenAI 直连")
    else:
        config_path = "config/web_target.yaml"
        print("模式: Web 认证")

    # ---- 加载配置 ----
    config = load_config(config_path)
    target = config["target"]
    mode = config.get("mode", "standard")
    artifacts_dir = args.artifacts_dir or config.get("artifacts_dir", "outputs")

    # ---- 必填参数从 .env 回填 ----
    if args.openai:
        target["endpoint"] = target.get("endpoint") or get_env("OPENAI_TARGET_ENDPOINT", "")
        target["model"] = target.get("model") or get_env("OPENAI_TARGET_MODEL", "")
        target["api_key"] = target.get("api_key") or get_env("OPENAICompatible_API_KEY", "")
    else:
        # Web 模式：从 .env 取目标 URL
        web_target_url = target.get("target_url") or get_env("WEB_TARGET_URL", "")
        target["target_url"] = web_target_url

    # ---- CLI --profile 覆盖 ----
    if args.profile:
        config.setdefault("execute", {})["scan_profile"] = args.profile

    # ---- Web 认证引导（默认模式）----
    if not args.openai:
        web_target_url = target.get("target_url", "")
        if not web_target_url:
            print("错误: Web 模式下需要 WEB_TARGET_URL（在 .env 中设置）")
            sys.exit(1)

        from pipeline.auth.bootstrap import AuthBootstrap

        auth_cfg = (config.get("target", {}).get("auth") or {})
        bootstrap = AuthBootstrap(
            web_target_url,
            cfg={
                "username_env": auth_cfg.get("username_env", "TARGET_USERNAME"),
                "password_env": auth_cfg.get("password_env", "TARGET_PASSWORD"),
                "selectors": auth_cfg.get("selectors"),
            },
            sessions_dir=str(Path("sessions")),
        )
        print(f"启动 Playwright 认证引导: {web_target_url}")
        print("  用户名/密码自动填充（.env）；OTP/验证码/滑窗请人工配合")
        profile = bootstrap.run()
        target = profile.to_target_dict()
        config["target"] = target
        print(f"认证完成 (类型={profile.auth_type})")
        print(f"  endpoint: {profile.endpoint}")
        print(f"  model:    {profile.model}")
        if profile.has_api_key:
            print(f"  凭据嗅探: {profile.key_source} (长度={len(profile.api_key)})，后续直连 API")

    # ---- 清理 __pycache__（运行前） ----
    cleaned = clean_pycache(project_root)
    if cleaned:
        print(f"清理 __pycache__: {cleaned} 个目录")

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
        print(f"\n流水线中断: {exc}")
    finally:
        clean_pycache(project_root)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
