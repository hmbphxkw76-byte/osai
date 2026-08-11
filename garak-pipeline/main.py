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

# R-012: 始终使用 UTF-8 编码 — 在所有 import 之前强制设置,
# 确保 stdout/stderr 在 Windows GBK 终端下也能正确输出 Unicode 字符
import os as _os
import sys
from pathlib import Path

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import logging

from pipeline.env import configure_hf_mirror, ensure_garak_src_path, load_env
from pipeline.utils import clean_pycache, load_config, prune_old_runs

# 启动时加载项目根 .env（幂等），使 TARGET_USERNAME / OPENAICompatible_API_KEY 等
# 统一从 .env 读取，无需在命令行手动 set。
load_env()

# 规则一（garak 原生优先，不重复造轮子）：把相对路径 ../src/garak-0.15.1
# 注入 sys.path 优先于 site-packages，确保自定义 Probe/Buff/Detector 继承
# 原生源码的基类，便于调试对齐 garak 0.15.1 官方实现。
ensure_garak_src_path()

# 智能选择 HuggingFace 端点：先官方，3 次失败后切换国内镜像 (hf-mirror.com)
# 必须在 garak / huggingface_hub 导入之前执行，确保 HF_ENDPOINT 生效
configure_hf_mirror()


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
  python main.py                                  # 默认: Web 认证模式 (从 .env 读 WEB_TARGET_URL)
  python main.py --openai                         # OpenAI 直连模式 (从 .env 读 OPENAI_TARGET_*)
  python main.py --openai --stage 1-3             # 仅跑前三个阶段
  python main.py --stage 4-5 --run-id 20260802_1530  # 复用历史产物做分析+导出
  python main.py --clean                          # 仅清理 __pycache__
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
        choices=["1", "2", "3", "4", "5", "all", "1-2", "1-3", "1-5", "4-5"],
        help="执行阶段: 1/2/3/4/5/all/1-2/1-3/4-5 [default: all]",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="复用历史 run_id（与 --stage 4-5 配合复用旧批次产物）",
    )
    parser.add_argument(
        "--prune",
        type=int,
        default=None,
        metavar="N",
        help="运行前清理历史产物，仅保留最近 N 个 run_id 批次（如 --prune 5）",
    )
    parser.add_argument(
        "--batch",
        default=None,
        metavar="PATH",
        help="多目标批量扫描配置（如 config/target_list.yaml）",
    )
    parser.add_argument(
        "--profile",
        default=None,
        choices=["full", "balanced", "quick", "smoke"],
        help="扫描档位 [default: 取 yaml 配置]",
    )
    parser.add_argument(
        "--phase",
        default=None,
        choices=["scan", "verify"],
        help="交战阶段: scan=正常扫描(默认), verify=补丁验证(重跑+差异报告)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="断点续扫模式：复用上次 run_id 的 checkpoint，跳过已完成的探针",
    )
    parser.add_argument(
        "--retest",
        default=None,
        metavar="RUN_ID",
        help="re-test diff 模式：对历史 run_id 重新扫描并生成 ASR/DEFCON 差异报告",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default=None,
        choices=[None, "api"],
        help="子命令: api = 启动 REST API 服务（默认无 = 运行扫描流水线）",
    )

    args = parser.parse_args()

    # Phase 5: --phase verify 等价于 --retest（补丁验证集成到主流程）
    if args.phase == "verify" and args.retest is None:
        # 查找最近一个 run_id 作为基线
        import glob as _glob
        analysis_files = sorted(_glob.glob(str(Path(args.artifacts_dir or "outputs") / "04_analysis" / "analysis_*.json")))
        if analysis_files:
            baseline_run_id = Path(analysis_files[-1]).stem.replace("analysis_", "")
            args.retest = baseline_run_id
            print(f"📋 补丁验证模式: 自动选取基线 run_id={baseline_run_id}")
        else:
            print("⚠️  补丁验证模式: 未找到历史分析结果，将执行正常扫描")

    # ---- 日志配置 ----
    # --verbose / -v: 启用 DEBUG 级别日志，否则默认 WARNING
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s:%(name)s:%(message)s",
    )

    # ---- 项目根 & pycache 清理 ----
    project_root = Path(__file__).resolve().parent

    # ---- 仅清理模式 ----
    if args.clean:
        cleaned = clean_pycache(project_root)
        print(f"已清理 {cleaned} 个 __pycache__ 目录")
        sys.exit(0)

    # ---- API 服务模式 ----
    if args.command == "api":
        import uvicorn

        from pipeline.api import app
        from pipeline.env import get_env as _get_env
        if app is None:
            print("错误: FastAPI 不可用，请安装 fastapi + uvicorn")
            sys.exit(1)
        host = _get_env("API_HOST", "0.0.0.0") or "0.0.0.0"
        port = int(_get_env("API_PORT", "8765") or "8765")
        print(f"启动 REST API: http://{host}:{port}")
        uvicorn.run(app, host=host, port=port)

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

    # ---- Judge 配置从 .env 回填 ----
    judge_cfg = config.get("judge", {})
    if not judge_cfg.get("endpoint"):
        judge_cfg["endpoint"] = get_env("JUDGE_ENDPOINT", "")
    if not judge_cfg.get("model") or judge_cfg.get("model") == "gpt-4o-mini":
        judge_cfg["model"] = get_env("JUDGE_MODEL", "gpt-4o-mini")
    judge_api_key = get_env("JUDGE_API_KEY", "")
    if judge_api_key:
        judge_cfg["api_key"] = judge_api_key
    # Judge endpoint 配置了才启用
    if judge_cfg.get("endpoint"):
        judge_cfg["enabled"] = True
    config["judge"] = judge_cfg

    # ---- atkgen 配置从 .env 回填 ----
    atkgen_cfg = config.get("atkgen", {})
    atkgen_enabled_env = get_env("ATKGEN_ENABLED", "")
    if atkgen_enabled_env:
        atkgen_cfg["enabled"] = atkgen_enabled_env.lower() in ("true", "1", "yes")
    atkgen_model_env = get_env("ATKGEN_MODEL_NAME", "")
    if atkgen_model_env:
        atkgen_cfg["red_team_model_name"] = atkgen_model_env
    atkgen_mut_env = get_env("ATKGEN_NUM_MUTATIONS", "")
    if atkgen_mut_env:
        try:
            atkgen_cfg["num_mutations"] = int(atkgen_mut_env)
        except ValueError:
            pass
    config["atkgen"] = atkgen_cfg

    # ---- CLI --profile 覆盖 ----
    if args.profile:
        config.setdefault("execute", {})["scan_profile"] = args.profile

    # ---- Web 认证引导 + 自动适配（默认模式）----
    if not args.openai:
        web_target_url = target.get("target_url", "")
        if not web_target_url:
            print("错误: Web 模式下需要 WEB_TARGET_URL（在 .env 中设置）")
            sys.exit(1)

        # ── Step 1: Playwright 侦察（打开页面 + 发现端点 + 模型名） ──
        discovered_endpoint = ""
        discovered_model = ""
        try:
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
            print(f"启动 Playwright 侦察: {web_target_url}")
            print("  用户名/密码自动填充（.env）；OTP/验证码/滑窗请人工配合")
            profile = bootstrap.run()
            discovered_endpoint = profile.endpoint
            discovered_model = profile.model
            print(f"侦察完成 (认证类型={profile.auth_type})")
            print(f"  发现端点: {discovered_endpoint}")
            print(f"  发现模型: {discovered_model}")
            if profile.has_api_key:
                print(f"  凭据嗅探: {profile.key_source} (长度={len(profile.api_key)})")
        except Exception as exc:
            print(f"⚠️  Playwright 侦察失败: {exc}")
            print("   回退到 HTTP 侦察模式（无浏览器）")

        # ── Step 2: 自动适配（检测 OpenAI 兼容性 → 不兼容则启动适配器） ──
        from pipeline.aivp_adapter import auto_adapt_for_web_target

        # 如果 Playwright 未发现端点，用 target_url 推导
        if not discovered_endpoint:
            from urllib.parse import urlparse as _up
            _p = _up(web_target_url)
            discovered_endpoint = f"{_p.scheme}://{_p.netloc}/api"
            discovered_model = "unknown-model"
            print(f"  回退端点: {discovered_endpoint}")

        adapt_result = auto_adapt_for_web_target(
            discovered_endpoint=discovered_endpoint,
            discovered_model=discovered_model,
            target_url=web_target_url,
        )

        if adapt_result["adapted"]:
            print(f"  ✅ 自动适配: {adapt_result['adapter_url']}")
            print(f"     模型名(自动发现): {adapt_result['model']}")
        else:
            print("  ✅ 端点 OpenAI 兼容，无需适配")

        # 构建最终 target（用适配后的端点 + 自动发现的模型名）
        target = {
            "kind": "openai",
            "endpoint": adapt_result["endpoint"],
            "model": adapt_result["model"],
            "api_key": "none",
            "auth": {"type": "static"},
        }
        config["target"] = target

    # ---- 清理 __pycache__（运行前） ----
    cleaned = clean_pycache(project_root)
    if cleaned:
        print(f"清理 __pycache__: {cleaned} 个目录")

    # ---- 历史产物清理（--prune N：保留最近 N 个 run_id 批次） ----
    if args.prune is not None:
        artifacts_root = Path(config.get("artifacts_dir", "outputs"))
        pruned = prune_old_runs(artifacts_root, keep=args.prune)
        print(f"🗑️  历史产物清理: 删除 {pruned} 个旧批次文件（保留最近 {args.prune} 个）")

    # ---- 多目标批量扫描模式 ----
    if args.batch:
        from pipeline.batch_runner import run_batch

        summary = run_batch(args.batch, project_root=str(project_root))
        sys.exit(0 if summary["failed"] == 0 else 1)

    success = True
    try:
        from pipeline.runner import PipelineRunner

        # --resume: 自动查找最近一个 run_id 的 checkpoint
        effective_run_id = args.run_id
        if args.resume and not effective_run_id:
            import glob
            ckpt_files = sorted(glob.glob(str(Path(artifacts_dir) / "03_execution" / ".checkpoint_*.json")))
            if ckpt_files:
                # 从文件名 .checkpoint_{run_id}.json 提取 run_id
                ckpt_name = Path(ckpt_files[-1]).stem  # e.g. ".checkpoint_20260809_1315"
                effective_run_id = ckpt_name.replace(".checkpoint_", "")
                print(f"📋 断点续扫: 检测到 checkpoint (run_id={effective_run_id})")
            else:
                print("⚠️  未检测到 checkpoint 文件，将从头开始扫描")

        runner = PipelineRunner(
            target=target, mode=mode, artifacts_dir=artifacts_dir,
            config=config, run_id=effective_run_id,
        )
        runner.run(stages=args.stage)
        success = True

        # --retest: 生成 ASR/DEFCON 差异报告
        if args.retest:
            from pipeline.retest_diff import (
                compute_retest_diff,
                load_analysis,
                save_retest_diff,
            )
            baseline = load_analysis(args.retest, artifacts_dir)
            if baseline is None:
                print(f"⚠️  re-test: 未找到历史分析结果 analysis_{args.retest}.json，跳过 diff")
            else:
                current_run_id = effective_run_id or "current"
                current = load_analysis(current_run_id, artifacts_dir)
                if current is None:
                    print(f"⚠️  re-test: 未找到当前分析结果 analysis_{current_run_id}.json，跳过 diff")
                else:
                    diff = compute_retest_diff(baseline, current)
                    diff_path = save_retest_diff(diff, args.retest, current_run_id, artifacts_dir)
                    s = diff["summary"]
                    print(f"\n📊 re-test diff 报告 (baseline={args.retest} → current={current_run_id})")
                    print(f"  ASR 回归: {s['asr_regressions']} 探针, 改善: {s['asr_improvements']} 探针")
                    print(f"  DEFCON 回归: {s['defcon_regressions']} 探针, 改善: {s['defcon_improvements']} 探针")
                    print(f"  Overall DEFCON: {s['baseline_overall_defcon']} → {s['current_overall_defcon']}")
                    print(f"  Worst ASR: {s['baseline_worst_asr']}% → {s['current_worst_asr']}%")
                    print(f"  diff 文件: {diff_path}")
    except Exception as exc:
        success = False
        logging.exception("流水线执行失败")
        print(f"\n流水线中断: {exc}")
    finally:
        clean_pycache(project_root)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
