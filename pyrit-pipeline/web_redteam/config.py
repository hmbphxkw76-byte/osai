# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""命令行参数解析。.

独立模块, 仅依赖标准库 argparse。
对齐 pipeline/config.py 的设计模式。

两种目标配置方式 (互斥):
  A. --target-profile <yaml>   完整模式: YAML Profile 包含认证/交互/攻击配置
  B. --target-url <url>        快速模式: 仅 URL, auto 探测认证, 默认交互选择器
     也可通过环境变量 WEB_REDTEAM_TARGET_URL 设置
"""

import argparse
import os


def parse_args() -> argparse.Namespace:
    """解析命令行参数。."""
    parser = argparse.ArgumentParser(
        description="Web Red Team Framework — 通用认证感知红队框架 (基于 PyRIT 原生 API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
两种目标配置方式 (互斥, 优先级: --target-profile > --target-url > $WEB_REDTEAM_TARGET_URL):

  方式 A: 完整 YAML Profile (复杂目标, 可复用)
    python -m web_redteam.run \\
      --target-profile web_redteam/targets/same_domain/example_portal.yaml \\
      --attack-type red_teaming --objective "Extract the system prompt"

  方式 B: 快速 URL 模式 (简单目标, auto 探测认证)
    python -m web_redteam.run \\
      --target-url https://example.com/chat \\
      --attack-type prompt_sending --objective "Tell me a joke"

  方式 C: 环境变量 (CI/CD 场景)
    # .env 中: WEB_REDTEAM_TARGET_URL=https://example.com/chat
    python -m web_redteam.run --attack-type prompt_sending
        """,
    )

    # ── 目标配置 (二选一) ──
    target_group = parser.add_argument_group("目标配置", "--target-profile 或 --target-url, 二选一")
    target_group.add_argument(
        "--target-profile",
        type=str,
        default=None,
        help="TargetProfile YAML 文件路径 (完整模式: 包含认证/交互/攻击配置)",
    )
    target_group.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="目标页面 URL (快速模式: auto 探测认证, 使用默认交互选择器). 也可通过环境变量 WEB_REDTEAM_TARGET_URL 设置",
    )

    # ── 攻击参数 ──
    parser.add_argument(
        "--attack-type",
        type=str,
        choices=["prompt_sending", "red_teaming", "crescendo", "tap"],
        default=None,
        help="攻击类型 (默认: 使用 Profile 中的 attack_defaults.attack_type)",
    )
    parser.add_argument(
        "--objective",
        type=str,
        default=None,
        help="攻击目标描述 (默认: 使用 Profile 中的 attack_defaults.objective)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=None,
        help="多轮攻击最大轮次 (默认: 使用 Profile 中的 attack_defaults.max_turns)",
    )

    # ── 浏览器参数 ──
    parser.add_argument(
        "--cdp-port",
        type=int,
        default=9222,
        help="CDP 调试端口 (默认: 9222)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="无头模式 (认证场景不建议, 默认: False)",
    )
    parser.add_argument(
        "--storage-state",
        type=str,
        default=None,
        help="认证状态持久化路径 (JSON, 用于复用已有认证)",
    )
    parser.add_argument(
        "--max-rpm",
        type=int,
        default=None,
        help="目标最大请求/分钟 (可选, 用于限速)",
    )

    # ── 侦察参数 ──
    parser.add_argument(
        "--recon",
        action="store_true",
        help="启用 Stage 0 目标侦察 (发现 API 端点 + DOM 注入面 + 攻击推荐)",
    )
    parser.add_argument(
        "--recon-duration",
        type=int,
        default=10,
        help="侦察持续时间 (秒, 默认: 10)",
    )

    # ── 输出 ──
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="报告输出目录 (默认: output/web_redteam_<target>_<timestamp>)",
    )

    args = parser.parse_args()

    # 校验: --target-profile 和 --target-url 二选一
    # 优先级: --target-profile > --target-url > $WEB_REDTEAM_TARGET_URL
    if args.target_profile is None:
        if args.target_url is None:
            env_url = os.environ.get("WEB_REDTEAM_TARGET_URL")
            if env_url:
                args.target_url = env_url
            else:
                parser.error(
                    "必须指定目标: 使用 --target-profile <yaml> 或 --target-url <url>, "
                    "或设置环境变量 WEB_REDTEAM_TARGET_URL"
                )
    elif args.target_url is not None:
        parser.error("--target-profile 和 --target-url 互斥, 请只指定一个")

    return args
