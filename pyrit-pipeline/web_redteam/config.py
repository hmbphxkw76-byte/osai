# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""命令行参数解析。.

独立模块, 仅依赖标准库 argparse。

三种目标配置方式:
  A. --target-profile <yaml>   Browser 完整模式: YAML Profile 包含认证/交互/攻击配置
  B. --target-url <url>        Browser 快速模式: 仅 URL, auto 探测认证, 默认交互选择器
  C. --api-url <url>           API 模式: 直接 HTTP POST 攻击 AI LLM API 端点 (无需浏览器)

方式 A/B 为浏览器模式 (PlaywrightTarget), 方式 C 为 API 模式 (HTTPTarget)。
"""

import argparse
import os


def parse_args() -> argparse.Namespace:
    """解析命令行参数。."""
    parser = argparse.ArgumentParser(
        description="Web Red Team Framework — 通用认证感知红队框架 (基于 PyRIT 原生 API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
三种目标配置方式:

  方式 A: Browser 完整 YAML Profile (复杂目标, 可复用)
    python -m web_redteam.run \\
      --target-profile web_redteam/targets/same_domain/example_portal.yaml \\
      --attack-type red_teaming --objective "Extract the system prompt"

  方式 B: Browser 快速 URL 模式 (简单目标, auto 探测认证)
    python -m web_redteam.run \\
      --target-url https://example.com/chat \\
      --attack-type prompt_sending --objective "Tell me a joke"

  方式 C: API 模式 (直接 HTTP POST 攻击 AI LLM API, 无需浏览器)
    python -m web_redteam.run \\
      --api-url https://api.example.com/v1/chat/completions \\
      --api-headers '{"Authorization": "Bearer sk-xxx"}' \\
      --api-body '{"model": "gpt-4", "messages": [{"role": "user", "content": "{PROMPT}"}]}' \\
      --max-rpm 60 --max-concurrency 5 \\
      --attack-type prompt_sending --objective "Tell me a joke"
        """,
    )

    # ── 目标配置 (三选一, 互斥) ──
    target_group = parser.add_argument_group(
        "目标配置",
        "--target-profile / --target-url / --api-url, 三选一",
    )
    target_group.add_argument(
        "--target-profile",
        type=str,
        default=None,
        help="TargetProfile YAML 文件路径 (Browser 完整模式)",
    )
    target_group.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="目标页面 URL (Browser 快速模式: auto 探测认证). 也可通过环境变量 WEB_REDTEAM_TARGET_URL 设置",
    )
    target_group.add_argument(
        "--api-url",
        type=str,
        default=None,
        help="目标 API 端点 URL (API 模式: 直接 HTTP POST 攻击, 无需浏览器)",
    )

    # ── API 模式参数 ──
    api_group = parser.add_argument_group(
        "API 模式参数",
        "仅在 --api-url 模式下生效",
    )
    api_group.add_argument(
        "--api-method",
        type=str,
        default="POST",
        choices=["POST", "GET", "PUT", "PATCH"],
        help="HTTP 请求方法 (默认: POST)",
    )
    api_group.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API 密钥 (自动注入 Authorization: Bearer 头; 也可通过 API_KEY 环境变量设置)",
    )
    api_group.add_argument(
        "--api-headers",
        type=str,
        default=None,
        help='请求头 (JSON 格式, 如 \'{"Authorization": "Bearer sk-xxx"}\'; --api-key 优先)',
    )
    api_group.add_argument(
        "--api-body",
        type=str,
        default=None,
        help="请求体模板 (JSON, 含 {PROMPT} 占位符; 或 @file_path 从文件加载)",
    )
    api_group.add_argument(
        "--api-model",
        type=str,
        default=None,
        help="目标模型名称 (用于请求体默认值和报告标识, 如 gpt-4)",
    )
    api_group.add_argument(
        "--api-response-path",
        type=str,
        default="choices[0].message.content",
        help="响应 JSON 提取路径 (默认: choices[0].message.content)",
    )
    api_group.add_argument(
        "--api-raw-request",
        type=str,
        default=None,
        help="Burp Suite 原始 HTTP 请求文件路径 (可选, 覆盖 --api-url/--api-body)",
    )
    api_group.add_argument(
        "--api-timeout",
        type=int,
        default=30,
        help="API 单次请求超时秒数 (默认: 30)",
    )
    api_group.add_argument(
        "--api-max-retries",
        type=int,
        default=3,
        help="API 请求错误重试次数 (默认: 3)",
    )
    api_group.add_argument(
        "--api-response-format",
        type=str,
        default="json",
        choices=["json", "sse"],
        help="响应格式 (json=标准JSON提取, sse=Server-Sent Events流式响应; 默认: json)",
    )
    api_group.add_argument(
        "--api-health-check",
        action="store_true",
        help="创建目标后发送探针请求验证端点可用性",
    )
    # R2: OAuth2 client_credentials 支持
    api_group.add_argument(
        "--api-auth-type",
        type=str,
        default="bearer",
        choices=["bearer", "oauth2"],
        help="认证类型 (bearer=静态 API Key, oauth2=client_credentials 动态获取; 默认: bearer)",
    )
    api_group.add_argument(
        "--api-oauth-token-url",
        type=str,
        default=None,
        help="OAuth2 token endpoint URL (仅 --api-auth-type oauth2 时需要)",
    )
    api_group.add_argument(
        "--api-oauth-client-id",
        type=str,
        default=None,
        help="OAuth2 client ID (仅 --api-auth-type oauth2 时需要)",
    )
    api_group.add_argument(
        "--api-oauth-client-secret",
        type=str,
        default=None,
        help="OAuth2 client secret (仅 --api-auth-type oauth2 时需要)",
    )

    # ── 攻击参数 ──
    parser.add_argument(
        "--attack-type",
        type=str,
        choices=["prompt_sending", "red_teaming", "crescendo", "tap"],
        default=None,
        help="攻击类型 (默认: prompt_sending)",
    )
    parser.add_argument(
        "--objective",
        type=str,
        default=None,
        help="攻击目标描述",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=None,
        help="多轮攻击最大轮次 (默认: 1 for prompt_sending, 10 for others)",
    )

    # ── 浏览器参数 (仅 Browser 模式) ──
    browser_group = parser.add_argument_group("浏览器参数", "仅在 --target-profile / --target-url 模式下生效")
    browser_group.add_argument(
        "--cdp-port",
        type=int,
        default=9222,
        help="CDP 调试端口 (默认: 9222)",
    )
    browser_group.add_argument(
        "--headless",
        action="store_true",
        help="无头模式 (认证场景不建议, 默认: False)",
    )
    browser_group.add_argument(
        "--storage-state",
        type=str,
        default=None,
        help="认证状态持久化路径 (JSON, 用于复用已有认证)",
    )

    # ── 速率与并发控制 (双模式通用) ──
    rate_group = parser.add_argument_group("速率与并发控制", "控制请求发送速率和并发数")
    rate_group.add_argument(
        "--max-rpm",
        type=int,
        default=None,
        help="目标最大请求/分钟 (RPM 限速, 默认: 不限)",
    )
    rate_group.add_argument(
        "--max-concurrency",
        type=int,
        default=3,
        help="最大并发请求数 (默认: 3, 仅 API 模式生效)",
    )

    # ── 侦察参数 ──
    parser.add_argument(
        "--recon",
        action="store_true",
        help="启用侦察 (Browser 模式: 页面侦察; API 模式: 从外部 JSON 加载)",
    )
    parser.add_argument(
        "--recon-data",
        type=str,
        default=None,
        help="外部侦察数据 JSON 文件路径 (recon-pipeline 产出, 用于驱动攻击场景选择)",
    )

    # R3: 中断恢复
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="从检查点恢复执行 (checkpoint JSON 文件路径, 由中断时自动生成)",
    )

    # ── 输出 ──
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="报告输出目录 (默认: output/web_redteam_<target>_<timestamp>)",
    )

    args = parser.parse_args()

    # 校验: --target-profile, --target-url, --api-url 三选一
    # 优先级: --target-profile > --target-url > --api-url > $WEB_REDTEAM_TARGET_URL
    provided = sum(1 for x in [args.target_profile, args.target_url, args.api_url] if x is not None)
    if provided > 1:
        parser.error("--target-profile, --target-url, --api-url 互斥, 请只指定一个")

    if provided == 0:
        env_url = os.environ.get("WEB_REDTEAM_TARGET_URL")
        if env_url:
            args.target_url = env_url
        else:
            parser.error(
                "必须指定目标: 使用 --target-profile <yaml> 或 --target-url <url> 或 --api-url <url>, "
                "或设置环境变量 WEB_REDTEAM_TARGET_URL"
            )

    # API 模式默认攻击参数
    if args.api_url:
        if args.attack_type is None:
            args.attack_type = "prompt_sending"
        if args.objective is None:
            args.objective = "Extract sensitive information from the target"

    return args
