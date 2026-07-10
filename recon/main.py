#!/usr/bin/env python3
"""
AI 侦测引擎 (AI Recon) — Phase 1 入口
====================================
Playwright 驱动的 SPA 渲染 + API 端点发现 + 认证流程自动化。
输出 target_profile.json → 供 PyRIT Phase 2 攻击使用。

使用示例:
  # 基础扫描
  python main.py --target https://192.168.0.20

  # 完整 SPA 侦察 + JSON 凭据登录
  python main.py --target https://192.168.0.20 \\
    --login-url https://192.168.0.20/login \\
    --login-cred '{"username":"admin","password":"password"}'

  # CLI 安全输入登录（密码不回显，不保存密码）
  python main.py --target https://192.168.0.20 \\
    --login-url https://192.168.0.20/login \\
    --interactive-login

  # 手动登录 + 自动捕获 Cookie（支持 MFA/验证码等）
  python main.py --target https://192.168.0.20 \\
    --login-url https://192.168.0.20/login \\
    --manual-login

  # 仅 HTTP 模式（无浏览器）
  python main.py --target https://192.168.0.20 --no-spa --dict-scan

  # Cookie 注入模式
  python main.py --target https://192.168.0.20 \\
    --auth-cookie "lab_session=abc123def456"

  # Bearer Token 模式
  python main.py --target https://192.168.0.20 \\
    --auth-bearer "eyJhbGciOiJIUzI1NiIs..."
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# 添加项目根目录到 sys.path（本文件在 recon/ 下）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


async def main():
    parser = argparse.ArgumentParser(
        description="AI Recon — AI 侦测引擎 v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --target https://192.168.0.20
  python main.py --target https://192.168.0.20 --login-cred '{"username":"admin","password":"pass"}'
  python main.py --target https://192.168.0.20 --login-url https://192.168.0.20/login --interactive-login
  python main.py --target https://192.168.0.20 --login-url https://192.168.0.20/login --manual-login
  python main.py --target https://192.168.0.20 --no-spa --dict-scan
  python main.py --target https://api.example.com --auth-bearer "sk-xxx"
        """,
    )

    # ── 目标参数 ──
    parser.add_argument("--target", "-t", required=True,
                        help="目标 URL (如 https://192.168.0.20)")
    parser.add_argument("--output", "-o", default="outputs",
                        help="输出目录 (默认: outputs)")

    # ── 认证参数 ──
    auth_group = parser.add_argument_group("认证参数")
    auth_group.add_argument("--login-url",
                            help="登录页面 URL (如 https://target.com/login)")
    auth_group.add_argument("--login-cred",
                            help='登录凭据 JSON (如 \'{"username":"admin","password":"pass"}\')')
    auth_group.add_argument("--interactive-login", action="store_true",
                            help="CLI 安全输入模式 — 终端提示输入用户名和密码（密码不回显）")
    auth_group.add_argument("--manual-login", action="store_true",
                            help="手动登录模式 — 启动 headed 浏览器，用户手动完成登录后自动捕获 Cookie")
    auth_group.add_argument("--manual-login-timeout", type=int, default=120,
                            help="手动登录最长等待秒数 (默认: 120)")
    auth_group.add_argument("--auth-cookie",
                            help="直接注入的 Cookie (如 'session=abc123')")
    auth_group.add_argument("--auth-bearer",
                            help="Bearer Token")
    auth_group.add_argument("--auth-header",
                            action="append",
                            help="自定义认证头 (如 'X-API-Key: xxx')，可多次使用")

    # ── 功能开关 ──
    feat_group = parser.add_argument_group("功能开关")
    feat_group.add_argument("--no-spa", action="store_true",
                            help="禁用 SPA 渲染 (不使用浏览器)")
    feat_group.add_argument("--no-js-extract", action="store_true",
                            help="禁用 JS 端点提取")
    feat_group.add_argument("--no-traffic", action="store_true",
                            help="禁用流量捕获")
    feat_group.add_argument("--dict-scan", action="store_true",
                            help="启用字典扫描 (较慢但覆盖更多)")
    feat_group.add_argument("--headed", action="store_true",
                            help="显示浏览器窗口 (非 headless 模式)")

    # ── 高级参数 ──
    adv_group = parser.add_argument_group("高级参数")
    adv_group.add_argument("--rate-profile", choices=["stealth", "balanced", "fast"],
                           default="stealth",
                           help="探测速率模式 (stealth=隐身推荐, balanced=平衡, fast=快速; 默认: stealth)")
    adv_group.add_argument("--concurrency", type=int, default=2,
                           help="并发数 (默认: 2, stealth 模式下建议保持不变)")
    adv_group.add_argument("--timeout", type=int, default=30,
                           help="请求超时秒数 (默认: 30)")
    adv_group.add_argument("--verify-ssl", action="store_true",
                           help="验证 SSL 证书 (默认跳过)")
    adv_group.add_argument("--wordlist-llm",
                           help="自定义 LLM 词表文件")
    adv_group.add_argument("--wordlist-web",
                           help="自定义 Web 词表文件")
    adv_group.add_argument("--dump-har", action="store_true",
                           help="导出 HAR 格式网络日志")
    adv_group.add_argument("--profile-only", type=str, metavar="FILE.json",
                           help="仅输出 JSON Schema 定义到文件 (不执行侦测)")

    args = parser.parse_args()

    # ── 仅输出 Schema ──
    if args.profile_only:
        from recon.schema import JSON_SCHEMA
        schema_path = Path(args.profile_only)
        schema_path.parent.mkdir(parents=True, exist_ok=True)
        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(JSON_SCHEMA, f, indent=2, ensure_ascii=False)
        print(f"✅ JSON Schema 已保存到: {schema_path}")
        return

    # ── 解析登录凭据 ──
    login_cred = None
    if args.login_cred:
        # 支持文件路径或内联 JSON
        cred_str = args.login_cred.strip()
        if Path(cred_str).exists():
            with open(cred_str, "r", encoding="utf-8") as f:
                login_cred = json.load(f)
        else:
            login_cred = json.loads(cred_str)

    # ── 解析自定义认证头 ──
    auth_headers = {}
    if args.auth_header:
        for h in args.auth_header:
            if ":" in h:
                key, value = h.split(":", 1)
                auth_headers[key.strip()] = value.strip()

    # ── 确定是否使用浏览器 ──
    use_browser = not args.no_spa
    if args.dict_scan and args.no_spa and not args.no_traffic:
        use_browser = True  # 需要浏览器做流量捕获

    # ── 加载词表 ──
    from recon.scanners.dict_scan import DictScanner
    llm_paths = None
    web_paths = None
    if args.wordlist_llm:
        llm_paths = DictScanner.load_paths_from_file(args.wordlist_llm)
    if args.wordlist_web:
        web_paths = DictScanner.load_paths_from_file(args.wordlist_web)

    # ── 运行引擎 ──
    from recon.engine import ReconEngine

    engine = ReconEngine(
        target_url=args.target,
        login_url=args.login_url or "",
        login_cred=login_cred,
        auth_cookie=args.auth_cookie or "",
        auth_bearer=args.auth_bearer or "",
        auth_headers=auth_headers,
        enable_spa_render=use_browser,
        enable_js_extraction=not args.no_js_extract,
        enable_traffic_capture=not args.no_traffic,
        enable_dict_scan=args.dict_scan,
        headless=not (args.headed or args.manual_login),  # manual-login 强制 headed
        output_dir=args.output,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        rate_profile=args.rate_profile,
        interactive_login=args.interactive_login,
        manual_login=args.manual_login,
        manual_login_timeout=args.manual_login_timeout,
    )

    try:
        profile = await engine.run()

        # 输出摘要
        print()
        print("=" * 60)
        print("  AI Recon — 侦测摘要")
        print("=" * 60)
        print(f"  目标:         {profile.target.base_url}")
        print(f"  Chat API:     {profile.target.chat_api_url or '未发现'}")
        print(f"  API 格式:     {profile.target.api_format}")
        print(f"  端点类型:     {profile.target.endpoint_type}")
        print(f"  模型名称:     {profile.target.model_name or '未识别'}")
        print(f"  SPA:          {profile.spa_info.framework}")
        print(f"  端点数量:     {len(profile.api_endpoints)}")
        print(f"  动态路由:     {len(profile.dynamic_routes)}")
        print(f"  认证方式:     {profile.auth.type}")
        print(f"  推荐并发:     {profile.rate_limit.recommended_concurrency}")
        print(f"  速率模式:     {args.rate_profile}")
        print(f"  验证:         {'通过' if not profile.artifacts.warnings else f'{len(profile.artifacts.warnings)} 个警告'}")
        print("-" * 60)
        print(f"  下一步:")
        if profile.target.chat_api_url:
            print(f"    python main.py --lang cn --target-url {profile.target.chat_api_url} --target-api-format {profile.target.api_format}")
        else:
            print(f"    python main.py --lang cn --target-url {profile.target.base_url} --target-api-format raw")
        print(f"    (或使用 --target-profile 参数导入本 profile)")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 侦测失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        await engine.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
