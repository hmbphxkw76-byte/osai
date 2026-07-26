# -*- coding: utf-8 -*-
"""
pyrit-web-recon CLI
===================

统一命令行入口：
  python main.py <URL> [--type auto|spa|web_ui|api] [--headless] ...
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from typing import Any, Dict

import yaml

from src.credential_manager import CredentialManager
from src.export import ProfileExporter, TemplateExporter
from src.recon import ReconEngine


def _default_config() -> Dict[str, Any]:
    """默认配置"""
    defaults = {
        "auth_mode": "auto",
        "credentials_dir": "credentials",
        "output_dir": "results/recon",
        "template_dir": "data/burp",
        "profile_dir": "results/recon/profiles",
    }
    return defaults


def load_yaml_config(path: str) -> Dict[str, Any]:
    """加载 YAML 配置文件"""
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="pyrit-web-recon",
        description="全面侦察基于 LLM 的 Web 应用目标",
    )
    parser.add_argument("url", help="目标 URL")
    parser.add_argument(
        "--type",
        dest="target_type",
        default="auto",
        choices=["auto", "spa", "web_ui", "api"],
        help="目标类型（默认 auto）",
    )
    parser.add_argument("--headless", action="store_true", help="无头模式")
    parser.add_argument("--config", default="config/recon.yaml", help="全局配置文件")
    parser.add_argument("--spa-config", default="config/spa_chat.yaml", help="SPA 配置文件")
    parser.add_argument("--sites", default="config/sites.yaml", help="已知站点配置")
    parser.add_argument("--auth-mode", default="auto", choices=["auto", "none", "header"], help="认证模式")
    parser.add_argument("--storage-state", default="", help="浏览器状态文件")
    parser.add_argument("--probe", default="你好，请介绍一下你自己。", help="探测消息")
    parser.add_argument("--no-send", action="store_true", help="不发送探测消息")
    parser.add_argument("--no-template", action="store_true", help="不导出攻击模板")
    parser.add_argument("--no-profile", action="store_true", help="不导出 TargetProfile")
    parser.add_argument("--manual-login", action="store_true", help="检测到登录页时等待人工完成登录")
    parser.add_argument("--manual-login-timeout", type=int, default=300, help="人工登录最大等待秒数（默认 300）")
    parser.add_argument("--manual-login-no-enter", action="store_true", help="自动检测登录完成后不等待 Enter 确认")
    parser.add_argument("--login-url", type=str, default="", help="显式指定登录页 URL（如 https://passport.jd.com）")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细日志")
    return parser


async def main():
    """主入口"""
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    defaults = _default_config()
    config = load_yaml_config(args.config)
    spa_config = load_yaml_config(args.spa_config)
    sites_config = load_yaml_config(args.sites)

    # 合并站点配置
    target_url = args.url
    site_config = sites_config.get("sites", {}).get(args.url, {})
    if site_config:
        spa_config.update(site_config.get("spa_config", {}))
        target_url = site_config.get("url", target_url)

    merged_config = {**defaults, **config}
    merged_config["spa_config"] = {**merged_config.get("spa_config", {}), **spa_config}
    merged_config["spa_config"]["send_probe_text"] = args.probe
    if args.no_send:
        merged_config["spa_config"]["enable_probe_send"] = False
    if args.manual_login:
        merged_config["spa_config"]["manual_login"] = True
        merged_config["spa_config"]["manual_login_timeout_ms"] = args.manual_login_timeout * 1000
        merged_config["spa_config"]["manual_login_require_enter"] = not args.manual_login_no_enter
    if args.login_url:
        merged_config["spa_config"]["login_url"] = args.login_url

    # 凭据管理
    cred_manager = CredentialManager(merged_config.get("credentials_dir", "credentials"))
    cred_resolution = cred_manager.resolve(target_url)

    auth_mode = args.auth_mode
    if auth_mode == "auto":
        auth_mode = "header" if cred_resolution.has_credentials else "none"

    if auth_mode == "none":
        cred_resolution.is_valid = True
        cred_resolution.profile = None

    cred_manager.print_status(cred_resolution, auth_mode=auth_mode)

    auth_profile = cred_resolution.profile if cred_resolution.has_credentials else None

    # 启动侦察引擎
    engine = ReconEngine(
        config=merged_config,
        credential_manager=cred_manager,
    )

    profile = await engine.probe(
        url=target_url,
        target_type=args.target_type,
        headless=args.headless,
        auth_profile=auth_profile,
        storage_state=args.storage_state,
    )

    # 输出结果
    print("\n" + "=" * 60)
    print("  🎯 侦察结果")
    print("=" * 60)
    print(profile.summarize())
    print("=" * 60)

    # 导出
    if not args.no_profile:
        exporter = ProfileExporter(merged_config.get("profile_dir", "results/recon/profiles"))
        profile_path = exporter.export(profile, fmt="json")
        print(f"  Profile 导出: {profile_path}")

    if not args.no_template:
        template_exporter = TemplateExporter(merged_config.get("template_dir", "data/burp"))
        template_paths = template_exporter.export(profile)
        for p in template_paths:
            print(f"  模板导出: {p}")

    # 保存 summary
    summary_path = os.path.join(merged_config.get("output_dir", "results/recon"), "latest_summary.txt")
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(profile.summarize())
        f.write("\n\nRaw:\n")
        json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)
    print(f"  摘要保存: {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
