# -*- coding: utf-8 -*-
"""
pyrit-web-recon CLI
===================

统一命令行入口，使用 PipelineRunner 串行执行侦察阶段：

  python main.py <URL> [--type auto|spa|web_ui|api] [--headless] ...

流水线阶段：
  1. credential_discovery   发现已有凭据与浏览器状态
  2. authentication         初始化认证方式
  3. api_probe              API 目标探测（非 API 目标自动跳过）
  4. navigation             启动浏览器并导航到目标
  5. entry_discovery        发现 AI 聊天入口
  6. dom_recon              检测 DOM 元素与登录页
  7. network_interception   拦截 LLM API 网络流量
  8. probe_interaction      发送探测消息触发 LLM API
  9. analysis               分析流量、提取模型名与攻击面
 10. credential_extraction 提取并保存浏览器凭据
 11. export                 导出 TargetProfile / 模板 / PyRIT 配置
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from typing import Any, Dict

import yaml
from dotenv import load_dotenv

from src.pipeline import PipelineContext, PipelineRunner
from src.pipeline.stages import (
    APIProbeStage,
    AnalysisStage,
    AuthenticationStage,
    CredentialDiscoveryStage,
    CredentialExtractionStage,
    DOMReconStage,
    EntryDiscoveryStage,
    ExportStage,
    NavigationStage,
    NetworkInterceptionStage,
    ProbeInteractionStage,
)


def _default_config() -> Dict[str, Any]:
    """默认配置"""
    return {
        "auth_mode": "auto",
        "credentials_dir": "credentials",
        "output_dir": "results/recon",
        "template_dir": "templates/burp",
        "profile_dir": "results/recon/profiles",
        "export_profile": True,
        "export_template": True,
        "export_pyrit": True,
    }


def load_yaml_config(path: str) -> Dict[str, Any]:
    """加载 YAML 配置文件"""
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _env_bool(name: str, default: bool = False) -> bool:
    """从环境变量读取布尔值"""
    value = os.getenv(name, "").lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器（支持 .env 默认值）"""
    parser = argparse.ArgumentParser(
        prog="pyrit-web-recon",
        description="全面侦察基于 LLM 的 Web 应用目标",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=os.getenv("RECON_TARGET_URL", ""),
        help="目标 URL 或站点别名（如 kimi；也可通过 RECON_TARGET_URL 设置）",
    )
    parser.add_argument(
        "--type",
        dest="target_type",
        default=os.getenv("RECON_TARGET_TYPE", "auto"),
        choices=["auto", "spa", "web_ui", "api"],
        help=(
            "LLM 应用目标类型（默认 auto；也可通过 RECON_TARGET_TYPE 设置）。"
            "spa=单页 LLM 聊天应用；web_ui=传统多页 LLM 聊天页面；api=直接暴露的 LLM API。"
        ),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=_env_bool("RECON_HEADLESS"),
        help="无头模式（也可通过 RECON_HEADLESS=true 设置）",
    )
    parser.add_argument("--config", default="config/recon.yaml", help="全局配置文件")
    parser.add_argument("--spa-config", default="config/spa_chat.yaml", help="SPA 配置文件")
    parser.add_argument("--sites", default="config/sites.yaml", help="已知站点配置")
    parser.add_argument(
        "--auth-mode",
        default=os.getenv("RECON_AUTH_MODE", "auto"),
        choices=["auto", "none", "header"],
        help="认证模式（也可通过 RECON_AUTH_MODE 设置）",
    )
    parser.add_argument("--storage-state", default=os.getenv("RECON_STORAGE_STATE", ""), help="浏览器状态文件")
    parser.add_argument(
        "--probe",
        default=os.getenv("RECON_PROBE", "你好，请介绍一下你自己。"),
        help="探测消息（也可通过 RECON_PROBE 设置）",
    )
    parser.add_argument("--no-send", action="store_true", help="不发送探测消息")
    parser.add_argument("--no-template", action="store_true", help="不导出攻击模板")
    parser.add_argument("--no-profile", action="store_true", help="不导出 TargetProfile")
    parser.add_argument("--no-pyrit", action="store_true", help="不导出 PyRIT 配置")
    parser.add_argument(
        "--manual-login",
        action="store_true",
        default=_env_bool("RECON_MANUAL_LOGIN"),
        help="检测到登录页时等待人工完成登录（也可通过 RECON_MANUAL_LOGIN=true 设置）",
    )
    parser.add_argument(
        "--manual-login-timeout",
        type=int,
        default=int(os.getenv("RECON_MANUAL_LOGIN_TIMEOUT", "300")),
        help="人工登录最大等待秒数（默认 300；也可通过 RECON_MANUAL_LOGIN_TIMEOUT 设置）",
    )
    parser.add_argument(
        "--manual-login-require-enter",
        action="store_true",
        default=_env_bool("RECON_MANUAL_LOGIN_REQUIRE_ENTER"),
        help="自动检测到登录完成后仍需按 Enter 确认才继续（默认自动接管）",
    )
    parser.add_argument(
        "--login-url",
        type=str,
        default=os.getenv("RECON_LOGIN_URL", ""),
        help="显式指定登录页 URL（如 https://passport.jd.com；也可通过 RECON_LOGIN_URL 设置）",
    )
    parser.add_argument(
        "--username",
        type=str,
        default=os.getenv("RECON_USERNAME", ""),
        help="登录用户名（也可通过 RECON_USERNAME 设置）",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=os.getenv("RECON_PASSWORD", ""),
        help="登录密码（也可通过 RECON_PASSWORD 设置）",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="详细日志")
    return parser


def _infer_target_type(url: str) -> str:
    """根据 URL 自动推断目标类型"""
    lower = url.lower()
    if any(kw in lower for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/chat/completions"]):
        return "api"
    return "spa"




def _build_pipeline() -> PipelineRunner:
    """构建侦察 Pipeline"""
    stages = [
        CredentialDiscoveryStage(),
        AuthenticationStage(),
        APIProbeStage(),
        NavigationStage(),
        NetworkInterceptionStage(),  # 尽早启动流量拦截
        EntryDiscoveryStage(),
        DOMReconStage(),
        ProbeInteractionStage(),
        AnalysisStage(),
        CredentialExtractionStage(),
        ExportStage(),
    ]
    return PipelineRunner(stages=stages)


async def main():
    """主入口"""
    # 加载 .env 文件，CLI 参数优先级高于环境变量
    load_dotenv()

    parser = build_parser()
    args = parser.parse_args()

    if not args.url:
        parser.error("必须提供目标 URL，或设置 RECON_TARGET_URL 环境变量/.env")

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
    merged_config["spa_config"]["manual_login_require_enter"] = args.manual_login_require_enter
    if args.login_url:
        merged_config["spa_config"]["login_url"] = args.login_url

    # 用户名/密码（用于登录页自动填充，点击登录/验证码仍需人工完成）
    if args.username:
        merged_config["username"] = args.username
    if args.password:
        merged_config["password"] = args.password

    # 认证模式
    merged_config["auth_mode"] = args.auth_mode
    if args.storage_state:
        merged_config["storage_state"] = args.storage_state

    # 导出开关
    if args.no_profile:
        merged_config["export_profile"] = False
    if args.no_template:
        merged_config["export_template"] = False
    if args.no_pyrit:
        merged_config["export_pyrit"] = False

    # 自动推断目标类型
    target_type = args.target_type
    if target_type == "auto":
        target_type = _infer_target_type(target_url)

    # 构建并执行 Pipeline
    context = PipelineContext(
        target_url=target_url,
        target_type=target_type,
        headless=args.headless,
        config=merged_config,
    )

    runner = _build_pipeline()
    final_context = context
    try:
        final_context = await runner.run(context)
    finally:
        # 确保浏览器与网络拦截器被妥善关闭，减少 Windows 下的 pipe 警告
        if final_context.interceptor:
            try:
                await final_context.interceptor.stop()
            except Exception:
                pass
        if final_context.browser_manager:
            try:
                await final_context.browser_manager.close()
            except Exception:
                pass

    # 最终摘要输出
    profile = final_context.profile
    if profile:
        print("\n" + "=" * 70)
        print("  🎯 侦察结果摘要")
        print("=" * 70)
        print(profile.summarize())
        print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())


