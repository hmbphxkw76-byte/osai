"""
===============================================================================
PyRIT Red Team — 参数解析器
===============================================================================
从 main.py 提取 argparse 定义，遵循:
  ✅ 单一职责 — 仅负责参数定义和解析
  ✅ 零副作用 — 不执行任何 I/O 或业务逻辑
  ✅ 完整文档 — epilog 包含所有使用示例

使用方式:
  from entrypoint.parser import build_parser

  parser = build_parser()
  args = parser.parse_args()
===============================================================================
"""
from __future__ import annotations

import argparse

from targets import SCENARIO_PRESETS


def build_parser() -> argparse.ArgumentParser:
    """构建 PyRIT Red Team CLI 参数解析器。

    Returns:
        配置完成的 ArgumentParser 实例
    """
    parser = argparse.ArgumentParser(
        description="PyRIT Unified Red Team Platform v10.0 (Phased Execution) — "
                    "70 test cases across 3 attack strategies + 2026-hottest attack vectors "
                    "(CoT/Constitution/MCP/A2A/Multimodal) + 17 triple-layer chains",
        epilog=_build_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── 核心参数 ──
    parser.add_argument("--lang", choices=["cn", "en"], default="cn",
                        help="Test suite language: cn=Chinese, en=English (default: cn)")
    parser.add_argument("--phase", choices=[
        "probe", "single", "crescendo", "pair", "tap", "flip",
        "chunked", "manyshot", "skeleton_key",
        "indirect_inject", "rag_poison", "agent_attack", "embedding_attack",
        "sequence_chain", "mcp_security", "a2a_security", "all",
    ], default="probe",
                        help="Phase: probe/single/crescendo/pair/tap/flip/chunked/manyshot/"
                             "skeleton_key/indirect_inject/rag_poison/agent_attack/embedding_attack/"
                             "sequence_chain/mcp_security/a2a_security/all")
    parser.add_argument("--auto-gate", action="store_true", default=False,
                        help="Enable auto-gating: skip phases if success rate < --gate-threshold (PyRIT best practice)")
    parser.add_argument("--gate-threshold", type=float, default=0.10,
                        help="Success rate threshold for auto-gating, 0.0-1.0 (default: 0.10)")
    parser.add_argument("--concurrent", type=int, default=1,
                        help="Max concurrent API calls (default: 1)")

    # ── 自定义目标参数 ──
    parser.add_argument("--target-url", type=str, default="",
                        help="自定义攻击目标 Chat API URL。仅提供 IP:端口时会自动枚举所有端点")
    parser.add_argument("--target-api-key", type=str, default="",
                        help="自定义目标的 API Key（放在 Authorization: Bearer header 中）")
    parser.add_argument("--target-model", type=str, default="",
                        help="自定义目标的模型名称（放在请求 body 中，默认从 .env 读取）")
    parser.add_argument("--target-api-format", type=str, default="openai",
                        choices=["openai", "gemini", "claude", "raw"],
                        help="API 格式: openai(默认) / gemini / claude / raw(万能回退)")
    parser.add_argument("--scenario", type=str, default="",
                        choices=[""] + list(SCENARIO_PRESETS.keys()),
                        help="场景预设，一键组合认证/传输参数")
    parser.add_argument("--target-no-ssl", action="store_true", default=True,
                        help="跳过 SSL 证书验证（内网自签证书，默认启用）")
    parser.add_argument("--target-verify-ssl", action="store_true", default=False,
                        help="验证 SSL 证书（覆盖 --target-no-ssl）")
    parser.add_argument("--target-extra-headers", type=str, default="",
                        help="自定义 HTTP 请求头，JSON 字符串格式")
    parser.add_argument("--target-cookie", type=str, default="",
                        help="Cookie 字符串，自动转为 Cookie 请求头")
    parser.add_argument("--target-user-agent", type=str, default="",
                        help="自定义 User-Agent（默认使用 Chrome/131 浏览器 UA）")
    parser.add_argument("--target-content-type", type=str, default="application/json",
                        choices=["application/json", "application/x-www-form-urlencoded", "text/plain"],
                        help="POST 请求 Content-Type")
    parser.add_argument("--target-jwt", type=str, default="",
                        help="JWT Token — 快捷方式，自动转为 Authorization: Bearer <jwt>")
    parser.add_argument("--target-http-method", type=str, default="POST",
                        choices=["POST", "GET", "PUT", "DELETE", "PATCH"],
                        help="HTTP 方法: POST(默认) / GET(信息收集/探测)")
    parser.add_argument("--no-probe", action="store_true", default=False,
                        help="跳过模型自动探测 + 端点枚举")
    parser.add_argument("--payloads", type=str, default="",
                        help="Payload 变量文件路径（.json / .yaml / .yml）")
    parser.add_argument("--payload-preset", type=str, default="",
                        help="载荷预设名称（stealth/bruteforce/redteam/academic/minimal）")
    parser.add_argument("--payload-vars", type=str, default="",
                        help="额外 Payload 变量，JSON 字符串，优先级高于 preset 和文件")
    parser.add_argument("--env-file", type=str, default=".env",
                        help=".env 配置文件路径（默认: .env）")
    parser.add_argument("--case", type=str, default="",
                        help="仅测试指定用例 ID（逗号分隔）")
    parser.add_argument("--exclude-case", type=str, default="",
                        help="排除指定用例 ID（逗号分隔）")
    parser.add_argument("--orch", choices=["pyrit", "legacy"], default="pyrit",
                        help="调度引擎: pyrit(默认, PyRIT原生Orchestrator) / legacy(旧版自定义引擎)")
    parser.add_argument("--mode", choices=["multi", "capstone", "all"], default="capstone",
                        help="[Deprecated] Legacy mode flag, use --phase instead")

    # ── 模板模式参数 ──
    parser.add_argument("--exploring-template", type=str, default="",
                        help="[探索模板] 指定 YAML 模板文件，快速测试 converter 链的突破效果")
    parser.add_argument("--penetrating-mode", action="store_true", default=False,
                        help="[渗透模式] 仅需提供提示词模板，系统自动完成全部编排")
    parser.add_argument("--penetrating-template", type=str, default="penetrating_prompts.yaml",
                        help="渗透模式提示词模板文件路径（默认: penetrating_prompts.yaml）")

    return parser


def _build_epilog() -> str:
    """构建 CLI 帮助信息的 epilog 使用示例。"""
    return (
        "EXAMPLES:\n"
        "  # [1] 端点枚举 + 模型探测 + 攻击 (渗透最强全自动化)\n"
        "  python main.py --lang cn --target-url http://192.168.2.199:8501/ --phase probe\n\n"
        "  # [2] 跳过自动探测，手动指定模型\n"
        "  python main.py --lang cn --target-url http://192.168.2.199:8501/ --target-model gpt-4 --phase probe\n\n"
        "  # [3] 跳过自动探测 + raw 格式 (非标准 API)\n"
        "  python main.py --lang cn --target-url http://192.168.2.199:8501/ --target-api-format raw --phase probe --no-probe\n\n"
        "  # [4] 攻击内网自签证书的 Chat API (OpenAI 兼容)\n"
        "  python main.py --lang cn --target-url https://192.168.12.22/chat --phase probe\n\n"
        "  # [5] 攻击 HTTP 内网 Web 应用 + Cookie/Session 认证 (渗透高频场景)\n"
        "  python main.py --lang cn --target-url http://192.168.1.100/api/chat --target-api-format raw --target-cookie \"session_id=abc123; auth_token=xyz\" --phase probe\n\n"
        "  # [6] 攻击 HTTPS 内部应用 + 自定义认证头\n"
        "  python main.py --lang cn --target-url https://internal-app/api/v1/query --target-api-format raw --target-extra-headers '{\"X-API-Key\":\"sk-secret\"}' --target-no-ssl --phase probe\n\n"
        "  # [7] 攻击 Gemini API (非 OpenAI 格式)\n"
        "  python main.py --lang cn --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent --target-api-key YOUR_KEY --target-api-format gemini --phase probe\n\n"
        "  # [8] 攻击 Claude API (非 OpenAI 格式)\n"
        "  python main.py --lang cn --target-url https://api.anthropic.com/v1/messages --target-api-key YOUR_KEY --target-api-format claude --target-model claude-3-sonnet-20240229 --phase probe\n\n"
        "  # [9] 原方式：不指定 --target-url → 探测 .env 中配置的 LLM API\n"
        "  python main.py --lang cn --phase all"
    )
