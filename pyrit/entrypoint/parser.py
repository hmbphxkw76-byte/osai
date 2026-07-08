"""
===============================================================================
PyRIT Red Team — 参数解析器 (v11.0 Streamlined)
===============================================================================
精简原则: "probe 阶段探测到的一切，都不应再让用户手动指定"
精简后: 34 参数 → 18 参数

变更:
  ✅ 删除 --target-api-key --target-model --target-api-format（probe 自动探测）
  ✅ 删除 --target-no-ssl --target-verify-ssl → 合并为 --ssl-skip
  ✅ 删除 --target-user-agent --target-content-type --target-http-method（默认覆盖 95%）
  ✅ 合并 --target-api-key/--target-cookie/--target-jwt/--target-extra-headers → --auth
  ✅ 合并 --payloads/--payload-preset/--payload-vars → --payload
  ✅ --concurrent 默认 0(自动) → probe 自动推算推荐并发

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
    """构建 PyRIT Red Team CLI 参数解析器（精简版）。

    Returns:
        配置完成的 ArgumentParser 实例
    """
    parser = argparse.ArgumentParser(
        description="PyRIT Unified Red Team Platform v11.0 (Streamlined) — "
                    "70 test cases across 3 attack strategies + 2026-hottest attack vectors "
                    "(CoT/Constitution/MCP/A2A/Multimodal) + 17 triple-layer chains",
        epilog=_build_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── 核心参数 (5) ──
    parser.add_argument("--lang", choices=["cn", "en"], default="cn",
                        help="Test suite language: cn=Chinese, en=English (default: cn)")
    parser.add_argument("--target-type", choices=["auto", "model", "app"],
                        default="auto",
                        help="目标类型: auto(智能检测)/model(已知模型API)/app(自定义AI应用)")
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
                        help="Enable auto-gating: skip phases if success rate < --gate-threshold")
    parser.add_argument("--gate-threshold", type=float, default=0.10,
                        help="Success rate threshold for auto-gating, 0.0-1.0 (default: 0.10)")

    # ── 🆕 并发: 0=自动(probe 推算) / >0=手动指定 ──
    parser.add_argument("--concurrent", type=int, default=0,
                        help="Max concurrent API calls (0=auto-detect from probe, default: 0)")

    # ── 目标参数 (5) ──
    parser.add_argument("--target-url", type=str, default="",
                        help="目标 Chat API URL。model 路径仅需 URL+auth；app 路径走完整侦察")
    parser.add_argument("--auth", type=str, default="",
                        help="认证凭证。自动检测格式: JWT(eyJ开头) / Cookie(key=value对) "
                             "/ JSON(自定义头) / API Key(默认Bearer)。示例:\n"
                             "  --auth sk-xxx                → API Key (Bearer)\n"
                             "  --auth eyJhbGciOi...           → JWT Token\n"
                             "  --auth \"session=abc; token=xyz\" → Cookie\n"
                             "  --auth '{\"X-API-Key\":\"sk\"}'    → 自定义Header\n\n"
                             "优先级: --auth > --auth-file > PYRIT_AUTH 环境变量")
    parser.add_argument("--auth-file", type=str, default="",
                        help="从文件读取认证凭证（适合超长 token/JWT）。文件内容作为 --auth 值处理，"
                             "自动检测格式。推荐存放在 configs/tokens/ 目录。示例:\n"
                             "  echo 'gAAAAA...' > configs/tokens/my_jwt.txt\n"
                             "  python main.py --target-url URL --auth-file configs/tokens/my_jwt.txt --phase probe\n\n"
                             "优先级: --auth > --auth-file > PYRIT_AUTH 环境变量")
    parser.add_argument("--ssl-skip", action="store_true", default=False,
                        help="跳过 SSL 证书验证（https:// 目标自动启用，无需手动指定）")
    parser.add_argument("--no-probe", action="store_true", default=False,
                        help="跳过模型自动探测 + 端点枚举 + 架构识别")
    parser.add_argument("--scenario", type=str, default="",
                        choices=[""] + list(SCENARIO_PRESETS.keys()),
                        help="场景预设，一键组合认证/传输参数")

    # ── 载荷参数 (1, 合并 payloads+preset+vars) ──
    parser.add_argument("--payload", type=str, default="",
                        help="载荷规格。自动检测类型:\n"
                             "  --payload stealth              → preset 名称\n"
                             "  --payload /path/to/vars.yaml   → YAML/JSON 文件\n"
                             "  --payload '{\"key\":\"val\"}'     → 内联 JSON 变量")

    # ── 环境与用例 (4) ──
    parser.add_argument("--env-file", type=str, default=".env",
                        help=".env 配置文件路径（默认: .env）")
    parser.add_argument("--case", type=str, default="",
                        help="仅测试指定用例 ID（逗号分隔）")
    parser.add_argument("--exclude-case", type=str, default="",
                        help="排除指定用例 ID（逗号分隔）")
    parser.add_argument("--orch", choices=["pyrit", "legacy"], default="pyrit",
                        help="调度引擎: pyrit(默认, PyRIT原生Orchestrator) / legacy(旧版)")

    # ── 高级参数 (4) ──
    parser.add_argument("--adaptive", action="store_true", default=False,
                        help="启用自适应攻击引擎（动态组合生成 + Bandit 调度 + 厂商载荷 + 混合评分）")
    parser.add_argument("--target-vendor", type=str, default="auto",
                        choices=["auto", "openai", "anthropic", "google", "deepseek", "qwen", "zhipu"],
                        help="目标模型厂商: auto(自动检测)/openai/anthropic/google/deepseek/qwen/zhipu")
    parser.add_argument("--use-dedup-cache", action="store_true", default=False,
                        help="启用请求去重缓存（配合 --adaptive 使用）")
    parser.add_argument("--enable-early-stop", action="store_true", default=False,
                        help="启用贪婪提前终止（配合 --adaptive 使用）")

    # ── 模板模式参数 (2) ──
    parser.add_argument("--exploring-template", type=str, default="",
                        help="[探索模板] 指定 YAML 模板文件，快速测试 converter 链的突破效果")
    parser.add_argument("--penetrating-mode", action="store_true", default=False,
                        help="[渗透模式] 仅需提供提示词模板，系统自动完成全部编排")
    parser.add_argument("--penetrating-template", type=str, default="penetrating_prompts.yaml",
                        help="渗透模式提示词模板文件路径（默认: penetrating_prompts.yaml）")

    # ── [Deprecated] 旧版参数隐藏别名（向下兼容，不显示在 help 中） ──
    parser.add_argument("--mode", choices=["multi", "capstone", "all"], default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)

    return parser


# ── Epilog 使用示例（精简版） ──

def _build_epilog() -> str:
    """构建 CLI 帮助信息的 epilog 使用示例。"""
    return (
        "EXAMPLES:\n"
        "  # 默认语言为中文 (--lang cn)，无需显式指定；英文用 --lang en\n\n"
        "  # [1] 🧠 智能分类: 已知模型 API → 自动跳过侦察，直接模型攻击\n"
        "  python main.py --target-url https://api.openai.com/v1 --auth sk-xxx --phase probe\n\n"
        "  # [2] 🔗 智能分类: 自定义 AI 应用 → 端点枚举 + 架构探测 + 策略推荐\n"
        "  python main.py --target-url http://192.168.2.199:8501/ --phase probe\n\n"
        "  # [3] ⚡ 显式指定走模型攻击路径 (跳过应用侦察)\n"
        "  python main.py --target-url http://192.168.2.199:8501/ --target-type model --auth sk-xxx --phase probe\n\n"
        "  # [4] 🔓 攻击 HTTPS 自签证书的 Chat API (OpenAI 兼容)\n"
        "  python main.py --target-url https://192.168.12.22/chat --ssl-skip --auth sk-xxx --phase probe\n\n"
        "  # [5] 🍪 攻击 HTTP 内网 Web 应用 + Cookie/Session 认证\n"
        "  python main.py --target-url http://192.168.1.100/api/chat --auth \"session_id=abc123;auth_token=xyz\" --phase probe\n\n"
        "  # [6] 🔑 攻击 HTTPS 内部应用 + 自定义认证头\n"
        "  python main.py --target-url https://internal-app/api/v1/query --auth '{\"X-API-Key\":\"sk-secret\"}' --ssl-skip --phase probe\n\n"
        "  # [7] 🔐 JWT Token 认证\n"
        "  python main.py --target-url https://api.internal.com/v1/chat --auth eyJhbGciOi... --phase probe\n\n"
        "  # [8] 🧠 自适应攻击引擎: 动态组合 + Bandit 调度 + 厂商载荷\n"
        "  python main.py --target-url http://192.168.2.199:8501/v1/chat/completions --auth sk-xxx --adaptive --phase single\n\n"
        "  # [9] 🎯 自适应 + 去重缓存 + 提前终止 + 指定厂商\n"
        "  python main.py --target-url http://192.168.2.199:8501/v1/chat/completions --auth sk-xxx --adaptive --target-vendor openai --use-dedup-cache --enable-early-stop --phase all\n\n"
        "  # [10] 🚪 自适应门控攻击\n"
        "  python main.py --target-url http://192.168.2.199:8501/v1/chat/completions --auth sk-xxx --adaptive --auto-gate --phase all\n\n"
        "  # [11] 🧪 自定义载荷: preset / 文件 / 内联 JSON\n"
        "  python main.py --target-url http://192.168.1.100/api/chat --auth sk-xxx --payload stealth --phase probe\n"
        "  python main.py --target-url http://192.168.1.100/api/chat --auth sk-xxx --payload /path/to/vars.yaml --phase probe\n"
        "  python main.py --target-url http://192.168.1.100/api/chat --auth sk-xxx --payload '{\"target\":\"bank\"}' --phase probe\n\n"
        "  # [12] 交互模式：不指定 --target-url → 提示输入目标 URL\n"
        "  python main.py --phase all"
    )
