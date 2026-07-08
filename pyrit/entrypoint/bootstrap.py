"""
===============================================================================
PyRIT Red Team — 环境引导模块（Bootstrap）v11.0
===============================================================================
精简变化:
  ✅ --auth 自动检测格式 (JWT/Cookie/API Key/自定义Header)
  ✅ --payload 自动检测类型 (preset/文件/内联JSON)
  ✅ --concurrent 默认 0(自动) → probe 推算推荐并发
  ✅ --ssl-skip 替代 --target-no-ssl + --target-verify-ssl

初始化流程:
  1. Memory 初始化（SQLiteMemory + CentralMemory 全局单例）
  2. .env 配置加载与校验
  3. 攻击/评分 Target 构建
  4. Payload 变量加载
  5. Converter 自动发现

使用方式:
  from entrypoint.bootstrap import BootstrapContext, bootstrap_environment

  ctx = await bootstrap_environment(args)
  if ctx is None:
      return  # 初始化失败
===============================================================================
"""
from __future__ import annotations

import json as _json
import os as _os
from dataclasses import dataclass, field
from datetime import datetime

from pyrit.prompt_target import PromptTarget, OpenAIChatTarget
from pyrit.memory import SQLiteMemory, CentralMemory
from rich.console import Console
from rich.panel import Panel

from targets import load_env_config, load_target_preset, create_scorer_target, create_attack_target, build_custom_target
from targets.auto_probe import auto_probe_target_model, auto_probe_target_type
from targets.target_type_probe import TargetTypeResult
from converters import discover_converters, sync_pyrit_converters, GLOBAL_ATTACK_COMBINATIONS, CONVERTER_MAP
from datasets.loader import load_payloads_module, apply_preset
from datasets.vendor_payloads import (
    detect_vendor_from_model_name, get_vendor_payloads, get_vendor_specific_vars,
)  # P0
from executor import PAYLOAD_VARS
from utils import ensure_results_dir, results_path

console = Console()


@dataclass
class BootstrapContext:
    """环境初始化上下文 — 所有模式共享的结构化状态。"""
    attack_target: PromptTarget | None = None
    scorer_target: PromptTarget | None = None
    attacker_config: dict = field(default_factory=dict)
    scorer_config: dict = field(default_factory=dict)
    target_type_result: TargetTypeResult | None = None
    target_type: str = "auto"  # "model" | "app" | "auto"
    db_path: str = ""
    case_filter: list[str] | None = None
    exclude_filter: list[str] | None = None
    combo_filter: list | None = None
    effective_phase: str = "probe"
    target_vendor: str = ""  # P0: 目标厂商检测结果
    use_adaptive_engine: bool = False  # P0: 是否启用自适应引擎
    recommended_concurrency: int = 5  # 🆕 probe 推算的推荐并发数


# ── 🆕 认证凭证自动检测 ──

def normalize_auth_value(auth_raw: str) -> dict:
    """将 --auth 值自动检测并拆分为组件。

    检测规则:
      - 以 'eyJ' 开头               → JWT Token
      - 包含 '=' (key=value 对)     → Cookie / 自定义 Header
      - 有效 JSON 对象              → 自定义 Headers dict
      - 其他                        → API Key (Bearer token)

    Returns:
        dict with keys: api_key, jwt_token, cookie, extra_headers
    """
    if not auth_raw or not auth_raw.strip():
        return {}

    auth_raw = auth_raw.strip()
    result = {}

    # ── JWT 检测: eyJ = base64url("{"alg":"...") ──
    if auth_raw.startswith("eyJ"):
        result["jwt_token"] = auth_raw
        return result

    # ── JSON 检测（自定义 headers dict） ──
    if auth_raw.startswith("{") and auth_raw.endswith("}"):
        try:
            parsed = _json.loads(auth_raw)
            if isinstance(parsed, dict) and parsed:
                result["extra_headers"] = parsed
                return result
        except (_json.JSONDecodeError, ValueError):
            pass

    # ── Cookie / key=value 检测 ──
    if "=" in auth_raw:
        # 分号分隔的多对 → Cookie
        if ";" in auth_raw:
            result["cookie"] = auth_raw
            return result
        # 单对 key=value → 也作 Cookie 处理（常见 Web 应用）
        result["cookie"] = auth_raw
        return result

    # ── 默认: API Key (Bearer token) ──
    result["api_key"] = auth_raw
    return result


# ── 🆕 载荷规格自动检测 ──

def normalize_payload_spec(payload_raw: str) -> dict:
    """将 --payload 值自动检测并拆分为 (file, preset, vars)。

    检测规则:
      - 匹配已知 preset 名               → preset
      - 以 .json/.yaml/.yml 结尾且存在    → file
      - 有效 JSON 对象                    → inline vars
      - 其他                             → file（尝试加载）

    Returns:
        {"file": "", "preset": "", "vars": ""}
    """
    if not payload_raw or not payload_raw.strip():
        return {"file": "", "preset": "", "vars": ""}

    payload_raw = payload_raw.strip()

    # ── 已知 preset 名检测 ──
    KNOWN_PRESETS = {"stealth", "bruteforce", "redteam", "academic", "minimal"}
    if payload_raw.lower() in KNOWN_PRESETS:
        return {"file": "", "preset": payload_raw, "vars": ""}

    # ── JSON 内联变量检测 ──
    if payload_raw.startswith("{") and payload_raw.endswith("}"):
        try:
            _json.loads(payload_raw)
            return {"file": "", "preset": "", "vars": payload_raw}
        except (_json.JSONDecodeError, ValueError):
            pass

    # ── 文件路径检测 ──
    if payload_raw.endswith((".json", ".yaml", ".yml")):
        return {"file": payload_raw, "preset": "", "vars": ""}

    # 默认: 当作文件路径
    return {"file": payload_raw, "preset": "", "vars": ""}


# ── 目标分类 ──

async def _classify_target_type(target_url: str) -> str:
    """智能分类目标类型：已知模型 API vs 自定义 AI 应用。"""
    import httpx
    from urllib.parse import urlparse

    KNOWN_API_HOSTS = {
        "api.openai.com", "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.siliconflow.cn", "open.bigmodel.cn",
        "dashscope.aliyuncs.com", "api.deepseek.com",
        "api.mistral.ai", "api.together.xyz",
        "api.groq.com", "openrouter.ai",
        "localhost", "127.0.0.1",
    }

    try:
        input_host = urlparse(target_url).netloc
        if input_host:
            host_lower = input_host.lower()
            if host_lower in KNOWN_API_HOSTS:
                console.print(
                    f"[dim]🔍 目标 URL 匹配已知模型平台 ({host_lower}) → 识别为已知模型[/dim]"
                )
                return "model"
            for known in KNOWN_API_HOSTS:
                if host_lower.endswith("." + known):
                    console.print(
                        f"[dim]🔍 目标 URL 匹配已知模型平台 ({known} 子域) → 识别为已知模型[/dim]"
                    )
                    return "model"
    except Exception:
        pass

    probe_url = target_url.rstrip("/")
    has_api_path = ("/chat/completions" in probe_url or "/v1/" in probe_url
                    or "/api/chat" in probe_url or "/api/generate" in probe_url)

    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            # ── 先探测 Ollama 特征端点 ──
            ollama_check = await client.get(probe_url + "/api/tags")
            if ollama_check.status_code == 200:
                try:
                    data = ollama_check.json()
                    if isinstance(data, dict) and "models" in data:
                        console.print(
                            "[dim]🔍 探测结果: Ollama API (/api/tags 200) → 识别为已知模型[/dim]"
                        )
                        return "model"
                except Exception:
                    pass

            # ── OpenAI 兼容 POST 探测 ──
            resp = await client.post(
                probe_url if has_api_path else probe_url + "/v1/chat/completions",
                json={
                    "model": "ping",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 1,
                },
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 401, 403):
                try:
                    data = resp.json()
                    if "choices" in data or (
                        "error" in data and "message" in data.get("error", {})
                    ):
                        console.print(
                            f"[dim]🔍 探测结果: OpenAI 兼容 API (HTTP {resp.status_code}) → 识别为已知模型[/dim]"
                        )
                        return "model"
                except Exception:
                    pass

            # ── Ollama /api/chat POST 探测 ──
            ollama_post = await client.post(
                probe_url + "/api/chat",
                json={
                    "model": "ping",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": False,
                },
                headers={"Content-Type": "application/json"},
            )
            if ollama_post.status_code in (200, 401, 403):
                try:
                    data = ollama_post.json()
                    if isinstance(data, dict) and "message" in data:
                        console.print(
                            "[dim]🔍 探测结果: Ollama Chat API (/api/chat responded) → 识别为已知模型[/dim]"
                        )
                        return "model"
                except Exception:
                    pass

            console.print(
                f"[dim]🔍 探测结果: 非标准 API 响应 (HTTP {resp.status_code}) → 识别为自定义应用[/dim]"
            )
    except Exception:
        console.print("[dim]🔍 探测结果: 无法连接到 OpenAI 兼容端点 → 识别为自定义应用[/dim]")

    return "app"


async def bootstrap_environment(args) -> BootstrapContext | None:
    """统一环境初始化入口 — 所有 CLI 模式共享（精简版）。

    Args:
        args: argparse.Namespace CLI 解析结果

    Returns:
        BootstrapContext 或 None（初始化失败时）
    """
    ctx = BootstrapContext()

    # ── 0. 目标 URL 确认 ──
    if not args.target_url:
        console.print(
            "\n[bold cyan]🔗 目标 URL 探测模式[/bold cyan]\n"
            "   默认对目标 Chat API 进行安全探测，请提供目标 URL。\n"
            "   示例: http://192.168.1.100:8501/ 或 https://api.example.com/v1/chat\n"
        )
        target_url = console.input("[bold yellow]请输入目标 URL: [/bold yellow]").strip()
        if not target_url:
            console.print("[bold red]❌ 未提供目标 URL，无法继续[/bold red]")
            return None
        args.target_url = target_url
        console.print(f"[green]✅ 目标 URL 已设置: {args.target_url}[/green]\n")

    # 🆕 协议自动补齐：裸 host:port → http://host:port
    if "://" not in args.target_url:
        args.target_url = f"http://{args.target_url}"
        console.print(f"[dim]🔗 自动补齐协议: [cyan]{args.target_url}[/cyan][/dim]")

    # ── 🆕 Step 0.5: 认证凭证归一化 ──
    normalized_auth = _resolve_auth(args)

    # ── 1. 初始化 PyRIT Memory ──
    ensure_results_dir()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"pyrit_redteam_memory_{ts}.db")
    memory = SQLiteMemory(db_path=db_path)
    CentralMemory.set_memory_instance(memory)
    ctx.db_path = db_path
    console.print(f"[green]✅ PyRIT Memory 已初始化 (SQLiteMemory + CentralMemory)[/green]")
    console.print(f"   [dim]db_path: {db_path}[/dim]")

    # ── 2. 加载 .env 配置 ──
    ctx.attacker_config, ctx.scorer_config = load_env_config(args.env_file)

    # ── 3. 配置校验 ──
    if not _validate_config(args, ctx.attacker_config, ctx.scorer_config,
                            target_type=getattr(args, 'target_type', 'auto')):
        return None

    # ── 3.5. 目标类型智能分类 ──
    cli_target_type = getattr(args, 'target_type', 'auto')
    if cli_target_type and cli_target_type != "auto":
        ctx.target_type = cli_target_type
        console.print(
            f"[bold cyan]🎯 目标类型 (CLI 显式指定): {ctx.target_type.upper()}[/bold cyan]"
        )
    else:
        ctx.target_type = await _classify_target_type(args.target_url)

    from entrypoint.display import print_target_classification
    print_target_classification(ctx.target_type, args.target_url)

    # ── 4. 创建评分器 Target ──
    ctx.scorer_target = create_scorer_target(ctx.scorer_config)

    # ── 5. 创建攻击目标 Target（注入归一化认证） ──
    target_preset = load_target_preset()
    attack_target = await _build_custom_target(args, target_preset, normalized_auth)
    if attack_target is None:
        return None
    ctx.attack_target = attack_target

    # 🆕 从探针结果中提取推荐并发
    if hasattr(args, '_probe_result') and args._probe_result and args._probe_result.discovery_summary:
        ds = args._probe_result.discovery_summary
        ctx.recommended_concurrency = ds.get("recommended_concurrency", 5)
    else:
        ctx.recommended_concurrency = 5

    # 自动并发应用
    _apply_auto_concurrent(args, ctx)

    # 目标架构类型探测（仅 app 路径）
    if ctx.target_type == "app":
        ctx.target_type_result = await auto_probe_target_type(
            args, args.target_url, normalized_auth.get("api_key", "")
        )
    else:
        ctx.target_type_result = None
        console.print(
            "[dim]⏭ 目标类型 = model → 跳过应用层架构探测 (RAG/MCP/Agent/A2A)[/dim]"
        )

    # ── 6. 加载 Payload 模板变量 ──
    console.print(f"[dim]📦 从 Python 模块加载 Payload (lang={args.lang})[/dim]")
    _load_payload_vars(args)

    # ── 7. 自动发现转换器 ──
    n_discovered = discover_converters("converters")
    n_synced = sync_pyrit_converters()
    if n_discovered or n_synced:
        console.print(f"[dim]🔍 自动发现: +{n_discovered} 自定义 + {n_synced} PyRIT 原生转换器[/dim]")

    # ── 8. 攻击特征库概况 ──
    n_converters = len(CONVERTER_MAP)
    n_combos = len(GLOBAL_ATTACK_COMBINATIONS)
    n_triple = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) >= 3)
    n_double = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 2)
    n_single = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 1)
    console.print(
        f"[dim]🎯 攻击特征库: {n_converters} 个转换器 + {n_combos} 组攻击组合 "
        f"(单层: {n_single} | 双层: {n_double} | 三层链: {n_triple})[/dim]"
    )

    # ── 9. 用例过滤 ──
    ctx.case_filter, ctx.exclude_filter, ctx.combo_filter, ctx.effective_phase = \
        _resolve_case_filters(args)

    # ── 10. P0: 自适应引擎 + 厂商检测 ──
    ctx.use_adaptive_engine = getattr(args, 'adaptive', False)

    if ctx.use_adaptive_engine:
        console.print(
            Panel(
                "[bold cyan]🧠 自适应攻击引擎已启用[/bold cyan]\n"
                "[dim]动态组合生成(300+) + Bandit 调度 + 厂商载荷 + 混合评分(0-1)[/dim]",
                style="bold cyan",
            )
        )

    model_name = ""
    if ctx.attacker_config and ctx.attacker_config.get("model"):
        model_name = ctx.attacker_config["model"]
    elif ctx.target_type_result and ctx.target_type_result.model_name:
        model_name = ctx.target_type_result.model_name
    elif hasattr(args, 'target_model') and args.target_model:
        model_name = args.target_model

    # 厂商检测：CLI 显式指定优先，否则自动检测
    vendor_from_cli = getattr(args, 'target_vendor', 'auto')
    if vendor_from_cli and vendor_from_cli != "auto":
        ctx.target_vendor = vendor_from_cli
        console.print(
            f"[bold cyan]🎯 目标厂商 (CLI 指定): {ctx.target_vendor.upper()}[/bold cyan]"
        )
    elif model_name:
        ctx.target_vendor = detect_vendor_from_model_name(model_name)

    if ctx.target_vendor and ctx.target_vendor != "unknown":
        vendor_payloads = get_vendor_payloads(ctx.target_vendor)
        if vendor_payloads:
            console.print(
                f"[bold cyan]🎯 目标厂商检测: {ctx.target_vendor.upper()} "
                f"({vendor_payloads.get('model_family', '')})[/bold cyan]"
            )
            console.print(
                f"   [dim]已知弱点: {', '.join(vendor_payloads.get('known_weaknesses', [])[:3])}...[/dim]"
            )
            console.print(
                f"   [dim]推荐转换器: {', '.join(vendor_payloads.get('recommended_converters', [])[:5])}[/dim]"
            )

        vendor_vars = get_vendor_specific_vars(ctx.target_vendor)
        if vendor_vars:
            PAYLOAD_VARS.update(vendor_vars)

    return ctx


# ── 🆕 认证归一化 ──

def _resolve_auth(args) -> dict:
    """解析认证凭证并归一化为组件，优先级: --auth > --auth-file > PYRIT_AUTH 环境变量。"""
    auth = ""

    # ── 1. CLI --auth（最高优先级）──
    cli_auth = getattr(args, 'auth', '')
    if cli_auth:
        auth = cli_auth
        _log_auth_source("CLI --auth")
    # ── 2. --auth-file（从文件读取）──
    elif getattr(args, 'auth_file', ''):
        auth_file = args.auth_file
        if _os.path.exists(auth_file):
            try:
                with open(auth_file, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f
                             if line.strip() and not line.strip().startswith("#")]
                    auth = lines[0] if lines else ""
                if not auth:
                    console.print(f"[yellow]⚠️ auth-file 无有效内容 (仅含空行/注释): {auth_file}[/yellow]")
                    return {}
                _log_auth_source(f"文件 (--auth-file {auth_file})" + 
                                 (f", 共 {len(lines)} 条有效行, 取首条" if len(lines) > 1 else ""))
            except Exception as e:
                console.print(f"[yellow]⚠️ 读取 auth-file 失败 ({auth_file}): {e}[/yellow]")
                return {}
        else:
            console.print(f"[yellow]⚠️ auth-file 不存在: {auth_file}[/yellow]")
            return {}
    # ── 3. PYRIT_AUTH 环境变量 ──
    else:
        env_auth = _os.getenv("PYRIT_AUTH", "")
        if env_auth:
            auth = env_auth
            _log_auth_source("环境变量 PYRIT_AUTH")

    if not auth:
        return {}

    result = normalize_auth_value(auth)

    labels = []
    if result.get("jwt_token"):
        labels.append("JWT Token")
    if result.get("cookie"):
        labels.append(f"Cookie ({_truncate_auth(result['cookie'])})")
    if result.get("api_key"):
        labels.append(f"API Key ({_truncate_auth(result['api_key'])})")
    if result.get("extra_headers"):
        hdr_names = list(result["extra_headers"].keys())
        labels.append(f"自定义头 ({', '.join(hdr_names[:3])})")

    console.print(f"[bold cyan]🔐 认证检测: {', '.join(labels)}[/bold cyan]")
    return result


def _log_auth_source(source: str) -> None:
    """输出认证凭证来源。"""
    console.print(f"[dim]🔑 认证来源: [cyan]{source}[/cyan][/dim]")


def _truncate_auth(value: str, max_len: int = 12) -> str:
    """截断认证值用于日志显示。"""
    if len(value) <= max_len:
        return value
    return value[:8] + "..." + value[-4:]


def _apply_auto_concurrent(args, ctx: BootstrapContext) -> None:
    """自动应用 probe 阶段推算的推荐并发数。"""
    cli_concurrent = getattr(args, 'concurrent', 0)

    if cli_concurrent > 0:
        # 用户手动指定 → 尊重用户选择
        console.print(
            f"[dim]⚡ 并发数: [cyan]{cli_concurrent}[/cyan] (用户手动指定)[/dim]"
        )
        return

    # auto 模式 (concurrent=0) → 使用 probe 推算
    rec = ctx.recommended_concurrency
    console.print(
        f"[dim]⚡ 并发数: [cyan]{rec}[/cyan] (probe 自动推算)[/dim]"
    )
    if rec != 5:  # 不是默认值时明确提示
        console.print(
            f"   [dim]💡 可通过 --concurrent N 手动覆盖[/dim]"
        )


# ── 配置校验 ──

def _validate_config(args, attacker_config: dict, scorer_config: dict,
                    target_type: str = "auto") -> bool:
    """校验模型配置完整性。"""
    scorer_required = True
    effective_phase = getattr(args, 'phase', 'probe')
    use_adaptive = getattr(args, 'adaptive', False)

    if effective_phase == "probe" and not use_adaptive:
        scorer_required = False

    if not scorer_config or not scorer_config.get("model"):
        if scorer_required:
            console.print(
                "[bold red]❌ 评分器模型未配置！[/bold red]\n"
                "    当前阶段需要评分器评估攻击效果。请在 .env 中配置:\n"
                "      [your_platform]\n"
                "      SCORE_URL=https://api.example.com/v1\n"
                "      SCORE_API=sk-xxx\n"
                "      SCORE_MODEL=gpt-4\n\n"
                "    或使用默认平台 (PLATFORM_SELECTOR):\n"
                "      当前 target_type={target_type}, phase={effective_phase}"
            )
            return False
        else:
            console.print(
                "[yellow]⚠️ 评分器模型未配置 — probe 侦察阶段将不进行自动评分[/yellow]\n"
                "[dim]   如需评分，请在 .env 中配置 SCORE_MODEL[/dim]"
            )
    return True


# ── Target 构建 ──

async def _build_custom_target(args, target_preset: dict | None = None,
                               normalized_auth: dict | None = None):
    """构建自定义 HTTP Target（精简版，含自动探测）。

    Args:
        args: argparse.Namespace CLI 解析结果
        target_preset: 从 .env [TARGET_xxx] 节加载的预设值字典
        normalized_auth: normalize_auth_value() 归一化后的认证字典
    """
    import json

    if target_preset is None:
        target_preset = {}
    if normalized_auth is None:
        normalized_auth = {}

    def _resolve(key: str, default=None):
        cli_val = getattr(args, key, None)
        if cli_val:
            if isinstance(cli_val, str) and cli_val:
                return cli_val
            if not isinstance(cli_val, str) and cli_val is not None:
                return cli_val
        preset_val = target_preset.get(key)
        if preset_val is not None:
            return preset_val
        return default

    effective_url = _resolve("target_url", "")
    if not effective_url:
        console.print("[bold red]❌ 未指定 --target-url 且 TARGET_PRESET 也未设置 TARGET_URL[/bold red]")
        return None

    # 🆕 协议自动补齐：裸 host:port → http://host:port
    if "://" not in effective_url:
        effective_url = f"http://{effective_url}"
        console.print(f"[dim]🔗 自动补齐协议: [cyan]{effective_url}[/cyan][/dim]")

    # 🆕 从归一化 auth 提取（支持 preset TARGET_AUTH 回退）
    if not normalized_auth:
        preset_auth = _resolve("target_auth", "")
        if preset_auth:
            normalized_auth = normalize_auth_value(preset_auth)
            console.print(f"[dim]🔑 认证来源: [cyan]targets.env 预设 (TARGET_AUTH)[/cyan][/dim]")

    effective_api_key = normalized_auth.get("api_key", "") or _resolve("target_api_key", "")
    effective_cookie = normalized_auth.get("cookie", "") or _resolve("target_cookie", "")
    effective_jwt = normalized_auth.get("jwt_token", "") or _resolve("target_jwt", "")
    auth_extra_headers = normalized_auth.get("extra_headers", {}) or {}

    # 🆕 SSL: https:// 目标自动跳过验证（红队场景多自签/内网证书）
    #          显式 --ssl-skip 或 preset TARGET_SSL_SKIP=1 也生效（向后兼容）
    is_https_target = effective_url.lower().startswith("https://")
    is_http_target = effective_url.lower().startswith("http://") or effective_url.lower().startswith("ws://")
    ssl_skip = getattr(args, 'ssl_skip', False) or _resolve("target_ssl_skip", False)
    if is_https_target and not ssl_skip:
        ssl_skip = True
        console.print(f"[dim]🔓 SSL 验证已自动跳过 ({effective_url} 为 HTTPS 目标)[/dim]")
    verify_ssl = not is_http_target and not ssl_skip

    if ssl_skip and not is_http_target:
        console.print("[yellow]⚠️ --ssl-skip: 跳过 SSL 证书验证（自签证书场景）[/yellow]")

    # 🆕 API 格式: 根据目标类型自动推断
    cli_target_type = getattr(args, 'target_type', 'auto')
    if cli_target_type == "model" or (
        cli_target_type == "auto" and await _classify_target_type(effective_url) == "model"
    ):
        effective_api_format = "openai"  # model 路径默认 OpenAI 格式
    else:
        effective_api_format = "raw"  # app 路径默认 raw 格式

    # 但允许 target_preset 覆盖
    if target_preset.get("target_api_format"):
        effective_api_format = target_preset["target_api_format"]

    effective_scenario = _resolve("scenario", "")

    # extra_headers: 合并 auth 检测的 headers + target_preset
    extra_headers = dict(auth_extra_headers)
    raw_extra_headers = _resolve("target_extra_headers", "")
    if raw_extra_headers:
        try:
            preset_headers = json.loads(raw_extra_headers) if isinstance(raw_extra_headers, str) else raw_extra_headers
            extra_headers.update(preset_headers)
        except (json.JSONDecodeError, TypeError):
            pass

    # ── 模型自动探测 + 可达性检查 ──
    effective_model, target_reachable = await auto_probe_target_model(
        args, effective_url, effective_api_key,
        normalized_auth=normalized_auth,
    )
    if not target_reachable:
        return None

    # 🆕 保存 probe 结果以便提取推荐并发
    if hasattr(args, '_probe_result') is False:
        from targets.model_probe import probe_model_info
        result = await probe_model_info(
            target_url=effective_url,
            api_key=effective_api_key or "",
        )
        args._probe_result = result

    # 🆕 自动补齐 Chat API 二级路径（探测到端点类型后）
    effective_url, effective_api_format = _auto_resolve_chat_url(
        effective_url, effective_api_format, args,
    )

    from utils import DEFAULT_MODEL_NAME
    return build_custom_target(
        endpoint=effective_url,
        scenario=effective_scenario,
        api_key=effective_api_key or "",
        model=effective_model or _resolve("target_model", DEFAULT_MODEL_NAME),
        api_format=effective_api_format,
        http_method="POST",
        content_type="application/json",
        verify_ssl=verify_ssl,
        cookie=effective_cookie,
        jwt_token=effective_jwt,
        user_agent="",
        extra_headers=extra_headers if extra_headers else None,
    )


# ── 🆕 自动补齐 Chat API 路径 ──

# 已知的 LLM Chat API 路径（如果 URL 已包含其中任意一个，则无需再拼接）
_KNOWN_CHAT_API_PATHS = (
    "/v1/chat/completions", "/v1/completions", "/v1/chat",
    "/chat/completions", "/completions",
    "/api/chat", "/api/chat/completions", "/api/generate", "/api/v1/chat",
    "/v1/generate",
)

# endpoint_type → (默认 Chat API 路径, API 格式)
_ENDPOINT_CHAT_MAP = {
    "ollama":         ("/api/chat", "ollama"),
    "ollama_compat":  ("/api/chat", "ollama"),
    "openai":         ("/v1/chat/completions", "openai"),
    "json_info":      ("/v1/chat/completions", "openai"),
    "html_info":      ("/v1/chat/completions", "openai"),
    "custom":         ("/v1/chat/completions", "openai"),
}


def _auto_resolve_chat_url(effective_url: str, effective_api_format: str, args) -> tuple[str, str]:
    """自动补齐 Chat API 二级路径。

    当用户输入的是裸 URL（如 http://192.168.0.20:11434/）且探针已识别
    端点类型（ollama/openai 等）时，自动在 URL 后拼接对应的 Chat API 路径。

    Args:
        effective_url: 用户原始提供的目标 URL
        effective_api_format: 当前 API 格式
        args: CLI 参数（含 _probe_result）

    Returns:
        (修正后的 URL, 修正后的 api_format)
    """
    # 检查 URL 是否已包含已知 Chat API 路径
    url_lower = effective_url.lower().rstrip("/")
    for known_path in _KNOWN_CHAT_API_PATHS:
        if url_lower.endswith(known_path.lower()):
            # URL 已包含完整路径，无需处理
            return effective_url, effective_api_format

    # 从探针结果获取端点类型
    probe_result = getattr(args, '_probe_result', None)
    if not probe_result:
        return effective_url, effective_api_format

    endpoint_type = probe_result.endpoint_type or "unknown"
    if endpoint_type == "unknown":
        return effective_url, effective_api_format

    # 查找对应的 Chat API 路径
    entry = _ENDPOINT_CHAT_MAP.get(endpoint_type)
    if not entry:
        return effective_url, effective_api_format

    chat_path, api_format = entry
    resolved_url = f"{effective_url.rstrip('/')}{chat_path}"

    console.print(
        f"[bold cyan]🔗 自动补齐 Chat API 路径[/bold cyan]\n"
        f"   [dim]原始 URL:   {effective_url}[/dim]\n"
        f"   [dim]端点类型:   {endpoint_type}[/dim]\n"
        f"   [bold green]➡ 攻击 URL:   {resolved_url}[/bold green]\n"
        f"   [dim]API 格式:   {api_format}[/dim]"
    )

    return resolved_url, api_format


# ── Payload 加载 ──

def _load_payload_vars(args) -> None:
    """加载 payload 变量到 executor.PAYLOAD_VARS（精简版）。

    支持 --payload 自动检测：preset 名称 / YAML-JSON 文件 / 内联 JSON
    """
    payload_spec = getattr(args, 'payload', '') or \
                   getattr(args, 'payloads', '') or \
                   getattr(args, 'payload_preset', '')

    # 🆕 归一化 --payload 规格
    norm = normalize_payload_spec(payload_spec)

    payload_file = norm["file"] or ""
    payload_preset = norm["preset"] or ""
    payload_vars_inline = norm["vars"] or ""

    ext = _os.path.splitext(payload_file)[1].lower() if payload_file else ""

    if ext in (".yaml", ".yml"):
        if _os.path.exists(payload_file):
            try:
                from datasets.loader import load_payload_vars as _yaml_load
                vars_dict, registry = _yaml_load(payload_file)
                PAYLOAD_VARS.update(vars_dict)
                console.print(f"[dim]📦 已从 YAML 加载 {len(PAYLOAD_VARS)} 个 payload 变量 ({payload_file})[/dim]")
                if payload_preset and registry:
                    apply_preset(PAYLOAD_VARS, payload_preset, registry.extract_presets())
            except Exception as e:
                console.print(f"[yellow]⚠️ 加载 YAML 失败 ({payload_file}): {e}[/yellow]")
        else:
            console.print(f"[yellow]⚠️ YAML 文件未找到: {payload_file}[/yellow]")
    elif ext == ".json":
        if _os.path.exists(payload_file):
            try:
                with open(payload_file, "r", encoding="utf-8") as f:
                    json_data = _json.load(f)
                if isinstance(json_data, dict):
                    PAYLOAD_VARS.update(json_data)
                    console.print(f"[dim]📦 已从 JSON 加载 {len(json_data)} 个 payload 变量 ({payload_file})[/dim]")
            except Exception as e:
                console.print(f"[yellow]⚠️ 加载 JSON 失败 ({payload_file}): {e}[/yellow]")
        else:
            console.print(f"[yellow]⚠️ JSON 文件未找到: {payload_file}[/yellow]")
    else:
        # ── 主方案: Python 模块加载 ──
        try:
            vars_dict, presets = load_payloads_module(args.lang)
            PAYLOAD_VARS.update(vars_dict)
            console.print(f"[dim]📦 已从 Python 模块加载 {len(vars_dict)} 个 payload 变量[/dim]")
            if payload_preset:
                apply_preset(PAYLOAD_VARS, payload_preset, presets)
        except Exception as e:
            console.print(f"[yellow]⚠️ 加载 Payload 模块失败: {e}[/yellow]")

    # ── 命令行额外变量覆盖（最高优先级）──
    if payload_vars_inline:
        try:
            extra = _json.loads(payload_vars_inline)
            PAYLOAD_VARS.update(extra)
            console.print(f"[dim]🔧 内联变量覆盖 {len(extra)} 个 payload 变量[/dim]")
        except _json.JSONDecodeError as e:
            console.print(f"[yellow]⚠️ --payload 内联 JSON 解析失败: {e}[/yellow]")


# ── 用例过滤 ──

def _resolve_case_filters(args) -> tuple:
    """解析用例白名单/排除列表/快捷别名。"""
    case_filter = [x.strip() for x in args.case.split(",") if x.strip()] if args.case else None
    exclude_filter = [x.strip() for x in args.exclude_case.split(",") if x.strip()] if args.exclude_case else None

    _CASE_SHORTCUTS = {"all-probe": "probe", "all-single": "single", "all-crescendo": "crescendo"}
    _phase_from_case = None
    _combo_filter = None

    if case_filter:
        for sc, ph in _CASE_SHORTCUTS.items():
            if sc in case_filter:
                _phase_from_case = ph
                case_filter.remove(sc)

        if "all-error" in case_filter:
            case_filter.remove("all-error")
            import glob as _glob
            import json as _json_log
            import os as _os_path
            _log_files = _glob.glob(_os_path.join("outputs", "results", "*_log_*.json"))
            if _log_files:
                _latest_log = max(_log_files, key=_os_path.getmtime)
                with open(_latest_log, "r", encoding="utf-8") as _f:
                    _prev_results = _json_log.load(_f)
                _error_pairs = sorted(set(
                    (r["case_id"], r.get("combo_name", ""))
                    for r in _prev_results if r.get("status") == "ERROR"
                ))
                if _error_pairs:
                    _combo_filter = _error_pairs
                    _error_ids = sorted(set(cid for cid, _ in _error_pairs))
                    case_filter = list(set(case_filter or []) | set(_error_ids))

                    def _infer_phase(cid: str) -> str:
                        if cid.startswith("probe_") or cid.upper().startswith("PROBE_"):
                            return "probe"
                        if cid.startswith("multi_crescendo_"):
                            return "crescendo"
                        if cid.startswith("single_"):
                            return "single"
                        return "crescendo"

                    _error_phases = {_infer_phase(cid) for cid in _error_ids}
                    if len(_error_phases) == 1:
                        _phase_from_case = _error_phases.pop()
                    console.print(
                        f"[yellow]📋 从最新日志提取 {len(_error_pairs)} 个 ERROR (case+combo) 精确对，"
                        f"覆盖 {len(_error_ids)} 个用例{' → ' + _phase_from_case if _phase_from_case else ''}[/yellow]"
                    )
                else:
                    console.print("[green]✅ 最新日志中无 ERROR 用例，无需重跑[/green]")
            else:
                console.print("[red]❌ 未找到历史日志文件，--case all-error 无效[/red]")

        if not case_filter:
            case_filter = None

    if _phase_from_case and args.phase != "all" and args.phase != _phase_from_case:
        console.print(f"[yellow]⚠ --phase={args.phase} 与 --case 快捷别名冲突，以快捷别名 {_phase_from_case} 为准[/yellow]")

    effective_phase = _phase_from_case or args.phase

    return case_filter, exclude_filter, _combo_filter, effective_phase
