"""
===============================================================================
PyRIT Red Team — 环境引导模块（Bootstrap）
===============================================================================
从 main.py 提取环境初始化逻辑，遵循 PyRIT 专家最佳实践:
  ✅ 单一职责 — 仅负责环境准备，不执行攻击
  ✅ 统一入口 — 所有模式共享同一份初始化流程
  ✅ 明确失败 — 任何环节失败均返回 None 或抛出明确异常

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
  # 使用 ctx.attack_target, ctx.scorer_target, ...
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
)  # 🆕 P0
from executor import PAYLOAD_VARS
from utils import ensure_results_dir, results_path

console = Console()


@dataclass
class BootstrapContext:
    """环境初始化上下文 — 所有模式共享的结构化状态。

    由 bootstrap_environment() 填充，传递给 router 执行具体的攻击模式。
    """
    attack_target: PromptTarget | None = None
    scorer_target: PromptTarget | None = None
    attacker_config: dict = field(default_factory=dict)
    scorer_config: dict = field(default_factory=dict)
    target_type_result: TargetTypeResult | None = None
    db_path: str = ""
    case_filter: list[str] | None = None
    exclude_filter: list[str] | None = None
    combo_filter: list | None = None
    effective_phase: str = "probe"
    target_vendor: str = ""  # 🆕 P0: 目标厂商检测结果
    use_adaptive_engine: bool = False  # 🆕 P0: 是否启用自适应引擎


async def bootstrap_environment(args) -> BootstrapContext | None:
    """统一环境初始化入口 — 所有 CLI 模式共享。

    执行顺序:
      0. Memory 初始化
      1. .env 配置加载与校验
      2. Target 构建（自动探测 + 场景预设）
      3. Payload 变量加载
      4. Converter 自动发现

    Args:
        args: argparse.Namespace CLI 解析结果

    Returns:
        BootstrapContext 或 None（初始化失败时）
    """
    ctx = BootstrapContext()

    # ── 0. 初始化 PyRIT Memory ──
    ensure_results_dir()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"pyrit_redteam_memory_{ts}.db")
    memory = SQLiteMemory(db_path=db_path)
    CentralMemory.set_memory_instance(memory)
    ctx.db_path = db_path
    console.print(f"[green]✅ PyRIT Memory 已初始化 (SQLiteMemory + CentralMemory)[/green]")
    console.print(f"   [dim]db_path: {db_path}[/dim]")

    # ── 1. 加载 .env 配置 ──
    ctx.attacker_config, ctx.scorer_config = load_env_config(args.env_file)

    # ── 2. 配置校验 ──
    if not _validate_config(args, ctx.attacker_config, ctx.scorer_config):
        return None

    # ── 3. 创建评分器 Target ──
    ctx.scorer_target = create_scorer_target(ctx.scorer_config)

    # ── 4. 创建攻击目标 Target ──
    target_preset = load_target_preset()
    if args.target_url:
        attack_target = await _build_custom_target(args, target_preset)
        if attack_target is None:
            return None  # 目标不可达
        ctx.attack_target = attack_target

        # 目标架构类型探测（RAG/MCP/Agent/LLM）
        ctx.target_type_result = await auto_probe_target_type(
            args, args.target_url, args.target_api_key
        )
    else:
        ctx.attack_target = create_attack_target(env_config=ctx.attacker_config)

    # ── 5. 加载 Payload 模板变量 ──
    console.print(f"[dim]📦 从 Python 模块加载 Payload (lang={args.lang})[/dim]")
    _load_payload_vars(args)

    # ── 6. 自动发现转换器 ──
    n_discovered = discover_converters("converters")
    n_synced = sync_pyrit_converters()
    if n_discovered or n_synced:
        console.print(f"[dim]🔍 自动发现: +{n_discovered} 自定义 + {n_synced} PyRIT 原生转换器[/dim]")

    # ── 7. 攻击特征库概况 ──
    n_converters = len(CONVERTER_MAP)
    n_combos = len(GLOBAL_ATTACK_COMBINATIONS)
    n_triple = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) >= 3)
    n_double = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 2)
    n_single = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 1)
    console.print(
        f"[dim]🎯 攻击特征库: {n_converters} 个转换器 + {n_combos} 组攻击组合 "
        f"(单层: {n_single} | 双层: {n_double} | 三层链: {n_triple})[/dim]"
    )

    # ── 8. 用例过滤 ──
    ctx.case_filter, ctx.exclude_filter, ctx.combo_filter, ctx.effective_phase = \
        _resolve_case_filters(args)

    # ── 9. 🆕 P0: 自适应引擎 + 厂商检测 ──
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

        # 注入厂商特定 payload 变量
        vendor_vars = get_vendor_specific_vars(ctx.target_vendor)
        if vendor_vars:
            PAYLOAD_VARS.update(vendor_vars)

    return ctx


def _validate_config(args, attacker_config: dict, scorer_config: dict) -> bool:
    """校验模型配置完整性。

    Returns:
        True 如果配置有效，False 如果配置不完整
    """
    if args.target_url:
        if not scorer_config or not scorer_config.get("model"):
            console.print(
                "[bold red]❌ 自定义 API 模式下，评分器模型未配置！[/bold red]\n"
                "    请在 .env 中设置评分器:\n"
                "      SCORER_PLATFORM_SELECTOR=ZHIPU\n"
                "      [ZHIPU]\n"
                "      SCORER_MODEL=GLM-5.2\n"
                "    或使用默认平台:\n"
                "      PLATFORM_SELECTOR=ZHIPU\n"
                "      [ZHIPU]\n"
                "      SCORER_MODEL=GLM-5.2"
            )
            return False
        console.print("[blue]ℹ️  自定义 API 模式: 已忽略 CHAT_MODEL，仅使用 SCORER_MODEL 配置评分器[/blue]")
    else:
        if not attacker_config or not attacker_config.get("model"):
            console.print(
                "[bold red]❌ 攻击者模型未配置！[/bold red]\n"
                "    请在 .env 中设置 PLATFORM_SELECTOR 并在对应节配置 CHAT_MODEL=模型名\n"
                "    或使用 --target-url 指定自定义 API 目标"
            )
            return False
        if not scorer_config or not scorer_config.get("model"):
            console.print(
                "[bold red]❌ 评分器模型未配置！[/bold red]\n"
                "    请在 [PLATFORM] 节中设置 SCORER_MODEL=模型名\n"
                "    例: SCORER_MODEL=GLM-5.2"
            )
            return False
    return True


async def _build_custom_target(args, target_preset: dict | None = None):
    """构建自定义 HTTP Target（含自动探测和预设合并）。

    优先级: CLI 显式参数 > 目标场景预设 (TARGET_PRESET) > 默认值

    Args:
        args: argparse.Namespace CLI 解析结果
        target_preset: 从 .env [TARGET_xxx] 节加载的预设值字典
    """
    import json

    if target_preset is None:
        target_preset = {}

    def _resolve(key: str, default=None):
        """优先级: CLI args > target_preset > default"""
        cli_val = getattr(args, key, None)
        if cli_val:
            # 字符串键：非空字符串
            if isinstance(cli_val, str) and cli_val:
                return cli_val
            # 非字符串键：非 None/非默认值
            if not isinstance(cli_val, str) and cli_val is not None:
                if key == "target_api_format" and cli_val == "openai":
                    pass  # openai 是默认值，允许预设覆盖
                elif key == "target_http_method" and cli_val == "POST":
                    pass  # POST 是默认值，允许预设覆盖
                elif key == "target_content_type" and cli_val == "application/json":
                    pass  # 默认值，允许预设覆盖
                elif key == "target_no_ssl" and cli_val:
                    return cli_val
                elif key == "target_verify_ssl" and cli_val:
                    return cli_val
                elif key not in ("target_no_ssl", "target_verify_ssl"):
                    return cli_val
        # 回退到预设值
        preset_val = target_preset.get(key)
        if preset_val is not None:
            return preset_val
        return default

    effective_url = _resolve("target_url", "")
    if not effective_url:
        console.print("[bold red]❌ 未指定 --target-url 且 TARGET_PRESET 也未设置 TARGET_URL[/bold red]")
        return None

    effective_scenario = _resolve("scenario", "")
    effective_api_key = _resolve("target_api_key", "")
    effective_api_format = _resolve("target_api_format", "openai")
    effective_http_method = _resolve("target_http_method", "POST")
    effective_content_type = _resolve("target_content_type", "application/json")
    effective_cookie = _resolve("target_cookie", "")
    effective_jwt = _resolve("target_jwt", "")
    effective_user_agent = _resolve("target_user_agent", "")

    # 处理 extra_headers（JSON 字符串 → dict）
    raw_extra_headers = _resolve("target_extra_headers", "")
    extra_headers = {}
    if raw_extra_headers:
        try:
            extra_headers = json.loads(raw_extra_headers)
        except json.JSONDecodeError as e:
            console.print(f"[bold red]❌ TARGET_EXTRA_HEADERS JSON 解析失败: {e}[/bold red]")
            return None

    is_http_target = effective_url.lower().startswith("http://")
    if is_http_target and args.target_verify_ssl:
        console.print("[yellow]⚠️ --target-verify-ssl 对 http:// 协议无效[/yellow]")

    # SSL: CLI --target-verify-ssl > preset TARGET_NO_SSL=0 > CLI --target-no-ssl 默认
    if args.target_verify_ssl:
        verify_ssl = True
    elif target_preset.get("target_no_ssl") is True:
        verify_ssl = False
    elif args.target_no_ssl is False and not is_http_target:
        verify_ssl = True
    else:
        verify_ssl = not is_http_target and not args.target_no_ssl

    # 模型自动探测 + 可达性检查
    effective_model, target_reachable = await auto_probe_target_model(
        args, effective_url, effective_api_key
    )
    if not target_reachable:
        return None

    from utils import DEFAULT_MODEL_NAME
    return build_custom_target(
        endpoint=effective_url,
        scenario=effective_scenario,
        api_key=effective_api_key or "",
        model=effective_model or _resolve("target_model", DEFAULT_MODEL_NAME),
        api_format=effective_api_format,
        http_method=effective_http_method,
        content_type=effective_content_type,
        verify_ssl=verify_ssl,
        cookie=effective_cookie,
        jwt_token=effective_jwt,
        user_agent=effective_user_agent,
        extra_headers=extra_headers if extra_headers else None,
    )


def _load_payload_vars(args) -> None:
    """加载 payload 变量到 executor.PAYLOAD_VARS。

    加载优先级: Python 模块 → preset 预设 → --payload-vars 覆盖（最高优先级）
    """
    ext = _os.path.splitext(args.payloads)[1].lower() if args.payloads else ""

    if ext in (".yaml", ".yml"):
        # ── 降级方案: YAML 文件加载 ──
        if _os.path.exists(args.payloads):
            try:
                from datasets.loader import load_payload_vars as _yaml_load
                vars_dict, registry = _yaml_load(args.payloads)
                PAYLOAD_VARS.update(vars_dict)
                console.print(f"[dim]📦 已从 YAML 加载 {len(PAYLOAD_VARS)} 个 payload 变量 ({args.payloads})[/dim]")
                if args.payload_preset and registry:
                    apply_preset(PAYLOAD_VARS, args.payload_preset, registry.extract_presets())
            except Exception as e:
                console.print(f"[yellow]⚠️ 加载 YAML 失败 ({args.payloads}): {e}[/yellow]")
        else:
            console.print(f"[yellow]⚠️ YAML 文件未找到: {args.payloads}[/yellow]")
    else:
        # ── 主方案: Python 模块加载 ──
        try:
            vars_dict, presets = load_payloads_module(args.lang)
            PAYLOAD_VARS.update(vars_dict)
            console.print(f"[dim]📦 已从 Python 模块加载 {len(vars_dict)} 个 payload 变量[/dim]")
            if args.payload_preset:
                apply_preset(PAYLOAD_VARS, args.payload_preset, presets)
        except Exception as e:
            console.print(f"[yellow]⚠️ 加载 Payload 模块失败: {e}[/yellow]")

    # ── 命令行额外变量覆盖（最高优先级）──
    if args.payload_vars:
        try:
            extra = _json.loads(args.payload_vars)
            PAYLOAD_VARS.update(extra)
            console.print(f"[dim]🔧 命令行覆盖 {len(extra)} 个 payload 变量[/dim]")
        except _json.JSONDecodeError as e:
            console.print(f"[yellow]⚠️ --payload-vars JSON 解析失败: {e}[/yellow]")


def _resolve_case_filters(args) -> tuple:
    """解析用例白名单/排除列表/快捷别名。

    Returns:
        (case_filter, exclude_filter, combo_filter, effective_phase)
    """
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

        # all-error: 从最新日志中提取 ERROR 的 (case_id, combo_name) 精确对
        if "all-error" in case_filter:
            case_filter.remove("all-error")
            import glob as _glob
            import json as _json
            import os as _os
            _log_files = _glob.glob(_os.path.join("outputs", "results", "*_log_*.json"))
            if _log_files:
                _latest_log = max(_log_files, key=_os.path.getmtime)
                with open(_latest_log, "r", encoding="utf-8") as _f:
                    _prev_results = _json.load(_f)
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
