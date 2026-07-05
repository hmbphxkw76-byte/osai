"""
===============================================================================
OffSec AI-300 终极红队演练平台 (Unified Platform v9.0 阶段执行版)
核心升级：
1. Crescendo 渐进式多轮攻击引擎，覆盖单轮无法突破的高阶考点
2. 完整复用所有单轮组件：转换器、评分器、仪表盘、日志、可视化
3. 自动兼容单轮/多轮测试用例，向后完全兼容
4. JailbreakBench Top5 模板 + 67组攻击组合（含17组三层链） + 防假阴性评分
5. --phase / --auto-gate 分阶段门控执行（PyRIT 最佳实践）
6. 测试用例 63→70 (+7 P0/P1，v9.0)：CoT推理提取/宪法越狱/JSON结构化输出劫持/PDF隐藏文本注入/MCP工具投毒/A2A跨Agent传播/三层编码链压测
7. 2026 最热点攻击面：DeepSeek-R1/o1/o3 推理模型 CoT 提取、Anthropic 宪法越狱、MCP/A2A 协议攻击
8. 全转换器激活：24个转换器 0% 闲置率，17 组三层编码链全覆盖

模块拆分:
- converters.py → 攻击策略转换器 & 攻击组合配置
- targets.py    → .env 配置加载 & Target 工厂
- engines.py    → 核心攻击引擎 & 仪表盘
- reporter.py   → 结果分析与报告生成
- main.py       → CLI 入口 & 任务编排

===============================================================================
快速使用指南 (Quick Reference)
===============================================================================
  模式 A: 不指定 --target-url → 攻击 .env 中配置的 LLM API (如智谱 GLM-4.7-Flash):
    python main.py --lang cn --phase probe              # 仅 PROBE 快速探测
    python main.py --lang cn --phase single             # 仅单轮主力突破
    python main.py --lang cn --phase crescendo          # 仅 Crescendo 多轮攻坚
    python main.py --lang cn --auto-gate                # 自动门控 (阈值 10%)
    python main.py --lang cn --auto-gate --gate-threshold 0.20  # 自定义阈值
    python main.py --lang cn --phase all                # 中文全量 (向后兼容)
    python main.py --lang en --phase all --concurrent 9  # 英文全量, 9 并发

  模式 B: 指定 --target-url → 攻击自定义 Chat API (内网应用/自签证书):
    python main.py --lang cn --phase probe --target-url https://192.168.12.22/chat
    python main.py --lang cn --auto-gate --target-url https://192.168.12.22/chat
    python main.py --lang cn --phase all --target-url https://192.168.12.22/chat --target-api-key sk-xxx

  模式 C: --target-url + --target-api-format → 攻击非 OpenAI 格式 API (Gemini/Claude):
    python main.py --lang cn --phase probe --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent --target-api-key YOUR_GEMINI_KEY --target-api-format gemini
    python main.py --lang cn --phase probe --target-url https://api.anthropic.com/v1/messages --target-api-key YOUR_CLAUDE_KEY --target-api-format claude --target-model claude-3-sonnet-20240229

  模式 D: --target-url + --target-api-format raw → 攻击任意非标准内部 Web 应用 (考试场景):
    # HTTP 内网应用 + Cookie 认证（默认浏览器 UA 伪装）
    python main.py --lang cn --phase probe --target-url http://192.168.1.100/internal/chat --target-api-format raw --target-cookie "session_id=abc123; auth_token=xyz"
    # HTTPS 内网自签 + form-urlencoded body + 完整浏览器头模拟
    python main.py --lang cn --phase probe --target-url https://internal-app/api/v1/query --target-api-format raw --target-content-type application/x-www-form-urlencoded --target-cookie "alimail_device_id=49816375-...; cna=..." --target-user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0" --target-extra-headers '{"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Language":"en-US,en;q=0.9","Accept-Encoding":"gzip, deflate","Upgrade-Insecure-Requests":"1"}' --target-no-ssl

  注: 两种模式下，评分器 (Judge) 均使用 .env 中配置的 LLM (如智谱 GLM-4.7-Flash) 进行判定。
===============================================================================
"""
import asyncio
import os
import sys
import argparse
import json
from datetime import datetime
import glob as _glob

# PyRIT 核心组件
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from pyrit.setup import initialize_pyrit_async
from pyrit.prompt_target import OpenAIChatTarget

# 实时UI与进度追踪
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# ── 项目模块 ──
from converters import GLOBAL_ATTACK_COMBINATIONS, CONVERTER_MAP, resolve_converters
from targets import (
    load_env_config, CustomHttpChatTarget,
    create_scorer_target, create_attack_target,
)
from engines import (
    DashboardState, classify_case, _calc_success_rate,
    execute_single_attack, execute_crescendo_attack, PAYLOAD_VARS,
)
from reporter import (
    analyze_and_visualize, print_detailed_report, generate_exam_report,
)
from utils import ensure_results_dir, results_path, RESULTS_DIR
# ── 数据层（Pydantic 校验 + LLM Few-shot 生成就绪） ──
from data.loader import load_test_cases, load_payloads_module, apply_preset

console = Console()

# 全局初始化标记，防止重复初始化DuckDB导致报错
_pyrit_initialized = False


# ================= 6. 主任务调度 =================
async def run_campaign(json_file, campaign_name, heatmap_title, heatmap_filename,
                       max_concurrent=5, phase_filter="all", attack_target=None, scorer_target=None,
                       case_filter=None, exclude_filter=None, combo_filter=None):
    global _pyrit_initialized

    try:
        cases, _ = load_test_cases(json_file)
    except Exception as e:
        console.print(f"[red]❌ Failed to load {json_file}: {e}[/red]")
        return []

    if not cases:
        console.print("[yellow]⚠️ 测试用例为空，退出执行[/yellow]")
        return []

    # 阶段过滤
    if phase_filter != "all":
        cases = [c for c in cases if classify_case(c) == phase_filter]
        if not cases:
            console.print(f"[yellow]⚠️ No '{phase_filter}' cases found in {json_file}, skipping[/yellow]")
            return []

    # case ID 白名单过滤（--case）
    if case_filter:
        _ids = set(case_filter)
        cases = [c for c in cases if c.get("id", "") in _ids]
        if not cases:
            console.print(f"[yellow]⚠️ No matching case IDs found in {json_file}, skipping[/yellow]")
            return []
        console.print(f"[dim]🔍 用例白名单过滤: {len(cases)} 个匹配 ({', '.join(c.get('id','') for c in cases)})[/dim]")

    # case ID 排除过滤（--exclude-case）
    if exclude_filter:
        _exclude = set(exclude_filter)
        before = len(cases)
        cases = [c for c in cases if c.get("id", "") not in _exclude]
        skipped = before - len(cases)
        if not cases:
            console.print(f"[yellow]⚠️ 所有用例已被 --exclude-case 排除[/yellow]")
            return []
        console.print(f"[dim]🚫 已排除 {skipped} 个用例，剩余 {len(cases)} 个[/dim]")

    # 数据库仅初始化一次（PyRIT 0.14.0: DUCK_DB → "SQLite", api 改名 + async）
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    db_path = results_path(f"ai300_memory_{ts}.duckdb")
    if not _pyrit_initialized:
        await initialize_pyrit_async(memory_db_type="SQLite", db_path=db_path)
        _pyrit_initialized = True

    # 使用外部传入的 target，若无则回退到默认 OpenAIChatTarget
    base_target = attack_target or OpenAIChatTarget(temperature=0.9)
    scorer_target = scorer_target or OpenAIChatTarget(temperature=0)
    semaphore = asyncio.Semaphore(max_concurrent)
    
    # 自动识别单轮/多轮用例，生成对应任务
    # combo_filter: set of (case_id, combo_name) — 仅运行精确匹配的 case+combo 对
    _cf = set(combo_filter) if combo_filter else None
    tasks = []
    for case in cases:
        raw_combos = case.get("attack_combos", GLOBAL_ATTACK_COMBINATIONS)
        combos = [{"name": c["name"], "converters": resolve_converters(c["converters"])} for c in raw_combos]
        
        # 判断用例类型：有multi_turn_objectives则走Crescendo多轮，否则走单轮
        is_multi_turn = "multi_turn_objectives" in case and len(case["multi_turn_objectives"]) > 0
        for combo in combos:
            # combo_filter 精确匹配：只跑 (case_id, combo_name) 在集合中的
            if _cf and (case.get("id", ""), combo["name"]) not in _cf:
                continue
            if is_multi_turn:
                tasks.append(("crescendo", case, combo))
            else:
                tasks.append(("single", case, combo))

    dashboard = DashboardState(len(tasks))
    all_results = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )
    task_id = progress.add_task(f"⚔️ Executing {len(tasks)} attacks...", total=len(tasks))

    # 启动 Live 实时仪表盘
    with Live(dashboard.get_layout(progress, task_id), console=console, refresh_per_second=4) as live:
        coros = []
        for task_type, case, combo in tasks:
            if task_type == "single":
                coro = execute_single_attack(semaphore, case, combo, base_target, scorer_target, dashboard)
            else:
                coro = execute_crescendo_attack(semaphore, case, combo, base_target, scorer_target, dashboard)
            coros.append(coro)
        
        for coro in asyncio.as_completed(coros):
            result = await coro
            all_results.append(result)
            progress.advance(task_id)
            live.update(dashboard.get_layout(progress, task_id))

    # 保存攻击日志（带时间戳）
    log_file = results_path(f"{campaign_name.replace(' ', '_')}_log_{ts}.json")
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]✅ 攻击日志已保存: {log_file}[/green]")
    
    # 生成热力图分析报告（带时间戳）
    heatmap_file = results_path(heatmap_filename.replace('.png', f'_{ts}.png'))
    analyze_and_visualize(all_results, heatmap_title, heatmap_file)
    
    # 打印详细报告（含 prompt/response 证据）
    print_detailed_report(all_results, campaign_name)
    
    # 生成考试用漏洞报告（Markdown，默认输出到 results 目录）
    generate_exam_report(all_results, campaign_name, output_dir=RESULTS_DIR)
    
    return all_results


# ================= 6.5 阶段门控编排器 =================
async def run_phased_campaign(json_file: str, max_concurrent: int, gate_threshold: float,
                               attack_target=None, scorer_target=None,
                               case_filter=None, exclude_filter=None, combo_filter=None):
    """PyRIT 最佳实践：阶梯式门控执行。低成功率自动跳过当前阶段，升级到下一阶段。"""
    console.print(Panel(
        f"[bold]🚀 AI-300 阶梯式门控攻击 (阈值: {gate_threshold:.0%})[/bold]\n"
        f"[dim]STAGE 1: PROBE 快速探测 → STAGE 2: 单轮主力突破 → STAGE 3: Crescendo 攻坚战[/dim]",
        style="bold blue"))

    # ── STAGE 1: PROBE 快速健康检查 ──
    console.print("\n[bold cyan]━━━ STAGE 1/3: PROBE 快速探测 ━━━[/bold cyan]")
    results_s, results_c = [], []  # 预初始化，避免门控跳过时 UnboundLocalError
    results_p = await run_campaign(
        json_file=json_file,
        campaign_name="AI-300_PROBE_Recon",
        heatmap_title="AI-300 PROBE Success Matrix",
        heatmap_filename="ai300_probe_heatmap.png",
        max_concurrent=max_concurrent,
        phase_filter="probe",
        attack_target=attack_target,
        scorer_target=scorer_target,
        case_filter=case_filter,
        exclude_filter=exclude_filter,
        combo_filter=combo_filter,
    )
    probe_rate = _calc_success_rate(results_p)
    console.print(f"[bold]PROBE 阶段成功率: {probe_rate:.1%}[/bold]")

    # ── STAGE 2: 单轮攻击（可能被门控跳过） ──
    skip_single = probe_rate < gate_threshold
    single_rate = 0.0
    if skip_single:
        console.print(f"[yellow]⚠️ PROBE 成功率 ({probe_rate:.1%}) < 门控阈值 ({gate_threshold:.0%})[/yellow]")
        console.print("[yellow]→ 目标防线较强，跳过单轮阶段，直接升级 Crescendo 攻坚...[/yellow]")
    else:
        console.print(f"\n[bold cyan]━━━ STAGE 2/3: 单轮主力突破 ━━━[/bold cyan]")
        results_s = await run_campaign(
            json_file=json_file,
            campaign_name="AI-300_SingleTurn_Assault",
            heatmap_title="AI-300 Single-Turn Success Matrix",
            heatmap_filename="ai300_single_heatmap.png",
            max_concurrent=max_concurrent,
            phase_filter="single",
            attack_target=attack_target,
            scorer_target=scorer_target,
            case_filter=case_filter,
            exclude_filter=exclude_filter,
            combo_filter=combo_filter,
        )
        single_rate = _calc_success_rate(results_s)
        console.print(f"[bold]单轮阶段成功率: {single_rate:.1%}[/bold]")

    # ── STAGE 3: Crescendo 攻坚 ──
    skip_crescendo = (not skip_single) and single_rate < gate_threshold
    if skip_crescendo:
        console.print(f"[yellow]⚠️ 单轮成功率 ({single_rate:.1%}) < 门控阈值 ({gate_threshold:.0%})[/yellow]")
        console.print("[yellow]→ Crescendo 多轮攻击在此目标上成功率极低，跳过以节省考试时间。[/yellow]")
    else:
        reason = "单轮突破成功，乘胜追击" if not skip_single else "PROBE 未穿透，升级重型武器"
        console.print(f"\n[bold cyan]━━━ STAGE 3/3: Crescendo 攻坚 ({reason}) ━━━[/bold cyan]")
        results_c = await run_campaign(
            json_file=json_file,
            campaign_name="AI-300_Crescendo_Siege",
            heatmap_title="AI-300 Crescendo Success Matrix",
            heatmap_filename="ai300_crescendo_heatmap.png",
            max_concurrent=max_concurrent,
            phase_filter="crescendo",
            attack_target=attack_target,
            scorer_target=scorer_target,
            case_filter=case_filter,
            exclude_filter=exclude_filter,
            combo_filter=combo_filter,
        )

    console.print("\n[bold green]✅ 阶梯式门控攻击完成！[/bold green]")
    
    # 阶段完成后生成综合报告
    all_phase_results = results_p + (results_s if not skip_single else []) + (results_c if not skip_crescendo else [])
    if all_phase_results:
        print_detailed_report(all_phase_results, "AI-300 阶梯式门控总战报")
    
    # 尝试收集各阶段日志生成综合考试报告
    log_files = sorted(_glob.glob(results_path("AI-300_*_log_*.json")))
    if len(log_files) >= 2:
        all_results_combined = []
        for lf in log_files[-3:]:  # 最近3个阶段日志
            try:
                with open(lf, 'r', encoding='utf-8') as f:
                    all_results_combined.extend(json.load(f))
            except Exception:
                pass
        if all_results_combined:
            generate_exam_report(all_results_combined, "AI-300_Combined_All_Phases", output_dir=RESULTS_DIR)
    
    # 保存综合结果供调用方使用（修复 UnboundLocalError）
    return results_p + (results_s if not skip_single else []) + (results_c if not skip_crescendo else [])


# ================= Payload 模板变量加载 =================
def _load_payload_vars(args) -> None:
    """加载 payload 变量到 engines.PAYLOAD_VARS。
    从 data/payloads_{lang}.py 加载（通过 data/loader.py）。
    顺序：Python 模块 → preset 预设 → --payload-vars 命令行覆盖（后者优先级更高）
    """
    ext = os.path.splitext(args.payloads)[1].lower() if args.payloads else ""

    if ext in (".yaml", ".yml"):
        # ── 降级方案: YAML 文件加载 ──
        if os.path.exists(args.payloads):
            try:
                from data.loader import load_payload_vars as _yaml_load
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
        # ── 主方案: Python 模块加载 (data/payloads_{lang}.py) ──
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
            extra = json.loads(args.payload_vars)
            PAYLOAD_VARS.update(extra)
            console.print(f"[dim]🔧 命令行覆盖 {len(extra)} 个 payload 变量[/dim]")
        except json.JSONDecodeError as e:
            console.print(f"[yellow]⚠️ --payload-vars JSON 解析失败: {e}[/yellow]")


# ================= CLI 入口 =================
async def main():
    parser = argparse.ArgumentParser(
        description="OffSec AI-300 Unified Red Team Platform v9.0 (Phased Execution) — 70 test cases across 3 attack strategies + 2026-hottest attack vectors (CoT/Constitution/MCP/A2A/Multimodal) + 17 triple-layer chains",
        epilog="EXAMPLES:\n"
               "  # [1] 攻击内网自签证书的 Chat API (OpenAI 兼容)\n"
               "  python main.py --lang cn --target-url https://192.168.12.22/chat --phase probe\n\n"
               "  # [2] 攻击 HTTP 内网 Web 应用 + Cookie/Session 认证 (考试高频场景)\n"
               "  python main.py --lang cn --target-url http://192.168.1.100/api/chat --target-api-format raw --target-cookie \"session_id=abc123; auth_token=xyz\" --phase probe\n\n"
               "  # [3] 攻击 HTTPS 内部应用 + 自定义认证头 (X-API-Key / X-CSRF-Token 等)\n"
               "  python main.py --lang cn --target-url https://internal-app/api/v1/query --target-api-format raw --target-extra-headers '{\"X-API-Key\":\"sk-secret\",\"X-CSRF-Token\":\"csrf-xyz\"}' --target-no-ssl --phase probe\n\n"
               "  # [4] 攻击 Gemini API (非 OpenAI 格式)\n"
               "  python main.py --lang cn --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent --target-api-key YOUR_KEY --target-api-format gemini --phase probe\n\n"
               "  # [5] 攻击 Claude API (非 OpenAI 格式)\n"
               "  python main.py --lang cn --target-url https://api.anthropic.com/v1/messages --target-api-key YOUR_KEY --target-api-format claude --target-model claude-3-sonnet-20240229 --phase probe\n\n"
               "  # [6] 原方式：不指定 --target-url → 探测 .env 中配置的 LLM API (如智谱 GLM-4.7-Flash)\n"
               "  python main.py --lang cn --phase all",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--lang", choices=["cn", "en"], default="cn",
                        help="Test suite language: cn=Chinese, en=English (default: cn)")
    parser.add_argument("--phase", choices=["probe", "single", "crescendo", "all"], default="probe",
                        help="Phase: probe (quick recon), single (main assault), crescendo (heavy multi-turn), all=full campaign")
    parser.add_argument("--auto-gate", action="store_true", default=False,
                        help="Enable auto-gating: skip phases if success rate < --gate-threshold (PyRIT best practice)")
    parser.add_argument("--gate-threshold", type=float, default=0.10,
                        help="Success rate threshold for auto-gating, 0.0-1.0 (default: 0.10)")
    parser.add_argument("--concurrent", type=int, default=1,
                        help="Max concurrent API calls (default: 1)")
    
    # ── 自定义目标参数 ──
    parser.add_argument("--target-url", type=str, default="",
                        help="自定义攻击目标 Chat API URL（如 https://192.168.12.22/chat）。不指定则攻击 .env 中配置的 LLM API")
    parser.add_argument("--target-api-key", type=str, default="",
                        help="自定义目标的 API Key（放在 Authorization: Bearer header 中）")
    parser.add_argument("--target-model", type=str, default="",
                        help="自定义目标的模型名称（放在请求 body 中，默认从 .env 读取）")
    parser.add_argument("--target-api-format", type=str, default="openai", choices=["openai", "gemini", "claude", "raw"],
                        help="API 格式: openai(默认) / gemini / claude / raw(万能回退, 适配任意非标准内部Web应用)")
    parser.add_argument("--target-no-ssl", action="store_true", default=True,
                        help="跳过 SSL 证书验证（内网自签证书，默认启用）")
    parser.add_argument("--target-verify-ssl", action="store_true", default=False,
                        help="验证 SSL 证书（覆盖 --target-no-ssl）")
    parser.add_argument("--target-extra-headers", type=str, default="",
                        help="自定义 HTTP 请求头，JSON 字符串格式（如 '{\"X-API-Key\":\"xxx\",\"X-Auth-Token\":\"yyy\"}'）用于内部Web应用的非标准认证")
    parser.add_argument("--target-cookie", type=str, default="",
                        help="Cookie 字符串（如 'session_id=abc; csrf_token=xyz'），自动转为 Cookie 请求头，适配 Web 应用 Session 认证")
    parser.add_argument("--target-user-agent", type=str, default="",
                        help="自定义 User-Agent（默认使用 Chrome/131 浏览器 UA 伪装 WAF）")
    parser.add_argument("--target-content-type", type=str, default="application/json",
                        choices=["application/json", "application/x-www-form-urlencoded", "text/plain"],
                        help="POST 请求 Content-Type，决定 body 编码: json(默认) / form(URL编码) / text(纯文本)")
    parser.add_argument("--target-jwt", type=str, default="",
                        help="JWT Token — 快捷方式，自动转为 Authorization: Bearer <jwt>（优先级高于 --target-api-key）")
    parser.add_argument("--target-http-method", type=str, default="POST",
                        choices=["POST", "GET", "PUT", "DELETE", "PATCH"],
                        help="HTTP 方法: POST(默认, Chat API) / GET(信息收集/探测)")
    parser.add_argument("--payloads", type=str, default="",
                        help="Payload 变量文件路径（支持 .json / .yaml / .yml；用于 objective {key} 模板替换），留空则按 --lang 自动选择 data/payloads_cn.yaml 或 data/payloads_en.yaml")
    parser.add_argument("--payload-preset", type=str, default="",
                        help="载荷预设名称（stealth/bruteforce/redteam/academic/minimal），一键切换整组载荷策略")
    parser.add_argument("--payload-vars", type=str, default="",
                        help="额外 Payload 变量，JSON 字符串（如 '{\"shell_type\":\"Python\"}'），优先级高于 preset 和文件")
    parser.add_argument("--env-file", type=str, default=".env",
                        help=".env 配置文件路径（默认: .env）")
    parser.add_argument("--case", type=str, default="",
                        help="仅测试指定用例 ID（逗号分隔），如 'single_reverse_shell,CAP_001_social_eng_phishing'")
    parser.add_argument("--exclude-case", type=str, default="",
                        help="排除指定用例 ID（逗号分隔），如 'CAP_009_explosive_device,CAP_041_gcg_adversarial_suffix'")
    parser.add_argument("--mode", choices=["multi", "capstone", "all"], default="capstone",
                        help="[Deprecated] Legacy mode flag, use --phase instead")
    args = parser.parse_args()

    # ── 显示完整命令行参数 ──
    cli_parts = [f"python {os.path.basename(__file__)}"]
    cli_parts.append(f"--lang {args.lang}")
    cli_parts.append(f"--phase {args.phase}")
    cli_parts.append(f"--concurrent {args.concurrent}")
    if args.auto_gate:
        cli_parts.append(f"--auto-gate --gate-threshold {args.gate_threshold}")
    if args.target_url:
        cli_parts.append(f"--target-url {args.target_url}")
    if args.target_api_key:
        cli_parts.append(f"--target-api-key {args.target_api_key}")
    if args.target_model:
        cli_parts.append(f"--target-model {args.target_model}")
    if args.target_api_format != "openai":
        cli_parts.append(f"--target-api-format {args.target_api_format}")
    if args.target_extra_headers:
        cli_parts.append(f"--target-extra-headers '{args.target_extra_headers}'")
    if args.target_cookie:
        cli_parts.append(f"--target-cookie '{args.target_cookie}'")
    if args.payload_preset:
        cli_parts.append(f"--payload-preset {args.payload_preset}")
    if args.case:
        cli_parts.append(f"--case {args.case}")
    if args.exclude_case:
        cli_parts.append(f"--exclude-case {args.exclude_case}")
    if args.target_user_agent:
        cli_parts.append(f"--target-user-agent '{args.target_user_agent}'")
    if args.target_content_type != "application/json":
        cli_parts.append(f"--target-content-type {args.target_content_type}")
    if args.target_jwt:
        cli_parts.append(f"--target-jwt {args.target_jwt[:20]}...")
    if args.target_http_method != "POST":
        cli_parts.append(f"--target-http-method {args.target_http_method}")
    if args.target_verify_ssl:
        cli_parts.append("--target-verify-ssl")
    if args.env_file != ".env":
        cli_parts.append(f"--env-file {args.env_file}")
    console.print(f"[bold cyan]📋 执行参数:[/bold cyan] {' '.join(cli_parts)}")

    # ── 0. 初始化 PyRIT（必须在创建任何 PromptTarget 之前调用） ──
    global _pyrit_initialized
    ensure_results_dir()
    db_path = results_path(f"ai300_memory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.duckdb")
    if not _pyrit_initialized:
        await initialize_pyrit_async(memory_db_type="SQLite", db_path=db_path)
        _pyrit_initialized = True

    # ── 0.1 加载 .env 配置 ──
    attacker_config, scorer_config = load_env_config(args.env_file)

    # ── 0.2 模型配置校验 ──
    # 自定义 API（--target-url）: 忽略 CHAT_MODEL，仅需 SCORER_MODEL
    # 非自定义 API: CHAT_MODEL 和 SCORER_MODEL 都必须设置
    if args.target_url:
        if not scorer_config or not scorer_config.get("model"):
            console.print(
                "[bold red]❌ 自定义 API 模式下，评分器模型未配置！[/bold red]\n"
                "    请在 .env 中设置评分器:\n"
                "      SCORER_PLATFORM_SELECTOR=ZHIPU\n"
                "      [ZHIPU]\\n"
                "      SCORER_MODEL=GLM-5.2\n"
                "    或使用默认平台:\n"
                "      PLATFORM_SELECTOR=ZHIPU\n"
                "      [ZHIPU]\\n"
                "      SCORER_MODEL=GLM-5.2"
            )
            return
        console.print("[blue]ℹ️  自定义 API 模式: 已忽略 CHAT_MODEL，仅使用 SCORER_MODEL 配置评分器[/blue]")
    else:
        if not attacker_config or not attacker_config.get("model"):
            console.print(
                "[bold red]❌ 攻击者模型未配置！[/bold red]\n"
                "    请在 .env 中设置 PLATFORM_SELECTOR 并在对应节配置 CHAT_MODEL=模型名\n"
                "    或使用 --target-url 指定自定义 API 目标"
            )
            return
        if not scorer_config or not scorer_config.get("model"):
            console.print(
                "[bold red]❌ 评分器模型未配置！[/bold red]\n"
                "    请在 [PLATFORM] 节中设置 SCORER_MODEL=模型名\n"
                "    例: SCORER_MODEL=GLM-5.2"
            )
            return

    # ── 0.3 创建评分器 Target（使用独立评分器配置） ──
    scorer_target = create_scorer_target(scorer_config)
    
    # ── 0.4 创建攻击目标 Target ──
    # 如果指定了 --target-url，使用 CustomHttpChatTarget 攻击该 URL
    # 否则攻击 .env 中配置的 LLM API
    if args.target_url:
        # 解析自定义 HTTP 请求头（JSON 字符串）
        extra_headers = {}
        if args.target_extra_headers:
            try:
                extra_headers = json.loads(args.target_extra_headers)
            except json.JSONDecodeError as e:
                console.print(f"[bold red]❌ --target-extra-headers JSON 解析失败: {e}[/bold red]")
                return
        # Cookie/SessionID/Token 认证: 支持两种方式
        #   方式1: --target-cookie "session_id=abc; csrf=xyz" → 自动转为 Cookie 头
        #   方式2: --target-extra-headers '{"Cookie":"session_id=abc"}' → 手动指定
        if args.target_cookie:
            existing_cookie = extra_headers.get("Cookie", "")
            merged_cookie = f"{existing_cookie}; {args.target_cookie}".strip("; ")
            extra_headers["Cookie"] = merged_cookie
        # User-Agent: --target-user-agent 快捷覆盖默认浏览器 UA
        if args.target_user_agent:
            extra_headers["User-Agent"] = args.target_user_agent
        # Content-Type: --target-content-type 选择 POST body 编码方式
        # （extra_headers["Content-Type"] 优先，后端代码会在 build headers 时做最终裁决）
        content_type = extra_headers.get("Content-Type", args.target_content_type)
        # 协议校验: --target-verify-ssl 对 http:// 无效
        is_http_target = args.target_url.lower().startswith("http://")
        if is_http_target and args.target_verify_ssl:
            console.print("[yellow]⚠️ --target-verify-ssl 对 http:// 协议无效（HTTP 不使用 SSL），已自动忽略[/yellow]")
        # 攻击自定义 API 时，忽略 attacker_config 中的 CHAT_MODEL
        verify_ssl = (args.target_verify_ssl or not args.target_no_ssl) and not is_http_target
        attack_target = CustomHttpChatTarget(
            endpoint=args.target_url,
            api_key=args.target_api_key or "",
            model=args.target_model or "default",
            temperature=0.9,
            timeout=60,
            verify_ssl=verify_ssl,
            api_format=args.target_api_format,
            extra_headers=extra_headers if extra_headers else None,
            content_type=content_type,
            http_method=args.target_http_method,
            jwt_token=args.target_jwt,
        )
    else:
        attack_target = create_attack_target(env_config=attacker_config)

    # ── 0.5 加载 Payload 模板变量（Python 模块，通过 data/loader.py）──
    if not args.payloads:
        console.print(f"[dim]📦 从 Python 模块加载 Payload (lang={args.lang})[/dim]")
    _load_payload_vars(args)

    # ── 0.5.5 攻击特征库概况 ──
    n_converters = len(CONVERTER_MAP)
    n_combos = len(GLOBAL_ATTACK_COMBINATIONS)
    n_triple = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) >= 3)
    n_double = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 2)
    n_single = sum(1 for c in GLOBAL_ATTACK_COMBINATIONS if len(c["converters"]) == 1)
    console.print(
        f"[dim]🎯 攻击特征库: {n_converters} 个转换器 + {n_combos} 组攻击组合 "
        f"(单层: {n_single} | 双层: {n_double} | 三层链: {n_triple})[/dim]"
    )

    # ── 0.6 解析用例白名单/排除列表（支持 all-probe / all-single / all-crescendo 快捷别名）──
    case_filter = [x.strip() for x in args.case.split(",") if x.strip()] if args.case else None
    exclude_filter = [x.strip() for x in args.exclude_case.split(",") if x.strip()] if args.exclude_case else None

    _CASE_SHORTCUTS = {"all-probe": "probe", "all-single": "single", "all-crescendo": "crescendo"}
    _phase_from_case = None
    _combo_filter = None  # (case_id, combo_name) 精确过滤集（all-error 专用）
    if case_filter:
        for sc, ph in _CASE_SHORTCUTS.items():
            if sc in case_filter:
                _phase_from_case = ph
                case_filter.remove(sc)
        # ── all-error: 从最新日志中提取 (case_id, combo_name) 精确对 ──
        if "all-error" in case_filter:
            case_filter.remove("all-error")
            import glob as _glob
            _log_files = _glob.glob(os.path.join(RESULTS_DIR, "*_log_*.json"))
            if _log_files:
                _latest_log = max(_log_files, key=os.path.getmtime)
                import json as _json
                with open(_latest_log, "r", encoding="utf-8") as _f:
                    _prev_results = _json.load(_f)
                _error_pairs = sorted(set(
                    (r["case_id"], r.get("combo_name", "")) for r in _prev_results if r.get("status") == "ERROR"
                ))
                if _error_pairs:
                    _combo_filter = _error_pairs
                    _error_ids = sorted(set(cid for cid, _ in _error_pairs))
                    case_filter = list(set(case_filter or []) | set(_error_ids))
                    # 从错误用例 ID 前缀自动推断阶段
                    def _infer_phase(cid: str) -> str:
                        if cid.startswith("probe_") or cid.upper().startswith("PROBE_"):
                            return "probe"
                        if cid.startswith("multi_crescendo_"):
                            return "crescendo"
                        if cid.startswith("single_"):
                            return "single"
                        return "crescendo"  # CAP_xxx 多轮用例默认
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
            # _combo_filter 在作用域外赋值，传递给 run_campaign
        if not case_filter:
            case_filter = None

    # 确定测试用例文件（data/ 目录下）
    DATA_DIR = "data"
    json_filename = "multi_stage_capstone_cases_en.json" if args.lang == "en" else "multi_stage_capstone_cases_cn.json"
    json_file = os.path.join(DATA_DIR, json_filename)

    # 快捷别名推断阶段
    if _phase_from_case:
        if args.phase != "all" and args.phase != _phase_from_case:
            console.print(f"[yellow]⚠ --phase={args.phase} 与 --case 快捷别名冲突，以快捷别名 {_phase_from_case} 为准[/yellow]")
        args.phase = _phase_from_case

    try:
        if args.auto_gate:
            # 阶梯式门控模式（PyRIT 最佳实践）
            await run_phased_campaign(json_file, args.concurrent, args.gate_threshold,
                                       attack_target, scorer_target,
                                       case_filter=case_filter, exclude_filter=exclude_filter,
                                       combo_filter=_combo_filter)
        elif args.phase != "all":
            # 手动指定单阶段
            phase_labels = {"probe": "PROBE Recon", "single": "Single-Turn Assault", "crescendo": "Crescendo Siege"}
            label = phase_labels[args.phase]
            await run_campaign(
                json_file=json_file,
                campaign_name=f"AI-300_{label.replace(' ', '_')}",
                heatmap_title=f"AI-300 {label} Success Matrix",
                heatmap_filename=f"ai300_{args.phase}_heatmap.png",
                max_concurrent=args.concurrent,
                phase_filter=args.phase,
                attack_target=attack_target,
                scorer_target=scorer_target,
                case_filter=case_filter,
                exclude_filter=exclude_filter,
                combo_filter=_combo_filter,
            )
        else:
            # 全量执行（向后兼容）
            await run_campaign(
                json_file=json_file,
                campaign_name="AI-300_Full_Campaign",
                heatmap_title="AI-300 Full Campaign Success Matrix",
                heatmap_filename="ai300_full_heatmap.png",
                max_concurrent=args.concurrent,
                attack_target=attack_target,
                scorer_target=scorer_target,
                case_filter=case_filter,
                exclude_filter=exclude_filter,
            )
    finally:
        # 清理自定义 Target 的 HTTP session
        if isinstance(attack_target, CustomHttpChatTarget):
            await attack_target.close()

if __name__ == "__main__":
    asyncio.run(main())
