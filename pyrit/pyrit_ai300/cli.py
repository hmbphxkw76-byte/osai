"""
AI-300 Framework - CLI Interface
命令行接口：提供框架的命令行操作入口
"""

from __future__ import annotations

import warnings

# 屏蔽第三方库 confusables 1.2.0 的无效转义序列警告
# 该包是 pyrit 的传递依赖，已废弃不维护，Python 3.12+ 触发 SyntaxWarning
warnings.filterwarnings("ignore", category=SyntaxWarning, module=r"confusables")

import argparse

from pyrit_ai300.utils import setup_logger


def main():
    """CLI 主入口"""
    parser = argparse.ArgumentParser(
        prog="ai300",
        description="AI-300 Red Teaming Framework - OffSec AI-300 Exam-Aligned Scanner",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # OWASP command
    owasp_parser = subparsers.add_parser(
        "owasp",
        help="Execute attacks by OWASP standard",
        epilog="""\
Examples:
  # 单目标攻击（指定配置文件）
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml

  # 单目标攻击（指定 URL）
  ai300 owasp llm01 --target-url http://www.example.com

  # 多目标批量攻击（目录下所有 YAML）
  ai300 owasp llm01 --target-dir config/targets/

  # 多目标批量攻击 + HTML 报告
  ai300 owasp llm01 --target-dir config/targets/ --format html

  # 先侦察再攻击
  ai300 owasp llm01 --target-url http://target.com --auto-recon

  # 使用侦察生成的 profile
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --profile results/recon/profile.json

  # 全量 LLM Top 10 攻击
  ai300 owasp llm --target-file config/targets/ollama_local.yaml

  # Jailbreak 模板攻击
  ai300 owasp text_jailbreak:aim --target-file config/targets/ollama_local.yaml

  # 单文件精确攻击
  ai300 owasp owasp:llm:llm04:rag_poison --target-file config/targets/ollama_local.yaml

  # 实验模式（推荐：一个参数替代 --objective/--placeholders）
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --experiment expericing/tier1_goal

  # 多目标攻击（逗号分隔）
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --objective "whoami,id,uname"

  # 全量攻击 + HTML 报告
  ai300 owasp all --target-file config/targets/ollama_local.yaml --format html -o report.html""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    owasp_required = owasp_parser.add_argument_group("required arguments")
    owasp_required.add_argument(
        "scope",
        help="OWASP scope: single ID (llm01/asi01), group (llm/agentic), all, "
             "ref_path (owasp:llm:llm04:rag_poison), or text_jailbreak:aim/random/all",
    )
    owasp_target = owasp_parser.add_argument_group(
        "target specification (required, at least one)"
    )
    owasp_target.add_argument(
        "-t", "--target-file",
        default=None,
        help="Target configuration file path (e.g., config/targets/ollama_local.yaml)",
    )
    owasp_target.add_argument(
        "--target-dir",
        default=None,
        help="Directory containing target YAML files (batch mode, scans all *.yaml)",
    )
    owasp_target.add_argument(
        "--target-url",
        default=None,
        help="Direct target URL (e.g., http://www.example.com), skips YAML config",
    )
    owasp_optional = owasp_parser.add_argument_group("optional arguments")
    owasp_optional.add_argument(
        "-o", "--output",
        default=None,
        help="Report output path (default: auto-generated with timestamp)",
    )
    owasp_optional.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format (default: markdown)",
    )
    owasp_optional.add_argument(
        "--profile",
        default=None,
        help="Path to TargetProfile JSON (from recon command)",
    )
    owasp_optional.add_argument(
        "--model",
        default=None,
        help="Override target model name (e.g., qwen3:1.7b), skips YAML config model",
    )
    owasp_optional.add_argument(
        "--objective",
        default=None,
        help="攻击目标（替换 {goal} / {objective} 占位符）"
             "（例如：'whoami', 'cat /etc/passwd'）。"
             "支持逗号分隔多个目标（如 'whoami,id,uname'）。未设置时使用载荷文本本身",
    )
    owasp_optional.add_argument(
        "--placeholders",
        default=None,
        help="自定义占位符，key=value 格式，逗号分隔（支持多个）"
             "（例如：'domain=evil.com,task=whoami,language=python'）。"
             "用于替换载荷中的 {domain}、{task}、{language} 等占位符",
    )
    owasp_optional.add_argument(
        "--list-placeholders",
        action="store_true",
        help="列出指定 scope 中所有载荷使用的占位符，然后退出",
    )
    owasp_optional.add_argument(
        "--no-prompt",
        action="store_true",
        help="禁用交互式占位符提示（用于自动化/CI 环境）",
    )
    owasp_optional.add_argument(
        "--placeholder-file",
        default=None,
        help="占位符配置文件路径（YAML 格式）。"
             "定义后自动填充载荷中的占位符，缺失时提示补齐",
    )
    owasp_optional.add_argument(
        "--experiment",
        default=None,
        help="实验配置路径（如 expericing/tier1_goal）。"
             "加载 data/owasp/expericing/{path}/experiment.yaml 中的 objective/placeholders/execution 参数，"
             "替代 --objective/--placeholders/--placeholder-file",
    )
    owasp_optional.add_argument(
        "--auto-recon",
        action="store_true",
        help="Automatically run recon before attack",
    )
    owasp_optional.add_argument(
        "--scorer-url",
        default=None,
        help="外部评分 LLM 的 OpenAI 兼容端点 URL（如 https://open.bigmodel.cn/api/paas/v4）。"
             "设置后覆盖默认的本地 Ollama 评分器",
    )
    owasp_optional.add_argument(
        "--scorer-key",
        default=None,
        help="外部评分 LLM 的 API Key（如智谱 GLM 的 API Key）。"
             "也可通过环境变量 SCORER_API_KEY 设置",
    )
    owasp_optional.add_argument(
        "--scorer-model",
        default=None,
        help="外部评分 LLM 的模型名称（如 glm-4-flash）。"
             "也可通过环境变量 SCORER_MODEL_NAME 设置",
    )
    owasp_optional.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available components")
    list_required = list_parser.add_argument_group("required arguments")
    list_required.add_argument(
        "component",
        choices=["attacks", "converters", "scorers", "targets", "owasp"],
        help="Component type to list",
    )
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from results")
    report_required = report_parser.add_argument_group("required arguments")
    report_required.add_argument(
        "-r", "--results",
        required=True,
        help="Results file path (JSON)",
    )
    report_optional = report_parser.add_argument_group("optional arguments")
    report_optional.add_argument(
        "-o", "--output",
        default=None,
        help="Report output path (default: auto-generated with timestamp)",
    )
    report_optional.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format (default: markdown)",
    )

    # Recon command
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance on target")
    recon_target = recon_parser.add_argument_group("target specification (required, one of)")
    recon_target.add_argument(
        "-t", "--target",
        default=None,
        help="Target URL or endpoint to recon (e.g., http://localhost:11434)",
    )
    recon_target.add_argument(
        "--target-file",
        default=None,
        help="Target config file from config/targets/ (e.g., config/targets/custom_model_endpoint.yaml)",
    )
    recon_optional = recon_parser.add_argument_group("optional arguments")
    recon_optional.add_argument(
        "-d", "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Reconnaissance depth (default: standard)",
    )
    recon_optional.add_argument(
        "--tools",
        nargs="+",
        default=None,
        help="Specific tools to use (default: all enabled)",
    )
    recon_optional.add_argument(
        "-o", "--output",
        default=None,
        help="Output path for TargetProfile JSON (default: results/recon/profile_<timestamp>.json)",
    )
    recon_optional.add_argument(
        "--config",
        default="config/recon/recon.yaml",
        help="Recon configuration file path (default: config/recon/recon.yaml)",
    )
    recon_optional.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if getattr(args, "verbose", False) else "INFO"
    logger = setup_logger(level=log_level)

    if args.command == "owasp":
        _run_owasp(args, logger)
    elif args.command == "list":
        _list_components(args, logger)
    elif args.command == "report":
        _generate_report(args, logger)
    elif args.command == "recon":
        _run_recon(args, logger)
    else:
        # 无子命令时启动专家引导向导
        _run_wizard(logger)


def _run_wizard(logger):
    """
    专家引导向导（无子命令时自动启动）

    引导用户逐步完成：
    0. 选择模式（攻击 / 侦察）
    1. 选择目标
    2. 选择攻击范围 / 侦察深度
    3. 设置攻击目标 / 执行侦察
    4. 确认并执行
    """
    from pathlib import Path

    targets_dir = Path("config/targets")

    print()
    print("=" * 60)
    print("  AI-300 红队评估框架 - 专家引导模式")
    print("=" * 60)
    print()

    # ── 步骤 0：选择模式 ──
    print("  [步骤 0] 选择操作模式")
    print("  " + "─" * 40)
    print("    1. 攻击（Attack）- 执行 OWASP 标准攻击")
    print("    2. 侦察（Recon）- 先侦察目标，生成画像")
    print()
    print("    输入 1 或 2 选择模式，输入 q 退出")
    print()

    try:
        mode_choice = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消")
        return

    if mode_choice.lower() == "q":
        print("  已退出")
        return

    if mode_choice == "2":
        _run_wizard_recon(logger)
        return
    elif mode_choice != "1":
        print("  ✗ 无效选择，默认进入攻击模式")
        print()

    # ── 步骤 1：选择目标 ──
    while True:
        if not targets_dir.exists() or not targets_dir.is_dir():
            print(f"  ✗ 目标配置目录不存在: {targets_dir}")
            print(f"    请创建该目录并添加目标 YAML 配置文件")
            return

        yaml_files = sorted(targets_dir.glob("*.yaml"))
        if not yaml_files:
            print(f"  ✗ 目标配置目录为空: {targets_dir}")
            print(f"    请添加目标 YAML 配置文件")
            return

        print("  [步骤 1/3] 选择攻击目标")
        print("  " + "─" * 40)
        for idx, yf in enumerate(yaml_files, 1):
            print(f"    {idx}. {yf.name}")
        print()
        print(f"    输入 1-{len(yaml_files)} 选择目标，输入 q 退出")
        print()

        try:
            choice = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  已取消")
            return

        if choice.lower() == "q":
            print("  已退出")
            return

        try:
            idx = int(choice)
            if 1 <= idx <= len(yaml_files):
                selected_target = str(yaml_files[idx - 1])
                print(f"\n  ✓ 已选择: {yaml_files[idx - 1].name}")
                break
            else:
                print(f"  ✗ 无效选择，请输入 1-{len(yaml_files)}")
        except ValueError:
            print("  ✗ 请输入数字")
        print()

    # ── 步骤 2：选择攻击范围（动态扫描 config/placeholders/） ──
    print()
    print("  [步骤 2/3] 选择攻击范围")
    print("  " + "─" * 40)

    scopes = discover_scopes()
    if not scopes:
        print("  ✗ 未找到任何 scope（config/placeholders/ 下无 manifest.yaml）")
        return

    # 分组：LLM vs Agentic
    llm_scopes = [s for s in scopes if s["id"].startswith("llm")]
    asi_scopes = [s for s in scopes if s["id"].startswith("asi")]

    idx = 0
    scope_map = {}  # idx -> scope_id

    if llm_scopes:
        print("    ── LLM Top 10 ──")
        for s in llm_scopes:
            idx += 1
            scope_map[idx] = s["id"]
            print(f"    {idx:>2}. {s['id']:<6} - {s['name']}（{s['description']}）")
        # LLM 分组选项
        idx += 1
        scope_map[idx] = "llm"
        print(f"    {idx:>2}. llm    - 全部 LLM Top 10")

    if asi_scopes:
        print("    ── Agentic Top 10 ──")
        for s in asi_scopes:
            idx += 1
            scope_map[idx] = s["id"]
            print(f"    {idx:>2}. {s['id']:<6} - {s['name']}（{s['description']}）")
        # Agentic 分组选项
        idx += 1
        scope_map[idx] = "agentic"
        print(f"    {idx:>2}. agentic - 全部 Agentic Top 10")

    # 全部选项
    idx += 1
    scope_map[idx] = "all"
    print(f"    {idx:>2}. all    - 全部 {len(scopes)} 项")
    print()
    print(f"    输入 1-{idx} 选择范围，输入 q 退出")
    print()

    while True:
        try:
            choice = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  已取消")
            return

        if choice.lower() == "q":
            print("  已退出")
            return

        try:
            choice_idx = int(choice)
            if choice_idx in scope_map:
                selected_scope = scope_map[choice_idx]
                print(f"\n  ✓ 已选择: {selected_scope}")
                break
            else:
                print(f"  ✗ 无效选择，请输入 1-{idx}")
        except ValueError:
            print("  ✗ 请输入数字")
        print()

    # ── 步骤 3：确认攻击目标和参数 ──
    import yaml
    from pathlib import Path

    # 加载 scope 的默认 goals 和占位符
    scope_goals = load_scope_goals(selected_scope)
    auto_ph = auto_discover_placeholders(selected_scope)

    print()
    print("  [步骤 3/3] 确认攻击配置")
    print("  " + "─" * 40)

    # 显示 {goal} 目标列表
    if scope_goals:
        print(f"    攻击目标 ({len(scope_goals)} 个，来自 data/owasp/llm/{selected_scope}/_goals.yaml):")
        for i, g in enumerate(scope_goals[:3], 1):
            preview = g[:60] + "..." if len(g) > 60 else g
            print(f"      {i}. {preview}")
        if len(scope_goals) > 3:
            print(f"      ... 还有 {len(scope_goals) - 3} 个")
        print()

    # 显示 Tier 3 占位符默认值
    if auto_ph:
        print(f"    领域参数 (默认值):")
        for k, v in list(auto_ph.items())[:5]:
            print(f"      {k} = {v}")
        if len(auto_ph) > 5:
            print(f"      ... 还有 {len(auto_ph) - 5} 个")
        print()

    print("    按 Enter 使用默认配置，或输入自定义目标")
    print("    格式: 目标文本（如 whoami）")
    print()

    try:
        choice = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消")
        return

    if choice.lower() == "q":
        print("  已退出")
        return

    selected_objective = None
    selected_placeholders = None
    selected_config_name = None

    if not choice:
        # 使用默认配置（goals + 占位符默认值）
        all_placeholders = auto_ph.copy() if auto_ph else {}

        if scope_goals:
            selected_objective = scope_goals[0]  # 预览第一个目标
            selected_config_name = f"_goals.yaml ({len(scope_goals)} 个目标)"
            print(f"  ✓ 已加载默认配置: {selected_config_name}")
        else:
            selected_config_name = "默认（无目标）"
            print(f"  ✓ 已加载默认配置")

        if selected_objective:
            preview = selected_objective[:50] + "..." if len(selected_objective) > 50 else selected_objective
            print(f"    攻击目标: {preview}")
        if all_placeholders:
            print(f"    占位符参数: {', '.join(all_placeholders.keys())}")

        selected_placeholders = all_placeholders if all_placeholders else None
    else:
        # 自定义目标
        selected_objective = choice
        selected_placeholders = auto_ph if auto_ph else None
        selected_config_name = "自定义"
        print(f"  ✓ 攻击目标: '{choice}'")

    # ── 确认并执行 ──
    print()
    print("  " + "=" * 40)
    print("  执行确认")
    print("  " + "=" * 40)
    print(f"    目标文件: {selected_target}")
    print(f"    攻击范围: {selected_scope}")
    if selected_config_name:
        print(f"    载荷配置: {selected_config_name}")
    print(f"    攻击目标: {selected_objective or '（使用载荷文本）'}")
    print()
    print("    输入 y 开始执行，输入 n 取消")
    print()

    try:
        confirm = input("  > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消")
        return

    if confirm != "y":
        print("  已取消")
        return

    print()
    print("  🚀 开始执行...")
    print()

    # 构建参数命名空间并执行
    import argparse
    exec_args = argparse.Namespace(
        command="owasp",
        scope=selected_scope,
        target_file=selected_target,
        target_dir=None,
        target_url=None,
        output=None,
        format="markdown",
        profile=None,
        model=None,
        objective=selected_objective,
        placeholders=selected_placeholders,
        list_placeholders=False,
        no_prompt=False,
        placeholder_file=None,
        experiment=None,
        auto_recon=False,
        scorer_url=None,
        scorer_key=None,
        scorer_model=None,
        verbose=False,
    )
    _run_owasp(exec_args, logger)


def _run_wizard_recon(logger):
    """
    侦察引导向导（AIMAP → Garak 顺序侦察，已整合到 ReconEngine.run() 内部）

    引导用户逐步完成：
    1. 选择目标（菜单选择 config/targets/ 或手动输入 URL）
    2. 确认并执行侦察（AIMAP 优先 → Garak 配置 → 剩余工具）
    """
    from pyrit_ai300.reconnaissance import ReconEngine
    from pyrit_ai300.pipeline import PipelineTracker
    from pathlib import Path

    # ── 步骤 1：选择目标 ──
    print()
    print("  [步骤 1/2] 选择侦察目标")
    print("  " + "─" * 40)

    targets_dir = Path("config/targets")
    yaml_files = sorted(targets_dir.glob("*.yaml")) if targets_dir.exists() else []

    target = None
    if yaml_files:
        # 显示目标菜单
        for idx, yf in enumerate(yaml_files, 1):
            try:
                import yaml
                with open(yf, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                name = data.get("target", {}).get("name", "")
                desc = data.get("target", {}).get("description", "")
                label = f" ({name})" if name else ""
                if desc:
                    label += f" — {desc}"
            except Exception:
                label = ""
            print(f"    {idx}. {yf.name}{label}")
        print(f"    {len(yaml_files) + 1}. [手动输入 URL]")
        print()
        print(f"    输入 1-{len(yaml_files) + 1} 选择目标，输入 q 退出")
        print()

        try:
            choice = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  已取消")
            return

        if choice.lower() == "q":
            print("  已退出")
            return

        try:
            idx = int(choice)
            if 1 <= idx <= len(yaml_files):
                target_file = str(yaml_files[idx - 1])
                target = ReconEngine.load_target(target_file)
                print(f"\n  ✓ 已选择: {yaml_files[idx - 1].name}")
            elif idx == len(yaml_files) + 1:
                print()
                print("    输入目标 URL 或 endpoint")
                print("    例如: http://target.com 或 http://localhost:11434")
                print()
                try:
                    target = input("  > ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\n  已取消")
                    return
                if target.lower() == "q":
                    print("  已退出")
                    return
                if not target:
                    print("  ✗ 目标不能为空")
                    return
                print(f"\n  ✓ 侦察目标: {target}")
            else:
                print(f"  ✗ 无效选择，请输入 1-{len(yaml_files) + 1}")
                return
        except ValueError:
            print("  ✗ 请输入数字")
            return
    else:
        print("    config/targets/ 目录不存在或为空")
        print("    请手动输入目标 URL")
        print("    例如: http://target.com 或 http://localhost:11434")
        print()
        print("    输入目标 URL，输入 q 退出")
        print()

        try:
            target = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  已取消")
            return

        if target.lower() == "q":
            print("  已退出")
            return

        if not target:
            print("  ✗ 目标不能为空")
            return

        print(f"\n  ✓ 侦察目标: {target}")

    # ── 步骤 2：确认并执行 ──
    print()
    print("  [步骤 2/2] 侦察执行确认")
    print("  " + "=" * 40)
    print(f"    目标:     {target}")
    print(f"    侦察模式: AIMAP → Garak → DeepTeam（自动顺序执行）")
    print()
    print("    输入 y 开始执行，输入 n 取消")
    print()

    try:
        confirm = input("  > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消")
        return

    if confirm != "y":
        print("  已取消")
        return

    print()
    print("  🔍 开始侦察...")
    print()

    # 执行侦察（AIMAP → Garak 顺序已整合到 ReconEngine.run() 内部）
    tracker = PipelineTracker(verbose=True)
    engine = ReconEngine()

    # 检查工具可用性
    tool_status = engine.check_tools()
    available_tools = [t for t, ok in tool_status.items() if ok]
    if not available_tools:
        print("  ⚠ 未检测到可用侦察工具（Garak / DeepTeam）")
        print("    请确保已安装: pip install garak deeteam")
        return

    print(f"  可用工具: {', '.join(available_tools)}")
    print()

    # 运行侦察（AIMAP 优先 → Garak 配置 → 剩余工具，全部由 engine.run() 处理）
    profile = engine.run(
        target=target,
        depth="standard",
        tools=None,  # 运行全部启用工具
        tracker=tracker,
    )

    # 保存结果
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"results/recon/wizard_profile_{timestamp}.json"
    profile.save(output_path)

    # 打印摘要
    print()
    print("  " + "=" * 40)
    print("  侦察完成")
    print("  " + "=" * 40)
    print(f"  目标:         {profile.target}")
    print(f"  使用工具:     {', '.join(profile.tools_used)}")
    print(f"  漏洞发现:     {profile.vulnerability_count}")
    print(f"  风险等级:     {profile.risk_level}")
    print(f"  OWASP 映射:   {', '.join(profile.get_owasp_mappings())}")
    print(f"  画像保存至:   {output_path}")
    print()

    # 打印冲突检测和交叉验证结果
    conflicts = [v for v in profile.vulnerabilities if v.conflict]
    cross_validated = [v for v in profile.vulnerabilities if len(v.source_tools) >= 2 and not v.conflict]
    if conflicts:
        print(f"  ⚠ 工具间冲突 (severity 差异 ≥ 2):")
        for v in conflicts:
            print(f"    • {v.owasp_mapping}: {', '.join(v.source_tools)} → severity={v.severity}")
    if cross_validated:
        print(f"  ✓ 交叉验证 (置信度提升):")
        for v in cross_validated:
            print(f"    • {v.owasp_mapping}: {', '.join(v.source_tools)} → confidence={v.confidence:.2f}")
    print()
    print("  提示: 使用以下命令基于画像执行攻击:")
    print(f"    ai300 owasp llm01 --target-url {target} --profile {output_path}")
    print()


def _resolve_targets(args):
    """
    解析目标列表（统一接口）

    Returns:
        list of (target_config, target_url) tuples
        - target_config: YAML 文件路径（或 None）
        - target_url: 直接 URL（或 None）
    """
    targets = []

    # --target-url：直接 URL
    if args.target_url:
        targets.append((None, args.target_url))

    # --target-file：单个 YAML 文件
    if args.target_file:
        targets.append((args.target_file, None))

    # --target-dir：目录下所有 YAML 文件
    if args.target_dir:
        from pathlib import Path
        target_dir = Path(args.target_dir)
        if not target_dir.is_dir():
            raise ValueError(f"--target-dir is not a directory: {args.target_dir}")
        yaml_files = sorted(target_dir.glob("*.yaml"))
        if not yaml_files:
            raise ValueError(f"No YAML files found in --target-dir: {args.target_dir}")
        for yaml_file in yaml_files:
            targets.append((str(yaml_file), None))

    return targets


# 占位符中文名映射
PLACEHOLDER_LABELS_CN = {
    # Tier 1
    "goal": "攻击目标",
    "objective": "攻击目标",
    # Tier 2 编码变体
    "base64_goal": "Base64编码目标",
    "base32_goal": "Base32编码目标",
    "ascii85_goal": "ASCII85编码目标",
    "french_goal": "法语翻译目标",
    "bidi_override_goal": "Bidi覆盖目标",
    "unicode_tag_goal": "Unicode标签目标",
    "zalgo_goal": "Zalgo变形目标",
    "chain_encoded_goal": "链式编码目标",
    "ascii_tag_deep_goal": "深层ASCII标签目标",
    "hex_goal": "十六进制编码目标",
    "rot13_goal": "ROT13编码目标",
    "sneaky_bits_goal": "隐蔽位编码目标",
    "interlinear_ws_goal": "行间空白编码目标",
    "multi_tag_mix_goal": "多标签混合编码目标",
    # Tier 3 领域参数
    "domain": "目标域名",
    "task": "攻击任务",
    "language": "编程语言",
    "target_host": "目标主机",
    "target_port": "目标端口",
    "false_claim": "虚假声明",
    "toxicity_prompt": "毒性提示",
    "address": "目标地址",
    "email": "目标邮箱",
    "user_input": "用户输入",
    "target_group": "目标群体",
    "action_verb": "动作动词",
    "action_definition": "动作定义",
    "context_object": "上下文对象",
    "target_object": "目标对象",
    "fake_info": "虚假信息",
    "input_string": "输入字符串",
    "center": "中心位置",
    "tabular": "表格内容",
    "goal_description": "目标描述",
    "injected_js": "注入JS代码",
    "injected_strings": "注入字符串",
    "injected_marker": "注入标记",
    "injected_action": "注入动作",
    "modified_domain": "修改后域名",
    "python_code": "Python代码",
    "sql_payload": "SQL载荷",
    "sql_command": "SQL命令",
    "malware_payload": "恶意软件载荷",
    "evasion_task": "规避任务",
    "subfunction": "子功能",
    "collection_name": "集合名称",
    "target_db": "目标数据库",
    "tenant": "租户",
    "db": "数据库",
    "captured_token": "捕获的令牌",
    "exploit_strategies": "利用策略",
    "functionality": "功能描述",
    "target_tool": "目标工具",
    "tool_name": "工具名称",
    "vulnerabilities": "漏洞列表",
    "text_prefix": "文本前缀",
    "current_date": "当前日期",
    "user_name": "用户名",
    "v": "变量值",
    "encoding": "编码方式",
}


def _get_placeholder_label(name: str) -> str:
    """获取占位符的中文标签"""
    return PLACEHOLDER_LABELS_CN.get(name, name)


def _parse_placeholders(placeholders_str: Optional[str]) -> Optional[Dict[str, str]]:
    """
    解析 --placeholders 参数（key=value,key=value 格式）

    支持一次传入多个，格式：key1=value1,key2=value2,...

    Args:
        placeholders_str: 逗号分隔的 key=value 字符串

    Returns:
        占位符字典，或 None
    """
    if not placeholders_str:
        return None
    result = {}
    for pair in placeholders_str.split(","):
        pair = pair.strip()
        if "=" not in pair:
            raise ValueError(
                f"无效的占位符格式: '{pair}'。正确格式: 'key=value'（多个用逗号分隔）"
            )
        key, value = pair.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _list_placeholders(args, logger):
    """
    列出指定 scope 中所有载荷使用的占位符
    """
    import re
    from pyrit_ai300.payloads.payload_manager import PayloadManager
    from pyrit_ai300.orchestrators.attack_orchestrator import _extract_payload_text

    pm = PayloadManager()
    pm.load_data_dir("data/")

    scope = args.scope
    refs = pm.get_scope_refs(scope)

    if not refs:
        print(f"No payloads found for scope: {scope}")
        return

    # 收集所有占位符
    all_placeholders = {}  # placeholder_name -> set of ref_paths
    for ref in refs:
        data = pm._payload_store.get(ref, {})
        for entry in data.get("payloads", []):
            if isinstance(entry, dict):
                text = entry.get("payload", "")
            else:
                text = str(entry)
            # 查找所有 {word} 占位符
            matches = re.findall(r'\{([a-z_][a-z0-9_]{1,})\}', text)
            for m in matches:
                if m not in all_placeholders:
                    all_placeholders[m] = set()
                all_placeholders[m].add(ref)

    if not all_placeholders:
        print(f"\n范围 '{scope}'（{len(refs)} 个载荷）: 未发现占位符。")
        return

    # 分类显示
    tier1 = {"goal", "objective"}
    tier2_encodings = {
        "base64_goal", "base32_goal", "ascii85_goal", "french_goal",
        "bidi_override_goal", "unicode_tag_goal", "zalgo_goal",
        "chain_encoded_goal", "ascii_tag_deep_goal",
        "hex_goal", "rot13_goal", "sneaky_bits_goal",
        "interlinear_ws_goal", "multi_tag_mix_goal",
    }

    print(f"\n{'='*60}")
    print(f" 范围 {scope} 的占位符清单（{len(refs)} 个载荷）")
    print(f"{'='*60}")

    # Tier 1
    tier1_found = {k: v for k, v in all_placeholders.items() if k in tier1}
    if tier1_found:
        print(f"\n  [第1级] 攻击目标（使用 --objective 参数）:")
        for ph, files in sorted(tier1_found.items()):
            print(f"    {_get_placeholder_label(ph)}（{{{ph}}}）— {len(files)} 个载荷")

    # Tier 2
    tier2_found = {k: v for k, v in all_placeholders.items() if k in tier2_encodings}
    if tier2_found:
        print(f"\n  [第2级] 编码变体（根据 --objective 自动编码）:")
        for ph, files in sorted(tier2_found.items()):
            print(f"    {_get_placeholder_label(ph)}（{{{ph}}}）— {len(files)} 个载荷")

    # Tier 3
    tier3_found = {k: v for k, v in all_placeholders.items()
                   if k not in tier1 and k not in tier2_encodings}
    if tier3_found:
        print(f"\n  [第3级] 领域参数（使用 --placeholders key=value 参数）:")
        for ph, files in sorted(tier3_found.items()):
            print(f"    {_get_placeholder_label(ph)}（{{{ph}}}）— {len(files)} 个载荷")
            # 显示来源文件示例
            for ref in sorted(files)[:2]:
                print(f"        └─ {ref}")
            if len(files) > 2:
                print(f"        └─ ... 还有 {len(files)-2} 个")

    print(f"\n 用法示例:")
    print(f"   --objective 'whoami'                        → 填充第1级 + 第2级")
    print(f"   --placeholders 'domain=evil.com,task=whoami' → 填充第3级")
    print(f"   （多个参数用逗号分隔，无数量限制）")
    print(f"{'='*60}\n")


def _scan_scope_placeholders(scope: str) -> Dict[str, set]:
    """
    扫描指定 scope 中所有载荷使用的占位符

    Args:
        scope: OWASP scope

    Returns:
        占位符名称 → 来源 ref_path 集合 的字典
    """
    import re
    from pyrit_ai300.payloads.payload_manager import PayloadManager

    pm = PayloadManager()
    pm.load_data_dir("data/")
    refs = pm.get_scope_refs(scope)

    all_placeholders = {}
    for ref in refs:
        data = pm._payload_store.get(ref, {})
        for entry in data.get("payloads", []):
            if isinstance(entry, dict):
                text = entry.get("payload", "")
            else:
                text = str(entry)
            matches = re.findall(r'\{([a-z_][a-z0-9_]{1,})\}', text)
            for m in matches:
                if m not in all_placeholders:
                    all_placeholders[m] = set()
                all_placeholders[m].add(ref)

    return all_placeholders


def _interactive_prompt_placeholders(args, logger) -> tuple:
    """
    交互式提示用户补齐缺失的占位符（中文界面）

    对于已在模板 placeholders 段声明默认值的占位符，不提示用户输入。

    Returns:
        (objective, placeholders) 元组
    """
    tier1_names = {"goal", "objective"}
    tier2_encodings = {
        "base64_goal", "base32_goal", "ascii85_goal", "french_goal",
        "bidi_override_goal", "unicode_tag_goal", "zalgo_goal",
        "chain_encoded_goal", "ascii_tag_deep_goal",
        "hex_goal", "rot13_goal", "sneaky_bits_goal",
        "interlinear_ws_goal", "multi_tag_mix_goal",
    }

    # 扫描 scope 的占位符
    all_ph = _scan_scope_placeholders(args.scope)

    if not all_ph:
        return args.objective, _parse_placeholders(getattr(args, "placeholders", None))

    # 收集已声明默认值的占位符（从模板 placeholders 段）
    declared_defaults = set()
    from pathlib import Path
    import yaml
    scope_dir = Path("data/owasp/llm") / args.scope
    if scope_dir.exists():
        for yaml_file in scope_dir.rglob("*.yaml"):
            if yaml_file.name.startswith("_"):
                continue
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                ph_defs = data.get("placeholders", {})
                declared_defaults.update(ph_defs.keys())
            except Exception:
                pass

    # 分类
    tier1_found = {k: v for k, v in all_ph.items() if k in tier1_names}
    # Tier 3：排除已有默认值的占位符
    tier3_found = {k: v for k, v in all_ph.items()
                   if k not in tier1_names and k not in tier2_encodings
                   and k not in declared_defaults}

    objective = args.objective
    placeholders = _parse_placeholders(getattr(args, "placeholders", None)) or {}

    # 检查是否需要交互提示
    need_tier1_prompt = tier1_found and not objective
    need_tier3_prompt = tier3_found and not all(k in placeholders for k in tier3_found)

    if not need_tier1_prompt and not need_tier3_prompt:
        return objective, placeholders if placeholders else None

    print(f"\n{'─'*60}")
    print(f" ⚠️  占位符向导 — 范围: {args.scope}")
    print(f"{'─'*60}")

    # Tier 1 提示
    if need_tier1_prompt:
        total_payloads = sum(len(v) for v in tier1_found.values())
        tier1_labels = "、".join(
            f"{_get_placeholder_label(k)}" for k in sorted(tier1_found.keys())
        )
        print(f"\n  [第1级] {total_payloads} 个载荷需要攻击目标")
        print(f"    包含: {tier1_labels}")
        # 显示来源示例
        for ph, files in sorted(tier1_found.items())[:3]:
            sample_refs = sorted(files)[:2]
            for ref in sample_refs:
                print(f"      {_get_placeholder_label(ph)} ← {ref}")
            if len(files) > 2:
                print(f"      ... 还有 {len(files)-2} 个文件")
        print()
        try:
            user_input = input("  请输入攻击目标（按 Enter 跳过）: ").strip()
            if user_input:
                objective = user_input
                print(f"  ✓ 攻击目标已设置: '{objective}'")
            else:
                print(f"  ⚠ 已跳过 — 将使用载荷文本本身作为目标")
        except (EOFError, KeyboardInterrupt):
            print(f"\n  ⚠ 已跳过 — 将使用载荷文本本身作为目标")

    # Tier 3 提示
    if need_tier3_prompt:
        missing_tier3 = {k: v for k, v in tier3_found.items() if k not in placeholders}
        if missing_tier3:
            print(f"\n  [第3级] 需要以下领域参数:")
            for ph, files in sorted(missing_tier3.items()):
                label = _get_placeholder_label(ph)
                print(f"    {label}（{{{ph}}}）— {len(files)} 个载荷")
                sample_refs = sorted(files)[:1]
                for ref in sample_refs:
                    print(f"        └─ {ref}")
            print()
            # 生成示例
            examples = []
            for ph in sorted(missing_tier3.keys())[:3]:
                examples.append(f"{ph}=示例值")
            example_str = ",".join(examples)
            print(f"  格式: key=value（多个用逗号分隔，无数量限制）")
            print(f"  示例: {example_str}")
            print()
            try:
                user_input = input("  > ").strip()
                if user_input:
                    parsed = _parse_placeholders(user_input)
                    if parsed:
                        placeholders.update(parsed)
                        cn_labels = [_get_placeholder_label(k) for k in parsed.keys()]
                        print(f"  ✓ 已设置: {', '.join(cn_labels)}")
                else:
                    print(f"  ⚠ 已跳过 — 占位符将保持原样输出")
            except (EOFError, KeyboardInterrupt):
                print(f"\n  ⚠ 已跳过 — 占位符将保持原样输出")

    print(f"{'─'*60}\n")
    return objective, placeholders if placeholders else None


def _normalize_objectives(objective, placeholders) -> list:
    """
    将 objective 标准化为列表

    支持以下输入格式：
    - None → [None]（使用载荷文本本身）
    - "whoami" → ["whoami"]
    - ["whoami", "cat /etc/passwd"] → ["whoami", "cat /etc/passwd"]
    - placeholders 中的 objective 列表
    """
    # 优先使用 CLI 参数
    if objective:
        if isinstance(objective, list):
            return objective
        # 支持逗号分隔多个目标
        if "," in objective:
            return [o.strip() for o in objective.split(",") if o.strip()]
        return [objective]

    # 从 placeholders 获取
    ph_obj = placeholders.get("objective")
    if ph_obj:
        if isinstance(ph_obj, list):
            return ph_obj
        return [ph_obj]

    # 无 objective，使用载荷文本本身
    return [None]


def load_placeholder_file(file_path: str) -> Dict[str, str]:
    """
    加载占位符配置文件（YAML 格式）

    Args:
        file_path: YAML 文件路径

    Returns:
        占位符字典（过滤掉空值）
    """
    import yaml
    from pathlib import Path

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"占位符配置文件不存在: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # 过滤空值，只返回有值的占位符
    # objective 支持字符串或列表（多目标）
    result = {}
    for k, v in data.items():
        if not v:
            continue
        if k == "objective" and isinstance(v, list):
            # 过滤空字符串
            objectives = [x for x in v if x and str(x).strip()]
            if objectives:
                result[k] = objectives
        elif isinstance(v, (str, int, float)):
            result[k] = v
    return result


def load_experiment_config(experiment_path: str) -> Dict[str, Any]:
    """
    加载实验配置文件

    实验配置是一个 YAML 文件，定义了一次实验所需的全部参数：
    - objective: Tier 1 攻击目标
    - placeholders: Tier 3 领域参数
    - payloads: 关联的实验数据文件列表
    - execution: 执行参数覆盖

    Args:
        experiment_path: 实验配置路径（相对于 data/owasp/expericing/）
                         如 "tier1_goal" → data/owasp/expericing/tier1_goal/experiment.yaml

    Returns:
        实验配置字典，包含 objective, placeholders, payloads, execution
    """
    import yaml
    from pathlib import Path

    # 构建完整路径：data/owasp/expericing/{path}/experiment.yaml
    config_path = Path("data/owasp/expericing") / experiment_path / "experiment.yaml"
    if not config_path.exists():
        # 尝试旧路径（向后兼容）
        config_path = Path("config/placeholders") / f"{experiment_path}.yaml"
        if not config_path.exists():
            config_path = Path("config/placeholders") / experiment_path

    if not config_path.exists():
        raise FileNotFoundError(
            f"实验配置不存在: {experiment_path}\n"
            f"查找路径: data/owasp/expericing/{experiment_path}/experiment.yaml\n"
            f"请确保文件存在"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # 标准化输出
    result = {
        "name": config.get("name", experiment_path),
        "description": config.get("description", ""),
        "version": config.get("version", "1.0"),
        "objective": [],
        "placeholders": {},
        "experiment_data": config.get("experiment_data"),
        "payloads": config.get("payloads", []),
        "execution": config.get("execution", {}),
        "config_path": str(config_path),
    }

    # 解析 objective
    obj = config.get("objective")
    if obj:
        if isinstance(obj, list):
            result["objective"] = [x for x in obj if x and str(x).strip()]
        elif isinstance(obj, str) and obj.strip():
            result["objective"] = [obj.strip()]

    # 解析 placeholders
    ph = config.get("placeholders", {})
    if ph:
        for k, v in ph.items():
            if v is not None and str(v).strip():
                result["placeholders"][k] = v

    return result


def load_scope_goals(scope: str) -> list:
    """
    加载 scope 的攻击目标列表（{goal} / {objective} 的值）

    自动合并框架默认值和用户自定义值：
    1. 框架默认：data/owasp/llm/{scope}/_goals.yaml
    2. 用户自定义：config/placeholders/{scope}/_goals.yaml
       - merge_strategy: append（默认）— 框架默认 + 用户新增
       - merge_strategy: prepend — 用户新增 + 框架默认
       - merge_strategy: replace — 仅使用用户自定义

    Args:
        scope: OWASP scope (如 "llm01", "llm05")

    Returns:
        攻击目标字符串列表
    """
    import yaml
    from pathlib import Path

    # 1. 加载框架默认值
    default_path = Path("data/owasp/llm") / scope / "_goals.yaml"
    defaults = []
    if default_path.exists():
        try:
            with open(default_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            defaults = data.get("goals", [])
        except Exception:
            pass

    # 2. 加载用户自定义
    custom_path = Path("config/placeholders") / scope / "_goals.yaml"
    if not custom_path.exists():
        return defaults

    try:
        with open(custom_path, "r", encoding="utf-8") as f:
            custom = yaml.safe_load(f) or {}
    except Exception:
        return defaults

    strategy = custom.get("merge_strategy", "append")
    user_goals = custom.get("goals", [])

    if not user_goals:
        return defaults

    # 3. 按策略合并
    if strategy == "replace":
        return user_goals
    elif strategy == "prepend":
        return user_goals + defaults
    else:  # append (默认)
        return defaults + user_goals


def discover_scopes() -> list[Dict[str, str]]:
    """
    扫描 data/owasp/llm/ 目录，发现所有可用 scope

    返回包含模板文件的目录，按 scope id 排序。

    Returns:
        scope 列表，每项包含 id, name, description
    """
    from pathlib import Path

    llm_dir = Path("data/owasp/llm")
    if not llm_dir.exists():
        return []

    scopes = []
    scope_names = {
        "llm01": ("提示注入", "Prompt Injection"),
        "llm02": ("敏感信息泄露", "Sensitive Information Disclosure"),
        "llm03": ("供应链攻击", "Supply Chain"),
        "llm04": ("数据与模型投毒", "Data & Model Poisoning"),
        "llm05": ("不安全输出处理", "Insecure Output Handling"),
        "llm06": ("过度代理", "Excessive Agency"),
        "llm07": ("系统提示泄露", "System Prompt Leak"),
        "llm08": ("向量与嵌入弱点", "Vector & Embedding Weaknesses"),
        "llm09": ("错误信息误导", "Misinformation"),
        "llm10": ("无界消耗", "Unbounded Consumption"),
    }

    for entry in sorted(llm_dir.iterdir()):
        if not entry.is_dir():
            continue
        # 检查是否有模板文件（至少一个 .yaml 文件）
        yaml_files = list(entry.glob("*.yaml")) + list(entry.glob("**/*.yaml"))
        if not yaml_files:
            continue
        name, desc = scope_names.get(entry.name, (entry.name, ""))
        scopes.append({
            "id": entry.name,
            "name": name,
            "description": desc,
        })
    return scopes


def auto_discover_placeholders(scope: str) -> Dict[str, Any]:
    """
    自动发现 scope 对应的占位符默认值

    从模板 YAML 的 placeholders 段中提取默认值。
    同时加载用户自定义覆盖（config/placeholders/{scope}/_goals.yaml）。

    Args:
        scope: OWASP scope (如 "llm01", "asi01")

    Returns:
        合并后的占位符字典，目录不存在返回空字典
    """
    import yaml
    from pathlib import Path

    merged = {}

    # 1. 从模板中提取 Tier 3 占位符默认值
    scope_dir = Path("data/owasp/llm") / scope
    if scope_dir.exists():
        for yaml_file in sorted(scope_dir.rglob("*.yaml")):
            if yaml_file.name.startswith("_"):
                continue  # 跳过 _goals.yaml
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                ph_defs = data.get("placeholders", {})
                for k, v in ph_defs.items():
                    if isinstance(v, dict) and "default" in v:
                        merged[k] = v["default"]
                    elif isinstance(v, (str, int, float)):
                        merged[k] = v
            except Exception:
                pass

    # 2. 加载用户自定义覆盖（config/placeholders/{scope}/ 下的 YAML）
    custom_dir = Path("config/placeholders") / scope
    if custom_dir.exists():
        for yaml_file in sorted(custom_dir.glob("*.yaml")):
            if yaml_file.name.startswith("_"):
                continue
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                for k, v in data.items():
                    if k in ("merge_strategy", "goals"):
                        continue
                    if v is not None and str(v).strip():
                        merged[k] = v
            except Exception:
                pass

    return merged


def validate_placeholders(scope: str, placeholders: Dict[str, str]) -> tuple:
    """
    校验占位符是否满足 scope 需求

    从模板 YAML 的 placeholders 段和 payload 文本中提取占位符需求。

    Args:
        scope: OWASP scope
        placeholders: 用户提供的占位符字典

    Returns:
        (missing_required, extra_placeholders) 元组
    """
    import re
    from pathlib import Path

    scope_dir = Path("data/owasp/llm") / scope
    if not scope_dir.exists():
        return [], list(placeholders.keys())

    # 收集 scope 中所有实际使用的占位符
    used_placeholders = set()
    declared_placeholders = set()

    for yaml_file in scope_dir.rglob("*.yaml"):
        if yaml_file.name.startswith("_"):
            continue
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            # 从 placeholders 段收集已声明占位符
            ph_defs = data.get("placeholders", {})
            declared_placeholders.update(ph_defs.keys())
            # 从 payload 文本收集所有占位符引用
            for entry in data.get("payloads", []):
                if isinstance(entry, dict):
                    text = entry.get("payload", "")
                else:
                    text = str(entry)
                matches = re.findall(r'\{([a-z_][a-z0-9_]{1,})\}', text)
                used_placeholders.update(matches)
        except Exception:
            pass

    # 编码变体占位符（Tier 2）由 objective 自动衍生，不算缺失
    tier2_encodings = {
        "base64_goal", "base32_goal", "ascii85_goal", "french_goal",
        "bidi_override_goal", "unicode_tag_goal", "zalgo_goal",
        "chain_encoded_goal", "ascii_tag_deep_goal",
        "hex_goal", "rot13_goal", "sneaky_bits_goal",
        "interlinear_ws_goal", "multi_tag_mix_goal",
    }

    # 检查缺失（排除 Tier 2 编码变体，排除已声明有默认值的占位符）
    missing = []
    for ph in used_placeholders:
        if ph in tier2_encodings:
            continue
        if ph in ("objective", "goal"):
            obj = placeholders.get("objective")
            if not obj or (isinstance(obj, list) and not any(obj)):
                missing.append(ph)
        elif ph not in placeholders and ph not in declared_placeholders:
            missing.append(ph)

    # 检查多余
    extra = [k for k in placeholders.keys()
             if k not in used_placeholders and k != "objective"]

    return missing, extra


def _print_partial_summary(results):
    """打印中断时的部分结果摘要"""
    total_success = 0
    total_failure = 0
    total_tests = 0
    for result in results:
        for attack in result.get("attacks", []):
            success = attack.get("success_count", 0)
            failure = attack.get("failure_count", 0)
            total_success += success
            total_failure += failure
            total_tests += success + failure
            scope = result.get("scope", "unknown")
            rate = (success / (success + failure) * 100) if (success + failure) > 0 else 0
            print(f"    {scope}: {success}/{success + failure} passed ({rate:.0f}%)")
    if total_tests > 0:
        overall_rate = total_success / total_tests * 100
        print(f"\n  总计: {total_success}/{total_tests} passed ({overall_rate:.0f}%)")
    print(f"\n  提示: 已保存部分结果到 results/ 目录")


def _run_owasp(args, logger):
    """执行 OWASP 标准攻击（支持多目标逐一分批）"""
    from pyrit_ai300 import AI300Engine
    from pyrit_ai300.pipeline import PipelineTracker
    from pyrit_ai300.reconnaissance import ReconEngine

    # --list-placeholders：列出占位符后退出
    if getattr(args, "list_placeholders", False):
        _list_placeholders(args, logger)
        return

    # ── 占位符解析优先级：--experiment > --objective > 自动发现 > --placeholder-file > 交互式提示 ──
    objective = args.objective
    placeholders = _parse_placeholders(getattr(args, "placeholders", None)) or {}

    # 0. 加载 --experiment 配置（最高优先级）
    experiment_config = None
    experiment_arg = getattr(args, "experiment", None)
    if experiment_arg:
        experiment_config = load_experiment_config(experiment_arg)
        logger.info("Loaded experiment config: %s (%s)", experiment_config["name"], experiment_config["description"])
        print(f"\n  🧪 实验模式: {experiment_config['name']}")
        print(f"     {experiment_config['description']}")
        if experiment_config.get("payloads"):
            print(f"     实验数据: data/owasp/expericing/{experiment_arg}/")

    # 1. 自动发现占位符默认值（从模板 placeholders 段）
    auto_placeholders = auto_discover_placeholders(args.scope)

    # 1.5 加载 scope 的 {goal} 目标列表（从 _goals.yaml）
    scope_goals = load_scope_goals(args.scope)

    # 2. 根据优先级合并配置
    if experiment_config:
        # 实验模式：实验配置为基础，CLI 参数可覆盖
        placeholders = experiment_config["placeholders"].copy()
        exp_obj = experiment_config["objective"]
        placeholders["objective"] = exp_obj if exp_obj else scope_goals
        # CLI 参数优先级高于实验配置
        if objective:
            placeholders["objective"] = objective
        if args.placeholders:
            placeholders.update(_parse_placeholders(args.placeholders))
        objective = placeholders.get("objective", "")
    elif args.placeholder_file:
        # 加载 --placeholder-file（如果指定，向后兼容）
        file_placeholders = load_placeholder_file(args.placeholder_file)
        # CLI 参数优先级高于文件
        if objective:
            file_placeholders["objective"] = objective
        elif scope_goals:
            file_placeholders["objective"] = scope_goals
        file_placeholders.update(placeholders)
        placeholders = file_placeholders
        objective = placeholders.get("objective", "")
    elif auto_placeholders or scope_goals:
        # 使用自动发现的配置 + scope goals
        placeholders = auto_placeholders
        # 使用 scope goals 作为默认 objective
        if scope_goals:
            placeholders["objective"] = scope_goals
        # CLI --objective 优先级高于默认配置
        if objective:
            placeholders["objective"] = objective
        objective = placeholders.get("objective", objective)
    else:
        # 无配置，使用 CLI 参数
        if objective:
            placeholders["objective"] = objective

    # 校验占位符
    if placeholders:
        missing, extra = validate_placeholders(args.scope, placeholders)
        if missing:
            missing_labels = [_get_placeholder_label(m) for m in missing]
            logger.warning(
                "⚠️ 占位符配置缺少 %d 个必要参数: %s",
                len(missing), ", ".join(missing_labels),
            )
            logger.warning("   请补齐以下占位符: %s", ", ".join(missing))
            print(f"\n  ⚠️  占位符配置不完整！")
            print(f"      缺失参数 ({len(missing)} 个): {', '.join(missing_labels)}")
            if experiment_arg:
                print(f"      请编辑 {experiment_config['config_path']} 补齐以下字段: {', '.join(missing)}")
            elif args.placeholder_file:
                print(f"      请编辑 {args.placeholder_file} 补齐以下字段: {', '.join(missing)}")
            else:
                print(f"      请编辑 data/owasp/llm/{args.scope}/ 下模板的 placeholders 段")
            if not getattr(args, "no_prompt", False):
                print(f"      或使用 --no-prompt 跳过（缺失占位符将保持原样输出）")
                raise ValueError(f"占位符配置不完整，缺失: {', '.join(missing)}")
        if extra:
            logger.info("ℹ️  %d 个未使用的占位符已自动忽略: %s", len(extra), ", ".join(extra))

    # ── 占位符校验：检查模板中声明的占位符是否有值 ──
    # （已集成到 validate_placeholders 中，此处不再重复）

    # 3. 交互式占位符提示（除非 --no-prompt 或无配置）
    if not getattr(args, "no_prompt", False) and not experiment_arg and not args.placeholder_file and not auto_placeholders:
        objective, placeholders = _interactive_prompt_placeholders(args, logger)
    else:
        # --no-prompt 模式下仍解析 --placeholders
        if placeholders is None:
            placeholders = {}

    # ── 标准化 objective 为列表（支持多目标） ──
    objectives = _normalize_objectives(objective, placeholders)

    # 解析目标列表
    targets = _resolve_targets(args)
    if not targets:
        logger.error(
            "No target specified. Use --target-file, --target-dir, or --target-url"
        )
        raise ValueError("Must specify at least one target: --target-file, --target-dir, or --target-url")

    logger.info("Target count: %d", len(targets))
    for i, (target_file, target_url) in enumerate(targets, 1):
        target_label = target_url or target_file or "unknown"
        logger.info("  [%d/%d] %s", i, len(targets), target_label)

    # 逐一分批执行
    all_results = []
    for target_idx, (target_file, target_url) in enumerate(targets, 1):
        target_label = target_url or target_file or "unknown"
        logger.info("=" * 60)
        logger.info("Processing target [%d/%d]: %s", target_idx, len(targets), target_label)
        logger.info("=" * 60)

        # 每个目标独立 tracker
        tracker = PipelineTracker(verbose=True)

        # 自动侦察（--auto-recon）— 流式模式
        profile_path = args.profile
        if args.auto_recon and not profile_path:
            logger.info("Running auto-recon (streaming mode) before attack...")
            recon_engine = ReconEngine()
            recon_target = target_url or target_file
            profile = None
            first_tool = None
            for tool_name, partial_profile, is_complete in recon_engine.run_streaming(
                target=recon_target,
                tracker=tracker,
            ):
                if first_tool is None:
                    first_tool = tool_name
                    print(f"\n  🔍 侦察启动: {recon_target}")
                print(f"  ✓ {tool_name} 完成 — "
                      f"已发现 {partial_profile.vulnerability_count} 个漏洞, "
                      f"风险={partial_profile.risk_level}")
                profile = partial_profile

                # 第一个工具完成时，可立即开始攻击准备
                if tool_name == first_tool and not is_complete:
                    logger.info("First tool complete, attack preparation can start...")

            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            profile_path = f"results/recon/auto_profile_{timestamp}.json"
            profile.save(profile_path)
            logger.info("Auto-recon profile saved to: %s", profile_path)

            if tracker.recon_log:
                tracker.recon_log.profile_path = profile_path

            print(f"  📄 侦察画像已保存: {profile_path}")

            # 打印冲突检测和交叉验证结果（流式模式）
            if profile:
                conflicts = [v for v in profile.vulnerabilities if v.conflict]
                cross_validated = [v for v in profile.vulnerabilities if len(v.source_tools) >= 2 and not v.conflict]
                if conflicts:
                    print(f"\n  ⚠ 工具间冲突 (severity 差异 ≥ 2):")
                    for v in conflicts:
                        print(f"    • {v.owasp_mapping}: {', '.join(v.source_tools)} → severity={v.severity}")
                if cross_validated:
                    print(f"\n  ✓ 交叉验证 (置信度提升):")
                    for v in cross_validated:
                        print(f"    • {v.owasp_mapping}: {', '.join(v.source_tools)} → confidence={v.confidence:.2f}")

        # 创建 AI300Engine（遍历每个 objective）
        results = []
        for obj_idx, obj in enumerate(objectives, 1):
            if len(objectives) > 1:
                logger.info("─" * 40)
                logger.info("Objective [%d/%d]: %s", obj_idx, len(objectives), obj)
                logger.info("─" * 40)

            engine = AI300Engine(
                target_config=target_file or "config/targets/ollama_local.yaml",
                tracker=tracker,
                profile_path=profile_path,
                target_url=target_url,
                model=args.model,
                objective=obj,
                placeholders=placeholders,
                scorer_url=args.scorer_url,
                scorer_key=args.scorer_key,
                scorer_model=args.scorer_model,
            )

            try:
                obj_results = engine.run(scope=args.scope)
                results.extend(obj_results)
            except KeyboardInterrupt:
                print("\n\n  ⚠ 用户中断 — 打印已完成的结果摘要")
                logger.warning("Execution interrupted by user (KeyboardInterrupt)")
                if results:
                    _print_partial_summary(results)
                else:
                    print("  无已完成的结果")
                return

        # 保存执行报告（每个 scope 聚合后保存一次）
        from pyrit_ai300.reporting import ExecutionReportGenerator
        report_gen = ExecutionReportGenerator()
        for result in results:
            # 收集该 scope 下所有 smart_match attacks
            smart_match_attacks = [
                a for a in result.get("attacks", [])
                if a.get("mode") == "smart_match"
            ]
            if not smart_match_attacks:
                continue

            # 聚合所有 smart_match attacks 的结果
            aggregated = {
                "total_executions": sum(a.get("total_executions", 0) for a in smart_match_attacks),
                "success_count": sum(a.get("success_count", 0) for a in smart_match_attacks),
                "failure_count": sum(a.get("failure_count", 0) for a in smart_match_attacks),
                "results": [r for a in smart_match_attacks for r in a.get("results", [])],
                "category_stats": {},
                "best_combinations": [c for a in smart_match_attacks for c in a.get("best_combinations", [])],
                "plan_summary": smart_match_attacks[0].get("plan_summary", {}) if smart_match_attacks else {},
                "plan": [p for a in smart_match_attacks for p in a.get("plan", [])],
            }

            # 合并 category_stats
            for a in smart_match_attacks:
                for cat, stats in a.get("category_stats", {}).items():
                    if cat not in aggregated["category_stats"]:
                        aggregated["category_stats"][cat] = {
                            "success": stats.get("success", 0),
                            "failure": stats.get("failure", 0),
                            "combinations": stats.get("combinations", {}),
                        }
                    else:
                        aggregated["category_stats"][cat]["success"] += stats.get("success", 0)
                        aggregated["category_stats"][cat]["failure"] += stats.get("failure", 0)
                        # 合并 combinations
                        for combo_key, combo_val in stats.get("combinations", {}).items():
                            if combo_key not in aggregated["category_stats"][cat]["combinations"]:
                                aggregated["category_stats"][cat]["combinations"][combo_key] = combo_val.copy()
                            else:
                                aggregated["category_stats"][cat]["combinations"][combo_key]["success"] += combo_val.get("success", 0)
                                aggregated["category_stats"][cat]["combinations"][combo_key]["failure"] += combo_val.get("failure", 0)

            report_gen.save_execution_report(
                results=aggregated,
                plan=aggregated["plan"],
                module_name=result.get("scope", "unknown"),
                target_path=target_file or target_url or "unknown",
            )

        # 生成报告（多目标时附加目标名）
        output_path = args.output
        if len(targets) > 1:
            from pathlib import Path
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = Path(target_file).stem if target_file else "url_target"
            output_path = f"results/report_{target_name}_{timestamp}.{args.format}"
            logger.info("Multi-target mode, report: %s", output_path)

        engine.generate_report(output_path=output_path, format=args.format)
        all_results.append((target_label, results))

    # 汇总
    logger.info("=" * 60)
    logger.info("All targets completed: %d/%d", len(targets), len(targets))
    for target_label, _ in all_results:
        logger.info("  ✓ %s", target_label)


def _list_components(args, logger):
    """列出可用组件"""
    if args.component == "attacks":
        from pyrit_ai300.orchestrators.attack_registry import list_attacks, get_attack_info
        print("Available Attacks:")
        for category in ["single_turn", "multi_turn", "compound", "streaming"]:
            attacks = list_attacks(category)
            if attacks:
                print(f"\n  {category.upper()}:")
                for attack in attacks:
                    info = get_attack_info(attack)
                    print(f"    - {attack}: {info.get('description', '')}")
    
    elif args.component == "converters":
        from pyrit_ai300.orchestrators.component_registry import CONVERTER_MAP
        print("Available Converters:")
        for converter_name in CONVERTER_MAP:
            print(f"    - {converter_name}")
    
    elif args.component == "scorers":
        from pyrit_ai300.orchestrators.attack_orchestrator import AttackOrchestrator
        from pyrit_ai300.orchestrators.component_registry import SCORER_MAP
        print("Available Scorer Types:")
        for scorer_name in SCORER_MAP:
            print(f"    - {scorer_name}")
        print(f"\nASI Auto-Selection Map:")
        asi_map = AttackOrchestrator._load_attack_defaults().get("asi_scorer_map", {})
        for asi, scorer_type in sorted(asi_map.items()):
            print(f"    {asi} → {scorer_type}")
        print(f"\nDefault LLM Backend: local_ollama (qwen3:0.6b @ http://localhost:11434/v1)")
        print(f"Override with: --scorer-url / --scorer-key / --scorer-model")
    
    elif args.component == "targets":
        from pyrit_ai300.orchestrators.attack_registry import list_types
        print("Available Target Types:")
        for target_type in list_types():
            print(f"    - {target_type}")
    
    elif args.component == "owasp":
        from pyrit_ai300.payloads.payload_manager import PayloadManager
        pm = PayloadManager()
        pm.load_data_dir("data/")
        scopes = discover_scopes()
        print("OWASP Scopes (动态发现):")
        if scopes:
            llm_ids = [s["id"] for s in scopes if s["id"].startswith("llm")]
            asi_ids = [s["id"] for s in scopes if s["id"].startswith("asi")]
            if llm_ids:
                print(f"  LLM:     {', '.join(llm_ids)}")
            if asi_ids:
                print(f"  Agentic: {', '.join(asi_ids)}")
        print("  Groups:    llm (all LLM), agentic (all Agentic)")
        print("  All:       all")
        print("  Single file: owasp:llm:llm04:rag_poison (ref_path format)")
        print(f"\n  Loaded refs: {len(pm.get_all_refs())}")
        for ref in pm.get_all_refs():
            print(f"    - {ref}")


def _generate_report(args, logger):
    """生成报告"""
    import json
    from pyrit_ai300.reporting import ReportGenerator

    with open(args.results, "r", encoding="utf-8") as f:
        results = json.load(f)

    generator = ReportGenerator(results=results)
    generator.generate(output_path=args.output, format=args.format)

    logger.info("Report generated: %s", args.output)


def _run_recon(args, logger):
    """执行侦察（独立模式，无攻击阶段）"""
    from pyrit_ai300.reconnaissance import ReconEngine
    from pyrit_ai300.pipeline import PipelineTracker

    # 解析目标：--target 或 --target-file（二选一）
    target = args.target
    if args.target_file:
        target = ReconEngine.load_target(args.target_file)
        logger.info("Loaded target from %s: %s", args.target_file, target)
    elif not target:
        logger.error("Either --target or --target-file is required")
        print("Error: Either --target or --target-file is required")
        print("  --target URL        Direct target URL")
        print("  --target-file YAML  Target config from config/targets/")
        return

    # 创建 PipelineTracker（仅侦察阶段）
    tracker = PipelineTracker(verbose=True)

    engine = ReconEngine(config_path=args.config)

    # 检查工具可用性
    if args.verbose:
        tool_status = engine.check_tools()
        print("Tool Status:")
        for tool, available in tool_status.items():
            status = "✓" if available else "✗"
            print(f"  {status} {tool}")

    # 执行侦察（传入 tracker）
    profile = engine.run(
        target=target,
        depth=args.depth,
        tools=args.tools,
        tracker=tracker,
    )

    # 确定输出路径
    output_path = args.output
    if not output_path:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"results/recon/profile_{timestamp}.json"

    # 保存结果
    profile.save(output_path)

    # 更新 tracker 中的 profile_path
    if tracker.recon_log:
        tracker.recon_log.profile_path = output_path

    # 打印摘要
    print("\nReconnaissance Complete")
    print(f"  Target: {profile.target}")
    print(f"  Tools Used: {', '.join(profile.tools_used)}")
    print(f"  Vulnerabilities: {profile.vulnerability_count}")
    print(f"  Risk Level: {profile.risk_level}")
    print(f"  OWASP Mappings: {', '.join(profile.get_owasp_mappings())}")
    print(f"  Profile saved to: {output_path}")

    # 打印冲突检测和交叉验证结果
    conflicts = [v for v in profile.vulnerabilities if v.conflict]
    cross_validated = [v for v in profile.vulnerabilities if len(v.source_tools) >= 2 and not v.conflict]
    if conflicts:
        print(f"\n  ⚠ Tool Conflicts (severity diff ≥ 2):")
        for v in conflicts:
            print(f"    • {v.owasp_mapping}: {', '.join(v.source_tools)} → severity={v.severity}")
            if v.description:
                print(f"      {v.description[:80]}")
    if cross_validated:
        print(f"\n  ✓ Cross-Validated (confidence boost):")
        for v in cross_validated:
            print(f"    • {v.owasp_mapping}: {', '.join(v.source_tools)} → confidence={v.confidence:.2f}")


if __name__ == "__main__":
    main()
