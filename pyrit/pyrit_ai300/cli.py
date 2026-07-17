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

  # 使用占位符配置文件（向后兼容）
  ai300 owasp llm03 --target-file config/targets/ollama_local.yaml --placeholder-file config/placeholders/default.yaml

  # 多目标攻击（逗号分隔）
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --objective "whoami,id,uname"

  # 全量攻击 + HTML 报告
  ai300 owasp all --target-file config/targets/ollama_local.yaml --format html -o report.html""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    owasp_required = owasp_parser.add_argument_group("required arguments")
    owasp_required.add_argument(
        "scope",
        help="OWASP scope: llm01/asi01 (single ID), llm/agentic (group), all, "
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
        help="占位符配置文件路径（YAML 格式，如 config/placeholders/default.yaml）。"
             "定义后自动填充载荷中的占位符，缺失时提示补齐",
    )
    owasp_optional.add_argument(
        "--experiment",
        default=None,
        help="实验配置路径（如 expericing/tier1_goal）。"
             "加载 config/placeholders/{path}.yaml 中的 objective/placeholders/execution 参数，"
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
    recon_required = recon_parser.add_argument_group("required arguments")
    recon_required.add_argument(
        "-t", "--target",
        required=True,
        help="Target URL or endpoint to recon",
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
        parser.print_help()


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

    # 分类
    tier1_found = {k: v for k, v in all_ph.items() if k in tier1_names}
    tier3_found = {k: v for k, v in all_ph.items()
                   if k not in tier1_names and k not in tier2_encodings}

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
    - experiment_data: 关联的实验数据目录名
    - execution: 执行参数覆盖

    Args:
        experiment_path: 实验配置路径（相对于 config/placeholders/）
                         如 "expericing/tier1_goal"

    Returns:
        实验配置字典，包含 objective, placeholders, experiment_data, execution
    """
    import yaml
    from pathlib import Path

    # 构建完整路径
    config_path = Path("config/placeholders") / f"{experiment_path}.yaml"
    if not config_path.exists():
        # 尝试不带 .yaml 后缀
        config_path = Path("config/placeholders") / experiment_path

    if not config_path.exists():
        raise FileNotFoundError(
            f"实验配置不存在: {experiment_path}\n"
            f"查找路径: config/placeholders/{experiment_path}.yaml\n"
            f"请确保文件存在于 config/placeholders/ 目录下"
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


def auto_discover_placeholders(scope: str) -> Dict[str, Any]:
    """
    自动发现 scope 对应的占位符配置文件

    检查 config/placeholders/{scope}/ 目录，加载所有 *.yaml 文件并合并。
    加载顺序：{scope}_tier1_goal.yaml 优先，其余按字母顺序。

    Args:
        scope: OWASP scope (如 "llm01", "asi01")

    Returns:
        合并后的占位符字典，目录不存在返回空字典
    """
    import yaml
    from pathlib import Path

    config_dir = Path("config/placeholders") / scope
    if not config_dir.exists() or not config_dir.is_dir():
        return {}

    # 按优先级排序：{scope}_tier1_goal.yaml 优先，其余按字母顺序
    yaml_files = sorted(config_dir.glob("*.yaml"))
    yaml_files.sort(key=lambda p: (0 if p.stem == f"{scope}_tier1_goal" else 1, p.name))

    if not yaml_files:
        return {}

    merged = {}
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for k, v in data.items():
                if not v:
                    continue
                if k == "objective" and isinstance(v, list):
                    objectives = [x for x in v if x and str(x).strip()]
                    if objectives:
                        merged[k] = objectives
                elif isinstance(v, (str, int, float)):
                    merged[k] = v
        except Exception:
            pass

    return merged


def validate_placeholders(scope: str, placeholders: Dict[str, str]) -> tuple:
    """
    校验占位符是否满足 scope 需求

    Args:
        scope: OWASP scope
        placeholders: 用户提供的占位符字典

    Returns:
        (missing_required, extra_placeholders) 元组
        - missing_required: 缺失的必需占位符列表
        - extra_placeholders: 多余（未使用）的占位符列表
    """
    import re
    from pyrit_ai300.payloads.payload_manager import PayloadManager

    pm = PayloadManager()
    pm.load_data_dir("data/")
    refs = pm.get_scope_refs(scope)

    if not refs:
        return [], list(placeholders.keys())

    # 收集 scope 中所有实际使用的占位符
    used_placeholders = set()
    for ref in refs:
        data = pm._payload_store.get(ref, {})
        for entry in data.get("payloads", []):
            if isinstance(entry, dict):
                text = entry.get("payload", "")
            else:
                text = str(entry)
            matches = re.findall(r'\{([a-z_][a-z0-9_]{1,})\}', text)
            used_placeholders.update(matches)

    # 编码变体占位符（Tier 2）由 objective 自动衍生，不算缺失
    tier2_encodings = {
        "base64_goal", "base32_goal", "ascii85_goal", "french_goal",
        "bidi_override_goal", "unicode_tag_goal", "zalgo_goal",
        "chain_encoded_goal", "ascii_tag_deep_goal",
        "hex_goal", "rot13_goal", "sneaky_bits_goal",
        "interlinear_ws_goal", "multi_tag_mix_goal",
    }

    # 检查缺失（排除 Tier 2 编码变体）
    missing = []
    for ph in used_placeholders:
        if ph in tier2_encodings:
            continue
        if ph == "objective" or ph == "goal":
            obj = placeholders.get("objective")
            if not obj or (isinstance(obj, list) and not any(obj)):
                missing.append(ph)
        elif ph not in placeholders:
            missing.append(ph)

    # 检查多余
    extra = [k for k in placeholders.keys() if k not in used_placeholders]

    return missing, extra


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
        if experiment_config["experiment_data"]:
            print(f"     实验数据: data/owasp/expericing/{experiment_config['experiment_data']}/")

    # 1. 自动发现 config/placeholders/{scope}/ 目录下的配置文件
    auto_placeholders = auto_discover_placeholders(args.scope)

    # 2. 根据优先级合并配置
    if experiment_config:
        # 实验模式：实验配置为基础，CLI 参数可覆盖
        placeholders = experiment_config["placeholders"].copy()
        placeholders["objective"] = experiment_config["objective"]
        # CLI 参数优先级高于实验配置
        if objective:
            placeholders["objective"] = objective
        if args.placeholders:
            placeholders.update(_parse_placeholders(args.placeholders))
        objective = placeholders.get("objective", "")
    elif placeholder_file:
        # 加载 --placeholder-file（如果指定，向后兼容）
        file_placeholders = load_placeholder_file(placeholder_file)
        # CLI 参数优先级高于文件
        if objective:
            file_placeholders["objective"] = objective
        file_placeholders.update(placeholders)
        placeholders = file_placeholders
        objective = placeholders.get("objective", "")
    elif auto_placeholders:
        # 使用自动发现的配置
        placeholders = auto_placeholders
        # CLI --objective 优先级高于自动发现的配置
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
            elif placeholder_file:
                print(f"      请编辑 {placeholder_file} 补齐以下字段: {', '.join(missing)}")
            else:
                print(f"      请编辑 config/placeholders/{args.scope}/ 下的配置文件")
            if not getattr(args, "no_prompt", False):
                print(f"      或使用 --no-prompt 跳过（缺失占位符将保持原样输出）")
                raise ValueError(f"占位符配置不完整，缺失: {', '.join(missing)}")
        if extra:
            logger.info("ℹ️  %d 个未使用的占位符已自动忽略: %s", len(extra), ", ".join(extra))

    # 3. 交互式占位符提示（除非 --no-prompt 或无配置）
    if not getattr(args, "no_prompt", False) and not experiment_arg and not placeholder_file and not auto_placeholders:
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

        # 自动侦察（--auto-recon）
        profile_path = args.profile
        if args.auto_recon and not profile_path:
            logger.info("Running auto-recon before attack...")
            recon_engine = ReconEngine()
            recon_target = target_url or target_file
            profile = recon_engine.run(
                target=recon_target,
                tracker=tracker,
            )
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            profile_path = f"results/recon/auto_profile_{timestamp}.json"
            profile.save(profile_path)
            logger.info("Auto-recon profile saved to: %s", profile_path)

            if tracker.recon_log:
                tracker.recon_log.profile_path = profile_path

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

            obj_results = engine.run(scope=args.scope)
            results.extend(obj_results)

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
        for asi, scorer_type in sorted(AttackOrchestrator._ASI_SCORER_MAP.items()):
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
        print("OWASP Scopes:")
        print("  Single ID: llm01, llm02, ..., llm10, asi01, asi02, ..., asi10")
        print("  Groups:    llm (all LLM Top 10), agentic (all Agentic Top 10)")
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
        target=args.target,
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


if __name__ == "__main__":
    main()
