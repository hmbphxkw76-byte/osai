"""
===============================================================================
PyRIT Red Team — Markdown 渗透漏洞报告（CLI Phase 路径）
===============================================================================
对齐 OSCP 报告标准：执行摘要 → 方法论 → 漏洞详情 → 根因分析 → 修复建议 → 后续命令 → 结论
"""
import os
from datetime import datetime

from rich.console import Console

from reporting.engine import build_followup_suggestions
from reporting.data import CASE_CATEGORY, CRESCENDO_CATEGORY

console = Console()

# ═══════════════════════════════════════════════════════════════════
# 根因分析映射（CLI 路径轻量版）
# ═══════════════════════════════════════════════════════════════════

_ROOT_CAUSE_HINTS = {
    "roleplay": "角色扮演场景下安全护栏被上下文覆盖，模型优先满足角色设定而非安全约束",
    "encoding": "输入预处理管道未对编码输入做解码检测",
    "academic": "学术研究框架下模型优先提供知识而非执行安全约束",
    "jailbreak": "安全对齐训练对抗样本多样性不足",
    "extraction": "输出过滤规则不足以覆盖侧信道提取方式",
    "tool_use": "工具调用参数缺乏严格的白名单校验",
    "default": "目标模型在此攻击维度缺乏有效的安全护栏",
}


def generate_penetrating_report(results: list, campaign_name: str, output_dir: str = ".",
                                target_info: dict | None = None):
    """生成 PyRIT Red Team 红队渗透漏洞报告（Markdown 格式，对齐 OSCP 标准）。"""
    if not results:
        return None

    successes = [r for r in results if r.get("status") == "SUCCESS"]
    failures = [r for r in results if r.get("status") == "FAILURE"]
    errors = [r for r in results if r.get("status") == "ERROR"]
    total = len(results)
    rate = len(successes) / total * 100 if total > 0 else 0

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{campaign_name.replace(' ', '_')}_Exam_Report_{datetime.now().strftime('%H%M%S')}.md"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    target_info = target_info or {}

    lines = []
    # ── 封面 / 文档控制 ──
    lines.append(f"# PyRIT Red Team — AI 渗透漏洞测试报告")
    lines.append(f"")
    lines.append(f"**TLP:AMBER** — 本报告仅限内部使用，不得对外公开。")
    lines.append(f"")
    lines.append(f"| 属性 | 内容 |")
    lines.append(f"|------|------|")
    lines.append(f"| 生成时间 | {timestamp} |")
    lines.append(f"| 测试类型 | {campaign_name} |")
    lines.append(f"| 总攻击次数 | {total} |")
    lines.append(f"| 成功突破 | {len(successes)} ({rate:.1f}%) |")
    lines.append(f"| 防御成功 | {len(failures)} |")
    lines.append(f"| 执行错误 | {len(errors)} |")
    lines.append(f"| 测试工具 | PyRIT Red Team Framework |")
    lines.append(f"")

    # ── Section 1: 测试方法论 ──
    lines.append(f"## 1. 测试方法论")
    lines.append(f"")
    lines.append(f"本次评估遵循标准化 AI 红队测试流程：")
    lines.append(f"")
    lines.append(f"1. **侦察** — 探测目标模型架构、认证方式、速率限制")
    lines.append(f"2. **攻击面枚举** — 加载 YAML 内置用例库，覆盖越狱/注入/提取/工具滥用等维度")
    lines.append(f"3. **策略变体生成** — 通过 Converter 引擎对每个 Prompt 应用编码/角色扮演/语义包装等攻击手法")
    lines.append(f"4. **执行与评分** — 并发投送 + CleanedSelfAskTrueFalseScorer 双重判定")
    lines.append(f"5. **结果分析** — 防御性剥离后评分，降低假阴性")
    lines.append(f"")
    lines.append(f"**工具链**: PyRIT Framework (Orchestrator + Converter + Scorer) | SQLiteMemory | Rich Console")
    lines.append(f"")

    # ── Section 2: 执行摘要 ──
    lines.append(f"## 2. 执行摘要")
    lines.append(f"")
    if successes:
        lines.append(f"本次测试共执行 {total} 次攻击，成功突破 {len(successes)} 次，命中率 {rate:.1f}%。")
        lines.append(f"共发现 **{len(set(r['case_id'] for r in successes))}** 个不同维度的安全漏洞。")
        lines.append(f"")

        # 按类别统计 ASR
        lines.append(f"### 攻击成功率按类别分布 (ASR by Category)")
        lines.append(f"")
        lines.append(f"| 类别 | 漏洞数 |")
        lines.append(f"|------|--------|")
        cat_count: dict[str, int] = {}
        for r in successes:
            for cat_name in CASE_CATEGORY:
                if r["case_id"] in CASE_CATEGORY[cat_name]:
                    cat_count[cat_name] = cat_count.get(cat_name, 0) + 1
        for cat_name, cnt in sorted(cat_count.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat_name} | {cnt} |")
        lines.append(f"")

        lines.append(f"### 漏洞概览")
        lines.append(f"")
        lines.append(f"| # | 用例 ID | 突破手法 | 成功次数 |")
        lines.append(f"|---|---------|---------|---------|")
        vuln_map: dict[str, list[str]] = {}
        for r in successes:
            vuln_map.setdefault(r["case_id"], []).append(r["combo_name"])
        for idx, (case_id, combos) in enumerate(vuln_map.items(), 1):
            lines.append(f"| {idx} | `{case_id}` | {', '.join(combos)} | {len(combos)} |")
        lines.append(f"")
    else:
        lines.append(f"本次测试共执行 {total} 次攻击，未发现可突破的安全漏洞。目标模型安全防御较强。")
        lines.append(f"")

    # ── Section 3: 漏洞详情与攻击证据 ──
    if successes:
        lines.append(f"## 3. 漏洞详情与攻击证据")
        lines.append(f"")

        vuln_grouped: dict[str, list] = {}
        for r in successes:
            vuln_grouped.setdefault(r["case_id"], []).append(r)

        _section_idx = 3
        for idx, (case_id, entries) in enumerate(vuln_grouped.items(), 1):
            lines.append(f"### 3.{idx}. {case_id}")
            lines.append(f"")
            lines.append(f"| 属性 | 值 |")
            lines.append(f"|------|----|")
            lines.append(f"| 判定标准 | {entries[0].get('criterion', 'N/A')} |")
            lines.append(f"| 漏洞类型 | {'多轮渐进式攻击' if entries[0].get('mode') == 'crescendo' else '单轮越狱攻击'} |")
            lines.append(f"| 突破次数 | {len(entries)} |")

            # 根因分析
            _infer_rca(lines, case_id, entries)
            lines.append(f"")

            for j, entry in enumerate(entries, 1):
                combo = entry["combo_name"]
                lines.append(f"#### 攻击手法 {j}: {combo}")
                lines.append(f"")

                prompt_text = entry.get("converted_prompt", entry.get("objective", ""))
                lines.append(f"**攻击 Prompt**:")
                lines.append(f"```")
                lines.append(f"{prompt_text[:1500]}")
                lines.append(f"```")
                lines.append(f"")

                resp_text = entry.get("response_text", "")
                lines.append(f"**目标模型响应**:")
                lines.append(f"```")
                lines.append(f"{resp_text[:1500]}")
                lines.append(f"```")
                lines.append(f"")

                score_reason = entry.get("score_reason", "")
                if score_reason:
                    lines.append(f"**评分判定**: {score_reason}")
                    lines.append(f"")

                lines.append(f"---")
                lines.append(f"")
            _section_idx += 1

    # ── Section 4: 防御统计 ──
    _next_section = 4 if successes else 3
    if failures:
        lines.append(f"## {_next_section}. 成功防御的攻击向量")
        lines.append(f"")
        fail_by_case: dict[str, set] = {}
        for r in failures:
            fail_by_case.setdefault(r["case_id"], set()).add(r["combo_name"])
        for case_id, combos in sorted(fail_by_case.items()):
            lines.append(f"- **{case_id}**: 成功防御 {len(combos)} 种攻击手法")
        lines.append(f"")
        _next_section += 1

    # ── Section 5/6: 下一步攻击命令 ──
    _next_section = _render_followup_markdown(lines, results, section_num=_next_section)

    # ── 修复建议 ──
    lines.append(f"## {_next_section}. 修复建议")
    lines.append(f"")
    if successes:
        vuln_types = set(r["case_id"] for r in successes)
        if any("sys_prompt" in v.lower() or "leak" in v.lower() for v in vuln_types):
            lines.append(f"- **系统提示词泄露**: 添加强输入/输出护栏，检测并过滤包含系统提示词关键词的响应")
        if any("roleplay" in v.lower() for v in vuln_types):
            lines.append(f"- **角色扮演越狱**: 强化对齐训练，增强对角色扮演类攻击的识别能力")
        if any("encoding" in v.lower() or "obfuscat" in v.lower() for v in vuln_types):
            lines.append(f"- **编码混淆绕过**: 对 Base64/ROT13/ZeroWidth 等编码输入进行解码检测后再做安全判定")
        if any("academic" in v.lower() or "priming" in v.lower() for v in vuln_types):
            lines.append(f"- **学术伪装攻击**: 增强对以研究/教育为借口的恶意请求的识别")
        if any("tool" in v.lower() for v in vuln_types):
            lines.append(f"- **工具调用注入**: 对工具调用参数进行安全校验，限制工具执行权限")
    else:
        lines.append(f"- 当前安全防御能力较强，建议保持安全监控和定期红队测试")
    lines.append(f"")

    # ── 结论 ──
    _next_section += 1
    lines.append(f"## {_next_section}. 结论与经验教训")
    lines.append(f"")
    if successes:
        top_case = max(vuln_map.items(), key=lambda x: len(x[1])) if 'vuln_map' in dir() and vuln_map else (None, [])
        lines.append(f"### 关键发现")
        lines.append(f"")
        lines.append(f"1. 目标模型在本次评估中综合突破率 **{rate:.1f}%**，共发现 **{len(vuln_map)}** 个漏洞维度。")
        lines.append(f"2. 最脆弱的攻击面: `{', '.join(list(vuln_map.keys())[:5])}` 等极易被突破。")
        lines.append(f"3. 建议将本次发现的所有漏洞纳入修复跟踪，并在修复后重新测试验证。")
    else:
        lines.append(f"### 关键发现")
        lines.append(f"")
        lines.append(f"1. 目标模型的防御能力较强，在本次评估范围内未被突破。")
    lines.append(f"")
    lines.append(f"### 后续建议")
    lines.append(f"")
    lines.append(f"- 建立周期性 AI 红队测试机制（建议每季度一次）")
    lines.append(f"- 将本次有效的攻击策略加入模型安全对齐训练的对抗样本集")
    lines.append(f"- 定期关注前沿漏洞（Frontier Registry），保持防御能力持续演进")
    lines.append(f"")

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    console.print(f"[bold green]📄 渗透漏洞报告已生成: {filepath}[/bold green]")
    return filepath


# ═══════════════════════════════════════════════════════════════════
# 辅助：根因推断（CLI 路径）
# ═══════════════════════════════════════════════════════════════════

def _infer_rca(lines: list, case_id: str, entries: list):
    """根据 case_id 和 combo_name 推断失效根因。"""
    root_cause = _ROOT_CAUSE_HINTS.get("default", "待进一步分析")
    for hint_key, hint_text in _ROOT_CAUSE_HINTS.items():
        if hint_key in case_id.lower():
            root_cause = hint_text
            break
        for entry in entries:
            if hint_key in entry.get("combo_name", "").lower():
                root_cause = hint_text
                break

    lines.append(f"| **失效根因** | {root_cause} |")


# ═══════════════════════════════════════════════════════════════════
# Markdown 版后续攻击命令渲染
# ═══════════════════════════════════════════════════════════════════

def _render_followup_markdown(lines: list, results: list, section_num: int = 3) -> int:
    """向 Markdown 行列表追加后续攻击命令，返回下一可用 section 编号。"""
    suggestions = build_followup_suggestions(results)
    if suggestions is None:
        return section_num

    lines.append(f"## {section_num}. 下一步攻击命令（自动生成）")
    lines.append(f"")
    lines.append(f"> 以下命令基于已发现的漏洞自动匹配最优后续攻击路径。可直接复制到终端执行。")
    lines.append(f"")
    cmd_counter = 0

    # ═══ PART 1: PROBE 预定义映射 ═══
    for probe_idx, pf in enumerate(suggestions["probe_followups"], 1):
        lines.append(f"### {section_num}.{probe_idx}. PROBE: {pf['probe_id']} — {pf['title']}")
        lines.append(f"")
        lines.append(f"**突破口**: {', '.join(pf['combos'])} 成功突破。{pf['breakthrough']}")
        lines.append(f"")
        for desc, case_ids in pf.get("single", []):
            cmd_counter += 1
            lines.append(f"**第 {cmd_counter} 条**: {desc}")
            lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --phase single --case {case_ids}"); lines.append(f"```"); lines.append(f"")
        for desc, case_ids in pf.get("probe", []):
            cmd_counter += 1
            lines.append(f"**第 {cmd_counter} 条**: {desc}")
            lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --phase probe --case {case_ids}"); lines.append(f"```"); lines.append(f"")
        for desc, case_ids in pf.get("crescendo", []):
            cmd_counter += 1
            lines.append(f"**第 {cmd_counter} 条**: {desc}")
            lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --phase crescendo --case {case_ids}"); lines.append(f"```"); lines.append(f"")

    # ═══ PART 2: 单轮突破 — 按手法×领域扩散 ═══
    if suggestions["single_diffusions"]:
        sub_idx = len(suggestions["probe_followups"]) + 1
        lines.append(f"### {section_num}.{sub_idx}. 单轮突破 — 按攻击手法 × 领域精准推荐")
        lines.append(f"")
        for sd in suggestions["single_diffusions"]:
            lines.append(f"**攻击手法: {sd['combo']}**")
            lines.append(f"")
            for entry in sd["entries"]:
                cmd_counter += 1
                lines.append(f"**第 {cmd_counter} 条**: 用 {sd['combo']} 横扫「{entry['category']}」类其他用例")
                lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --phase single --case {','.join(entry['other_ids'])}"); lines.append(f"```"); lines.append(f"")
        lines.append(f"")

    # ═══ PART 3: 多轮突破 — 按手法×领域扩散 ═══
    if suggestions["cresc_diffusions"]:
        sub_idx = len(suggestions["probe_followups"]) + (2 if suggestions["single_diffusions"] else 1)
        lines.append(f"### {section_num}.{sub_idx}. 多轮突破 — 按攻击手法 × 领域精准推荐")
        lines.append(f"")
        for cd in suggestions["cresc_diffusions"]:
            lines.append(f"**攻击手法: {cd['combo']}**")
            lines.append(f"")
            for entry in cd["entries"]:
                cmd_counter += 1
                lines.append(f"**第 {cmd_counter} 条**: 用 {cd['combo']} 横扫「{entry['category']}」类其他用例")
                lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --phase crescendo --case {','.join(entry['other_ids'])}"); lines.append(f"```"); lines.append(f"")
        lines.append(f"")

    # ═══ 最快聚合路径 ═══
    n_probe = len(suggestions["probe_followups"])
    n_single = 1 if suggestions["single_diffusions"] else 0
    n_cresc = 1 if suggestions["cresc_diffusions"] else 0
    last = n_probe + n_single + n_cresc + 1

    merged_s = suggestions["merged_single_ids"]
    merged_c = suggestions["merged_crescendo_ids"]

    lines.append(f"### {section_num}.{last}. 最快路径 — 一键覆盖全部攻击面")
    lines.append(f"")
    if merged_s:
        lines.append(f"**第 1 条**: 集合所有推荐单轮用例")
        lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --case all-single"); lines.append(f"```"); lines.append(f"")
    if merged_c:
        lines.append(f"**第 2 条**: 集合所有推荐多轮用例")
        lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --case all-crescendo"); lines.append(f"```"); lines.append(f"")
    lines.append(f"**第 3 条**: 全自动门控阶梯式攻击")
    lines.append(f"```powershell"); lines.append(f"python main.py --lang cn --auto-gate --gate-threshold 0.10 --concurrent 3"); lines.append(f"```"); lines.append(f"")

    return section_num + n_probe + n_single + n_cresc + 1 + 1  # +1 for 修复建议
