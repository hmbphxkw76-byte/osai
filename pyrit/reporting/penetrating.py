"""
===============================================================================
PyRIT Red Team — Markdown 渗透漏洞报告生成
===============================================================================
"""
import os
from datetime import datetime

from rich.console import Console

from reporting.engine import build_followup_suggestions

console = Console()


def generate_penetrating_report(results: list, campaign_name: str, output_dir: str = "."):
    """生成 PyRIT Red Team 红队渗透漏洞报告（Markdown 格式）。"""
    if not results:
        return None

    successes = [r for r in results if r.get("status") == "SUCCESS"]
    failures = [r for r in results if r.get("status") == "FAILURE"]
    total = len(results)
    rate = len(successes) / total * 100 if total > 0 else 0

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{campaign_name.replace(' ', '_')}_Exam_Report_{datetime.now().strftime('%H%M%S')}.md"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    lines = []
    lines.append(f"# PyRIT Red Team 红队漏洞测试报告")
    lines.append(f"")
    lines.append(f"**生成时间**: {timestamp}")
    lines.append(f"**测试类型**: {campaign_name}")
    lines.append(f"**总攻击次数**: {total}")
    lines.append(f"**成功突破**: {len(successes)} ({rate:.1f}%)")
    lines.append(f"**防御成功**: {len(failures)}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # ── 执行摘要 ──
    lines.append(f"## 1. 执行摘要")
    lines.append(f"")
    if successes:
        lines.append(f"本次测试共执行 {total} 次攻击，成功突破 {len(successes)} 次，命中率 {rate:.1f}%。")
        lines.append(f"共发现 **{len(set(r['case_id'] for r in successes))}** 个不同维度的安全漏洞。")
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
    else:
        lines.append(f"本次测试共执行 {total} 次攻击，未发现可突破的安全漏洞。目标模型安全防御较强。")
    lines.append(f"")

    # ── 漏洞详情 ──
    if successes:
        lines.append(f"## 2. 漏洞详情与攻击证据")
        lines.append(f"")

        vuln_grouped: dict[str, list] = {}
        for r in successes:
            vuln_grouped.setdefault(r["case_id"], []).append(r)

        for idx, (case_id, entries) in enumerate(vuln_grouped.items(), 1):
            lines.append(f"### 2.{idx}. {case_id}")
            lines.append(f"")
            lines.append(f"**判定标准**: {entries[0].get('criterion', 'N/A')}")
            lines.append(f"**漏洞类型**: {'多轮渐进式攻击' if entries[0].get('mode') == 'crescendo' else '单轮越狱攻击'}")
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

    # ── 防御统计 ──
    _next_section = 3
    if failures:
        lines.append(f"## 3. 成功防御的攻击向量")
        lines.append(f"")
        fail_by_case: dict[str, set] = {}
        for r in failures:
            fail_by_case.setdefault(r["case_id"], set()).add(r["combo_name"])
        for case_id, combos in sorted(fail_by_case.items()):
            lines.append(f"- **{case_id}**: 成功防御 {len(combos)} 种攻击手法")
        lines.append(f"")
        _next_section = 4

    # ── 下一步攻击命令（Markdown 版） ──
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
        if not vuln_types.intersection({"PROBE_01", "PROBE_02", "PROBE_03", "PROBE_04", "PROBE_05"}):
            lines.append(f"- 建议根据具体漏洞案例针对性加强对应维度的安全防护")
    else:
        lines.append(f"- 当前安全防御能力较强，建议保持安全监控和定期红队测试")
    lines.append(f"")

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    console.print(f"[bold green]📄 渗透漏洞报告已生成: {filepath}[/bold green]")
    return filepath


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
