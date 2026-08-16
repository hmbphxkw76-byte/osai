# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""A-4: 攻击链路可视化引擎 — Mermaid 流程图 + Kill Chain 矩阵 + 时间线.

生成攻击链路可视化, 嵌入到 HTML 报告中:
  1. Mermaid 流程图: 展示成功攻击的完整路径
     Recon → Initial Access → Payload Delivery → Bypass → Impact
  2. Kill Chain 矩阵: MITRE ATT&CK 风格的覆盖矩阵
  3. 成功攻击"三元组"卡片: 载荷 + 目标响应 + 安全影响
  4. 时间线攻击图: Gantt-style 展示攻击执行顺序和结果

设计原则 (R-022: PyRIT 原生优先):
  - 不修改 PyRIT 原生报告生成器
  - 作为报告增强层: 生成 Mermaid 源码 + HTML 片段
  - 嵌入到 ReportGenerator 的 Markdown → HTML 渲染中
  - 非侵入式: 失败时回退到纯文本

学术依据:
  - MITRE ATT&CK Framework
  - Lockheed Martin Kill Chain
  - HarmBench (arXiv:2402.04249) 标准化证据收集
  - JailbreakBench (arXiv:2402.01135) 漏洞披露最佳实践

> **日期**: 2026-8-16
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class AttackChainVisualizer:
    """攻击链路可视化引擎.

    生成 Mermaid 流程图和 HTML 片段, 嵌入到报告中.
    """

    # Kill Chain 阶段定义 (对齐 Lockheed Martin Cyber Kill Chain)
    KILL_CHAIN_STAGES = [
        ("recon", "Reconnaissance", "目标侦察 — 端点发现/能力探测"),
        ("initial_access", "Initial Access", "初始访问 — 首次接触目标"),
        ("delivery", "Payload Delivery", "载荷投递 — 攻击消息发送"),
        ("bypass", "Defense Bypass", "防御绕过 — 过滤器/安全机制规避"),
        ("execution", "Execution", "执行 — 目标模型响应"),
        ("impact", "Impact", "影响 — 数据泄露/权限提升/越狱"),
    ]

    # OWASP ID → Kill Chain 阶段映射 (全覆盖 LLM01-10 + ASI01-10)
    OWASP_TO_KILL_CHAIN = {
        "LLM01": ["delivery", "execution", "impact"],
        "LLM02": ["execution", "impact"],
        "LLM03": ["delivery", "execution", "impact"],
        "LLM04": ["delivery", "execution", "impact"],
        "LLM05": ["execution", "impact"],
        "LLM06": ["execution", "impact"],
        "LLM07": ["execution", "impact"],
        "LLM08": ["delivery", "execution", "impact"],
        "LLM09": ["execution", "impact"],
        "LLM10": ["delivery", "execution", "impact"],
        "ASI01": ["delivery", "execution"],
        "ASI02": ["execution", "impact"],
        "ASI03": ["execution", "impact"],
        "ASI04": ["execution", "impact"],
        "ASI05": ["execution", "impact"],
        "ASI06": ["delivery", "execution", "impact"],
        "ASI07": ["delivery", "execution"],
        "ASI08": ["execution", "impact"],
        "ASI09": ["delivery", "execution"],
        "ASI10": ["delivery", "execution", "impact"],
    }

    def __init__(self) -> None:
        """Initialize AttackChainVisualizer."""
        self._attack_chains: list[dict[str, Any]] = []
        self._timeline_data: list[dict[str, Any]] = []

    def build_from_attack_results(
        self,
        attack_results: list[Any],
        owasp_mapping: dict[str, list[str]] | None = None,
    ) -> None:
        """从攻击结果构建可视化数据.

        Args:
            attack_results: PyRIT AttackResult 列表.
            owasp_mapping: 攻击类型到 OWASP ID 的映射.
        """
        try:
            from pyrit.models import AttackOutcome
        except ImportError:
            AttackOutcome = None  # type: ignore[assignment]

        from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer
        from pipeline.converters.log import extract_converter_info_from_result

        eval_hash_map = AttackResultAnalyzer.build_eval_hash_map(attack_results)

        for ar in attack_results:
            technique = AttackResultAnalyzer.extract_technique_name(
                ar, eval_hash_map=eval_hash_map,
            )
            outcome = getattr(ar, "outcome", None)
            is_success = (
                outcome == AttackOutcome.SUCCESS
                if AttackOutcome
                else str(outcome).upper() == "SUCCESS"
            )

            # 提取 Converter 信息
            conv_info = extract_converter_info_from_result(ar)
            converter_chain = conv_info.get("converter_chain", "") if conv_info else ""

            # 提取 OWASP ID (多路径 fallback: owasp_mapping → metadata → display_group)
            owasp_ids: list[str] = []
            if owasp_mapping:
                attack_type = str(getattr(ar, "attack_type", "")) or technique
                owasp_ids = owasp_mapping.get(attack_type, [])
            # P0-O5: 无 owasp_mapping 时从 metadata 提取
            if not owasp_ids:
                _meta = getattr(ar, "metadata", None) or {}
                _owasp = _meta.get("owasp_id", "") if isinstance(_meta, dict) else ""
                if _owasp:
                    owasp_ids = [_owasp]
            # P0-O5: 仍无 OWASP ID 时从 display_group 提取
            if not owasp_ids:
                _dg = _meta.get("display_group", "") if isinstance(_meta, dict) else ""
                if _dg:
                    import re as _re
                    _m = _re.search(r"(llm\d{2}|asi\d{2})", _dg, _re.IGNORECASE)
                    if _m:
                        owasp_ids = [_m.group(1).upper()]

            # 构建链路
            chain = self._build_single_chain(
                technique=technique,
                converter_chain=converter_chain,
                is_success=is_success,
                owasp_ids=owasp_ids,
                attack_result=ar,
            )
            self._attack_chains.append(chain)

            # 时间线数据
            self._timeline_data.append({
                "technique": technique,
                "converter": converter_chain,
                "outcome": "SUCCESS" if is_success else "FAILURE",
                "turns": getattr(ar, "turns", 0) or 0,
                "execution_time": getattr(ar, "execution_time", 0) or 0,
                "owasp_ids": owasp_ids,
            })

    def _build_single_chain(
        self,
        *,
        technique: str,
        converter_chain: str,
        is_success: bool,
        owasp_ids: list[str],
        attack_result: Any,
    ) -> dict[str, Any]:
        """构建单个攻击的 Kill Chain 数据."""
        # 确定 Kill Chain 阶段 (P0-O5: 无 OWASP ID 时使用默认阶段)
        stages_covered: set[str] = set()
        for owasp_id in owasp_ids:
            stages_covered.update(self.OWASP_TO_KILL_CHAIN.get(owasp_id, ["delivery", "execution", "impact"]))
        # P0-O5: 无 OWASP ID 时给默认 Kill Chain 阶段 (成功攻击至少覆盖 delivery→execution→impact)
        if not stages_covered:
            stages_covered = {"delivery", "execution", "impact"}
        # P0-O5: 成功攻击自动覆盖 recon 和 initial_access (每条攻击都经历了侦察和初始访问)
        if is_success:
            stages_covered.add("recon")
            stages_covered.add("initial_access")
            stages_covered.add("delivery")
            stages_covered.add("execution")
            stages_covered.add("impact")
            if converter_chain:
                stages_covered.add("bypass")

        # 提取载荷和响应
        payload = str(getattr(attack_result, "objective", ""))[:500]
        response = ""
        for attr in ("response", "response_text", "target_response"):
            val = getattr(attack_result, attr, None)
            if val and isinstance(val, str):
                response = val[:500]
                break

        return {
            "technique": technique,
            "converter_chain": converter_chain,
            "is_success": is_success,
            "owasp_ids": owasp_ids,
            "stages_covered": sorted(stages_covered),
            "payload": payload,
            "response": response,
            "impact_description": self._describe_impact(owasp_ids, is_success),
        }

    @staticmethod
    def _describe_impact(owasp_ids: list[str], is_success: bool) -> str:
        """描述攻击影响."""
        if not is_success:
            return "攻击未成功 — 目标防御有效"
        if not owasp_ids:
            return "攻击成功 — 目标响应符合攻击目标"
        impact_map = {
            "LLM01": "提示注入成功 — 目标模型执行了非预期指令",
            "LLM02": "敏感信息泄露 — 目标暴露了内部数据",
            "LLM05": "不当输出处理 — 目标生成了有害内容",
            "LLM06": "过度权限 — Agent 执行了越权操作",
            "LLM07": "系统提示泄露 — 内部指令被提取",
            "ASI02": "工具误用 — Agent 工具被恶意调用",
            "ASI04": "数据外泄 — 敏感数据通过 Agent 外泄",
            "ASI05": "权限提升 — 攻击者获得了更高权限",
        }
        descriptions = [impact_map.get(oid, f"{oid} 攻击成功") for oid in owasp_ids]
        return " | ".join(descriptions)

    def render_mermaid_flowchart(self, max_chains: int = 10) -> str:
        """渲染 Mermaid 流程图源码.

        展示成功攻击的完整路径:
        Recon → Initial Access → Delivery → Bypass → Execution → Impact

        Args:
            max_chains: 最多展示的攻击链数量.

        Returns:
            Mermaid 流程图源码字符串.
        """
        successful_chains = [c for c in self._attack_chains if c["is_success"]]
        if not successful_chains:
            return "%% No successful attacks to visualize"

        chains = successful_chains[:max_chains]

        lines = ["```mermaid", "graph LR"]

        # 起始节点
        lines.append("    RECON[Reconnaissance<br/>Target Discovery]")

        for i, chain in enumerate(chains):
            prefix = f"A{i+1}"

            # 构建攻击路径节点
            lines.append(f"    {prefix}_DEL[{chain['technique']}<br/>Payload Delivery]")
            if chain["converter_chain"]:
                lines.append(f"    {prefix}_BYP[{chain['converter_chain'][:30]}<br/>Defense Bypass]")
            lines.append(f"    {prefix}_EXEC[Execution<br/>Target Response]")
            lines.append(f"    {prefix}_IMP[Impact<br/>{chain['impact_description'][:50]}]")

            # 连接路径
            lines.append(f"    RECON --> {prefix}_DEL")
            if chain["converter_chain"]:
                lines.append(f"    {prefix}_DEL --> {prefix}_BYP")
                lines.append(f"    {prefix}_BYP --> {prefix}_EXEC")
            else:
                lines.append(f"    {prefix}_DEL --> {prefix}_EXEC")
            lines.append(f"    {prefix}_EXEC --> {prefix}_IMP")

            # OWASP 标注
            if chain["owasp_ids"]:
                owasp_str = ", ".join(chain["owasp_ids"][:3])
                lines.append(f"    {prefix}_IMP -.->|{owasp_str}| OWASP[OWASP Coverage]")

        lines.append("```")
        return "\n".join(lines)

    def render_kill_chain_matrix(self) -> str:
        """渲染 Kill Chain 覆盖矩阵 (Markdown 表格).

        Returns:
            Markdown 表格字符串.
        """
        # 统计每个阶段的成功攻击数
        stage_counts: dict[str, int] = {s[0]: 0 for s in self.KILL_CHAIN_STAGES}
        stage_attacks: dict[str, list[str]] = {s[0]: [] for s in self.KILL_CHAIN_STAGES}

        for chain in self._attack_chains:
            if chain["is_success"]:
                for stage in chain["stages_covered"]:
                    if stage in stage_counts:
                        stage_counts[stage] += 1
                        stage_attacks[stage].append(chain["technique"])

        lines = [
            "\n### Kill Chain Coverage Matrix\n",
            "| Stage | Description | Successful Attacks | Techniques |",
            "|-------|-------------|-------------------|------------|",
        ]
        for stage_id, stage_name, stage_desc in self.KILL_CHAIN_STAGES:
            count = stage_counts.get(stage_id, 0)
            techs = list(set(stage_attacks.get(stage_id, [])))
            tech_str = ", ".join(techs[:3])
            if len(techs) > 3:
                tech_str += f" (+{len(techs) - 3})"
            coverage = f"{'✅' if count > 0 else '❌'} {count}"
            lines.append(f"| {stage_name} | {stage_desc} | {coverage} | {tech_str} |")

        return "\n".join(lines)

    def render_success_triad_cards(self) -> str:
        """渲染成功攻击三元组卡片 (Markdown).

        每个成功攻击展示: 载荷 + 目标响应 + 安全影响.

        Returns:
            Markdown 字符串.
        """
        successful = [c for c in self._attack_chains if c["is_success"]]
        if not successful:
            return "\n*No successful attacks to display*\n"

        lines = ["\n### Successful Attack Triads\n"]
        for i, chain in enumerate(successful[:10], 1):
            lines.append(f"\n#### Attack #{i}: {chain['technique']}")
            if chain["converter_chain"]:
                lines.append(f"- **Converter**: `{chain['converter_chain'][:100]}`")
            if chain["owasp_ids"]:
                lines.append(f"- **OWASP**: {', '.join(chain['owasp_ids'])}")

            lines.append(f"\n**Payload**:\n```\n{chain['payload'][:500]}\n```")
            if chain["response"]:
                lines.append(f"\n**Target Response**:\n```\n{chain['response'][:500]}\n```")
            lines.append(f"\n**Impact**: {chain['impact_description']}")
            lines.append("\n---\n")

        return "\n".join(lines)

    def render_timeline(self) -> str:
        """渲染攻击时间线 (Markdown 表格).

        Returns:
            Markdown 表格字符串.
        """
        if not self._timeline_data:
            return "\n*No timeline data available*\n"

        lines = [
            "\n### Attack Timeline\n",
            "| # | Technique | Converter | Outcome | Turns | Time | OWASP |",
            "|---|-----------|-----------|---------|--------|------|-------|",
        ]
        for i, entry in enumerate(self._timeline_data[:50], 1):
            outcome_icon = "✅" if entry["outcome"] == "SUCCESS" else "❌"
            conv_len = len(entry.get("converter", ""))
            converter = entry["converter"][:30] + "..." if conv_len > 30 else entry.get("converter", "")
            owasp_str = ", ".join(entry.get("owasp_ids", []))
            time_str = f"{entry['execution_time']:.1f}s" if entry.get("execution_time") else "N/A"
            lines.append(
                f"| {i} | {entry['technique']} | {converter} | {outcome_icon} | "
                f"{entry.get('turns', 0)} | {time_str} | {owasp_str} |"
            )

        if len(self._timeline_data) > 50:
            lines.append(f"| ... | *{len(self._timeline_data) - 50} more attacks* | | | | | |")

        return "\n".join(lines)

    def render_all(self) -> str:
        """渲染完整的攻击链路可视化 (嵌入 Markdown 报告).

        Returns:
            Markdown 字符串, 包含 Mermaid 图 + Kill Chain 矩阵 + 三元组卡片 + 时间线.
        """
        parts: list[str] = [
            "\n## 5. Attack Chain Visualization\n",
            "This section visualizes the complete attack paths from "
            "reconnaissance through impact, following the MITRE ATT&CK "
            "framework and Lockheed Martin Kill Chain methodology.\n",
        ]

        # Mermaid 流程图
        mermaid = self.render_mermaid_flowchart()
        parts.append(f"\n### Attack Path Flowchart\n\n{mermaid}\n")

        # Kill Chain 矩阵
        parts.append(self.render_kill_chain_matrix())
        parts.append("")

        # 成功攻击三元组
        parts.append(self.render_success_triad_cards())

        # 时间线
        parts.append(self.render_timeline())

        return "\n".join(parts)

    def get_summary(self) -> dict[str, Any]:
        """获取可视化摘要供报告使用."""
        successful = [c for c in self._attack_chains if c["is_success"]]
        return {
            "total_chains": len(self._attack_chains),
            "successful_chains": len(successful),
            "kill_chain_stages_covered": list({
                s for chain in successful for s in chain["stages_covered"]
            }),
            "techniques_used": list({c["technique"] for c in self._attack_chains}),
            "converters_used": list({
                c["converter_chain"] for c in self._attack_chains if c["converter_chain"]
            }),
        }

    # ── P4: 交互式 HTML 可视化 ──

    def render_interactive_html(self) -> str:
        """P4: 生成交互式 HTML 攻击链路可视化.

        包含:
          - 可折叠的攻击卡片 (点击展开/收起)
          - 按成功/失败/OWASP分类过滤
          - 搜索框实时搜索攻击技术/载荷
          - Kill Chain 覆盖热力图 (CSS grid)

        Returns:
            HTML 字符串 (嵌入到报告 <body> 中).
        """
        import html

        # 准备数据
        chains_json = json.dumps(
            [
                {
                    "technique": c["technique"],
                    "converter": c["converter_chain"][:100],
                    "success": c["is_success"],
                    "owasp": c["owasp_ids"],
                    "payload": c["payload"][:300],
                    "response": c["response"][:300],
                    "impact": c["impact_description"],
                    "stages": c["stages_covered"],
                }
                for c in self._attack_chains
            ],
            ensure_ascii=False,
        )

        # Kill Chain 热力图数据
        stage_counts: dict[str, int] = {s[0]: 0 for s in self.KILL_CHAIN_STAGES}
        for c in self._attack_chains:
            if c["is_success"]:
                for s in c["stages_covered"]:
                    if s in stage_counts:
                        stage_counts[s] += 1

        stages_html = ""
        for stage_id, stage_name, stage_desc in self.KILL_CHAIN_STAGES:
            count = stage_counts.get(stage_id, 0)
            intensity = min(count * 30, 255) if count > 0 else 20
            bg_color = f"rgba(255, {255 - intensity}, 0, 0.6)"
            stages_html += (
                f'<div class="kill-chain-cell" style="background:{bg_color}" '
                f'title="{html.escape(stage_desc)}">'
                f'<span class="stage-name">{html.escape(stage_name)}</span>'
                f'<span class="stage-count">{count}</span>'
                f'</div>'
            )

        total = len(self._attack_chains)
        success = sum(1 for c in self._attack_chains if c["is_success"])
        fail = total - success

        return f"""<div id="attack-chain-viz">
<style>
  #attack-chain-viz .filter-bar {{
    display: flex; gap: 10px; margin: 10px 0; flex-wrap: wrap;
  }}
  #attack-chain-viz .filter-btn {{
    padding: 6px 14px; border: 1px solid #888; border-radius: 4px;
    cursor: pointer; font-size: 13px; background: #f0f0f0;
  }}
  #attack-chain-viz .filter-btn.active {{
    background: #2563eb; color: white; border-color: #2563eb;
  }}
  #attack-chain-viz .search-box {{
    padding: 6px 10px; border: 1px solid #888; border-radius: 4px;
    font-size: 13px; width: 250px;
  }}
  #attack-chain-viz .kill-chain-grid {{
    display: grid; grid-template-columns: repeat(6, 1fr); gap: 5px; margin: 15px 0;
  }}
  #attack-chain-viz .kill-chain-cell {{
    text-align: center; padding: 10px 5px; border-radius: 4px; border: 1px solid #ccc;
  }}
  #attack-chain-viz .stage-name {{ display: block; font-size: 12px; font-weight: bold; }}
  #attack-chain-viz .stage-count {{ display: block; font-size: 20px; margin-top: 5px; }}
  #attack-chain-viz .attack-card {{
    border: 1px solid #ddd; border-radius: 6px; margin: 8px 0; overflow: hidden;
  }}
  #attack-chain-viz .attack-header {{
    padding: 10px 15px; cursor: pointer; display: flex; justify-content: space-between;
    align-items: center; background: #f8f9fa;
  }}
  #attack-chain-viz .attack-header.success {{ border-left: 4px solid #22c55e; }}
  #attack-chain-viz .attack-header.failure {{ border-left: 4px solid #ef4444; }}
  #attack-chain-viz .attack-body {{
    display: none; padding: 12px 15px; background: white; font-size: 13px;
  }}
  #attack-chain-viz .attack-body.open {{ display: block; }}
  #attack-chain-viz .attack-body pre {{
    background: #f5f5f5; padding: 8px; border-radius: 4px; overflow-x: auto;
    font-size: 12px; max-height: 200px;
  }}
  #attack-chain-viz .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: 11px; font-weight: bold; margin: 0 2px;
  }}
  #attack-chain-viz .badge-success {{ background: #dcfce7; color: #166534; }}
  #attack-chain-viz .badge-fail {{ background: #fee2e2; color: #991b1b; }}
  #attack-chain-viz .badge-owasp {{ background: #dbeafe; color: #1e40af; }}
  #attack-chain-viz .stats {{
    font-size: 13px; color: #666; margin: 10px 0;
  }}
</style>

<h3>Interactive Attack Chain Visualization</h3>
<div class="stats">
  Total: <strong>{total}</strong> |
  <span style="color:#22c55e">Success: {success}</span> |
  <span style="color:#ef4444">Failure: {fail}</span>
</div>

<div class="kill-chain-grid">{stages_html}</div>

<div class="filter-bar">
  <button class="filter-btn active" onclick="filterAttacks('all')">All ({total})</button>
  <button class="filter-btn" onclick="filterAttacks('success')">Success ({success})</button>
  <button class="filter-btn" onclick="filterAttacks('failure')">Failure ({fail})</button>
  <input type="text" class="search-box" placeholder="Search technique/payload..."
         oninput="filterBySearch(this.value)">
</div>

<div id="attack-cards"></div>

<script>
  const attacks = {chains_json};
  const container = document.getElementById('attack-cards');

  function renderCards(filter, search) {{
    container.innerHTML = '';
    attacks
      .filter(a => !filter || filter === 'all' ||
                     (filter === 'success' && a.success) ||
                     (filter === 'failure' && !a.success))
      .filter(a => !search || a.technique.toLowerCase().includes(search.toLowerCase()) ||
                     a.payload.toLowerCase().includes(search.toLowerCase()))
      .forEach((a, i) => {{
        const card = document.createElement('div');
        card.className = 'attack-card';
        const outcomeBadge = a.success
          ? '<span class="badge badge-success">SUCCESS</span>'
          : '<span class="badge badge-fail">FAILURE</span>';
        const owaspBadges = (a.owasp || []).map(
          o => `<span class="badge badge-owasp">${{o}}</span>`
        ).join('');
        card.innerHTML = `
          <div class="attack-header ${{a.success ? 'success' : 'failure'}}"
               onclick="this.nextElementSibling.classList.toggle('open')">
            <span>#${{i+1}} ${{a.technique}} ${{outcomeBadge}} ${{owaspBadges}}</span>
            <span style="color:#999;font-size:11px">click to expand</span>
          </div>
          <div class="attack-body">
            <p><strong>Converter:</strong> ${{a.converter || 'N/A'}}</p>
            <p><strong>Payload:</strong></p><pre>${{a.payload}}</pre>
            <p><strong>Response:</strong></p><pre>${{a.response || 'N/A'}}</pre>
            <p><strong>Impact:</strong> ${{a.impact}}</p>
            <p><strong>Kill Chain Stages:</strong> ${{(a.stages||[]).join(', ')}}</p>
          </div>`;
        container.appendChild(card);
      }});
  }}

  let currentFilter = 'all';
  function filterAttacks(f) {{
    currentFilter = f;
    document.querySelectorAll('#attack-chain-viz .filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    renderCards(f, document.querySelector('.search-box').value);
  }}
  function filterBySearch(s) {{ renderCards(currentFilter, s); }}

  renderCards('all', '');
</script>
</div>"""
