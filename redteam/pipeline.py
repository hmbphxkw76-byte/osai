"""AI-300 红队攻击流水线 (Pipeline)。

基于 OffSec AI-300 课程 11 章的完整攻击链编排，对齐 OSAI+ 认证考试要求：

  阶段              AI-300章节     模块
  ─────────────────────────────────────────────
  1. AI 攻击面侦察    Ch2          recon/ (ai_surface, auth_parse)
  2. 提示注入攻击     Ch3          attack/prompt_inject.py
  3. Agent 深度攻击   Ch3+Ch4      attack/agent_attack.py
  4. RAG 流水线攻击   Ch5          attack/rag_attack.py
  5. 嵌入模型攻击     Ch6 ✨       attack/embeddings_attack.py
  6. AI 供应链攻击    Ch8 ✨       attack/supply_chain.py
  7. MCP+基础设施攻击 Ch7+Ch9       attack/infra_attack.py
  8. 威胁建模与报告   Ch10+Ch11    pipeline.py: report_phase

设计原则：
  - Library-First：所有 HTTP/探测能力委托 httpx + 成熟工具
  - 渐进式：每一步基于上一步的发现推进
  - 失败隔离：单阶段失败不阻断后续阶段
  - 结果持久化：每个阶段产出 JSON checkpoint
"""
from __future__ import annotations

import uuid
import time
from pathlib import Path
from typing import Any

from redteam.core.models import (
    AIService, AttackChain, AttackStep, AuthContext, Finding,
    OWASPLlm, MITREATLASTactic, ReconResult, ReportConfig,
)
from redteam.core.store import save_json, load_json, save_findings, make_run_id
from redteam.core.tools import ToolResolver
from redteam.recon.auth_parse import parse_headers, parse_headers_file, describe_auth
from redteam.recon.ai_surface import (
    discover_ai_services, passive_recon, profile_guardrails,
)
from redteam.attack.prompt_inject import (
    run_direct_injection_phase, extract_system_prompt,
    run_jailbreak_phase, generate_injection_findings,
    run_full_injection_suite,
)
from redteam.attack.agent_attack import (
    test_indirect_injection, poison_agent_memory,
    hijack_agent_tools, cross_agent_attack,
    generate_agent_attack_findings,
    run_agent_attack_with_pyrit,
)
from redteam.attack.pyrit_runner import is_pyrit_available
from redteam.attack.rag_attack import (
    probe_vector_dbs, inject_rag_poison,
    check_retrieval_leakage, generate_rag_findings,
)
from redteam.attack.embeddings_attack import (
    probe_embedding_endpoints, test_embedding_inversion,
    inject_adversarial_embeddings, check_embedding_leakage,
    generate_embedding_findings,
)
from redteam.attack.supply_chain import (
    detect_hf_model_source, check_pickle_deserialization_risk,
    check_dataset_poisoning_risks, check_dependency_risks,
    generate_supply_chain_findings,
)
from redteam.attack.infra_attack import (
    scan_cloud_misconfigs, generate_infra_findings,
)


class AIPipeline:
    """AI-300 红队攻击流水线。"""

    def __init__(self, resolver: ToolResolver | None = None):
        self.resolver = resolver or ToolResolver()
        self.settings = self.resolver.settings

    # ===== 阶段一：AI 攻击面侦察 (Ch2) =====
    def recon_phase(
        self,
        target: str,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
    ) -> tuple[str, ReconResult, list[AIService]]:
        """AI 攻击面侦察。

        Args:
            target: 目标 URL
            header_text: F12 请求头文本
            header_file: F12 请求头文件路径
            run_id: 运行 ID

        Returns:
            (run_id, recon_result, ai_services)
        """
        run_id = run_id or make_run_id(target, uuid.uuid4().hex[:8])
        print(f"\n{'='*60}")
        print(f"[Phase 1] AI 攻击面侦察 - {target}")
        print(f"{'='*60}")

        # 解析认证
        auth: AuthContext | None = None
        if header_file:
            auth = parse_headers_file(header_file)
        elif header_text:
            auth = parse_headers(header_text)
        if auth:
            print(describe_auth(auth))

        recon = ReconResult(target=target)
        all_services: list[AIService] = []

        # 读取限速配置
        recon_cfg = self.settings.get("recon", {}) or {}
        rate_limit_ms = int(recon_cfg.get("rate_limit_ms", 0))
        if rate_limit_ms:
            print(f"[Recon] 限速模式: {rate_limit_ms}ms/请求")

        # 1.1 被动侦察
        print("\n[Recon] 被动侦察...")
        passive = passive_recon(target)
        print(f"  发现 AI 端点线索: {len(passive['ai_endpoints_hint'])}")
        print(f"  技术响应头: {passive['tech_headers']}")
        print(f"  CSP AI 域名: {passive['csp_ai_hints']}")

        # 1.2 主动 AI 服务发现
        print("\n[Recon] 主动 AI 服务发现...")
        services = discover_ai_services(target, auth, rate_limit_ms=rate_limit_ms)
        all_services.extend(services)
        for svc in services:
            print(f"  [{svc.protocol.upper()}] {svc.url} | 模型: {svc.models[:3]} | 认证: {svc.auth_required}")
        recon.ai_services = services
        recon.components = sorted(set(s.protocol for s in services))
        recon.models = sorted(set(m for s in services for m in s.models))

        # 1.3 护栏画像（三阶段：指纹→分类→绕过评估）
        for svc in services:
            if svc.protocol in ("openai_compatible", "ollama", "mcp", "generic_ai"):
                print(f"\n[Recon] 护栏画像: {svc.url}")
                guard = profile_guardrails(svc, auth=auth, rate_limit_ms=rate_limit_ms)
                svc.guardrail_profile = guard
                print(f"  护栏类型: {guard.guardrail_type.value} (置信度 {guard.guardrail_confidence})")
                print(f"  阻断类别: {[c.value for c in guard.blocked_categories]}")
                print(f"  绕过难度: {guard.bypass_difficulty}")
                if guard.recommended_techniques:
                    print(f"  推荐攻击策略: {guard.recommended_techniques}")
                if guard.discouraged_techniques:
                    print(f"  不推荐技术: {guard.discouraged_techniques}")

        # 持久化
        save_json(run_id, "recon", recon.model_dump())
        save_json(run_id, "services", [s.model_dump() for s in all_services])

        return run_id, recon, all_services

    # ===== 阶段二：提示注入攻击 (Ch3) =====
    def injection_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
        auth: AuthContext | None = None,
        use_pyrit: bool | None = None,
    ) -> tuple[list[Finding], AttackChain]:
        """提示注入攻击阶段。

        选择可攻击的 AI 服务，依次执行：
        1. 直接提示注入
        2. 系统提示提取
        3. 越狱/护栏绕过
        4. 间接提示注入

        Arg:
            use_pyrit: 是否使用 PyRIT 执行（None=自动检测）
        """
        print(f"\n{'='*60}")
        print("[Phase 2] 提示注入攻击")
        print(f"{'='*60}")

        chain = AttackChain(chain_id=run_id, target=recon.target)
        all_findings: list[Finding] = []
        step_id = 1

        # 筛选可攻击目标
        attackable = [s for s in services if s.protocol in (
            "openai_compatible", "ollama", "mcp", "generic_ai",
        )]
        if not attackable:
            print("  无可攻击的 AI 服务，跳过注入阶段")
            return all_findings, chain

        _pyrit = use_pyrit if use_pyrit is not None else is_pyrit_available()
        if _pyrit:
            print(f"  [PyRIT] 已启用（提升评分精度 + 编码绕过）")
        else:
            print(f"  [Native] 回退到手写 httpx 模式")

        for svc in attackable[:3]:  # 最多攻击前 3 个服务
            print(f"\n[Injection] 目标: [{svc.protocol}] {svc.url}")

            # 使用统一套件（自动选择 PyRIT/Native）
            suite = run_full_injection_suite(svc, auth, use_pyrit=_pyrit)
            direct_results = suite["direct"]
            sp_result = suite["system_prompt"]
            jailbreak_results = suite["jailbreak"]

            # 2.1 直接提示注入
            success_direct = sum(1 for r in direct_results if r.success)
            print(f"  [1/4] 直接提示注入: {success_direct}/{len(direct_results)} 成功")
            chain.steps.append(AttackStep(
                step_id=step_id, phase="direct_injection",
                technique="direct_prompt_injection",
                target_url=svc.url, status="success" if success_direct else "partial",
            ))
            step_id += 1

            # 2.2 系统提示提取
            if sp_result and sp_result.success:
                print(f"  [2/4] 系统提示提取: SUCCESS! ({sp_result.extracted_info[:80]}...)")
                chain.steps.append(AttackStep(
                    step_id=step_id, phase="system_prompt_extract",
                    technique=sp_result.technique,
                    target_url=svc.url, status="success",
                    evidence=sp_result.extracted_info[:500],
                ))
            else:
                print("  [2/4] 系统提示提取: 未成功")
                chain.steps.append(AttackStep(
                    step_id=step_id, phase="system_prompt_extract",
                    technique="multi_technique", target_url=svc.url, status="failed",
                ))
            step_id += 1

            # 2.3 越狱尝试
            success_jb = sum(1 for r in jailbreak_results if r.success)
            print(f"  [3/4] 越狱/护栏绕过: {success_jb}/{len(jailbreak_results)} 成功")
            chain.steps.append(AttackStep(
                step_id=step_id, phase="jailbreak",
                technique="jailbreak_multi", target_url=svc.url,
                status="success" if success_jb else "failed",
            ))
            step_id += 1

            # 2.4 间接提示注入
            indirect_results = test_indirect_injection(svc, auth)
            success_indirect = sum(1 for r in indirect_results if r.success)
            print(f"  [4/4] 间接提示注入: {success_indirect}/{len(indirect_results)} 成功")
            chain.steps.append(AttackStep(
                step_id=step_id, phase="indirect_injection",
                technique="indirect_prompt_injection", target_url=svc.url,
                status="success" if success_indirect else "partial",
            ))
            step_id += 1

            # 2.5 生成 Findings
            injection_findings = generate_injection_findings(
                svc, direct_results, sp_result, jailbreak_results,
            )
            all_findings.extend(injection_findings)

            chain.mitre_atlas_tactics.append(MITREATLASTactic.INITIAL_ACCESS.value)
            chain.owasp_llm_categories.append(OWASPLlm.LLM01_PROMPT_INJECTION.value)

        save_findings(run_id, all_findings)
        save_json(run_id, "attack_chain_injection", chain.model_dump())
        return all_findings, chain

    # ===== 阶段三：Agent 攻击 (Ch3+Ch4) =====
    def agent_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
        use_pyrit: bool | None = None,
    ) -> list[Finding]:
        """Agent 深度攻击：记忆投毒、工具劫持、跨智能体攻击。

        Arg:
            use_pyrit: 是否使用 PyRIT 评分器（None=自动检测）
        """
        print(f"\n{'='*60}")
        print("[Phase 3] Agent 深度攻击")
        print(f"{'='*60}")

        _pyrit = use_pyrit if use_pyrit is not None else is_pyrit_available()
        if _pyrit:
            print(f"  [PyRIT] 评分器已启用（LLM-as-Judge）")

        all_findings: list[Finding] = []
        agent_services = [s for s in services if s.protocol in ("mcp", "agent_to_agent") or s.tools]

        if not agent_services:
            print("  无 Agent 服务，跳过")
            return all_findings

        for svc in agent_services[:3]:
            print(f"\n[Agent] 目标: [{svc.protocol}] {svc.url}")

            if _pyrit:
                suite = run_agent_attack_with_pyrit(svc, auth)
                indirect_results = suite["indirect"]
                memory_results = suite["memory"]
                tool_results = suite["tool"]
                cross_results = suite["cross_agent"]
                print(f"  [PyRIT] 间接注入:{len(indirect_results)} 记忆投毒:{len(memory_results)} 工具劫持:{len(tool_results)} 跨智能体:{len(cross_results)}")
            else:
                print("  [1] 记忆投毒...")
                memory_results = poison_agent_memory(svc, auth)
                print(f"      载荷数: {len(memory_results)}")
                print("  [2] 工具劫持...")
                tool_results = hijack_agent_tools(svc, auth)
                print(f"      载荷数: {len(tool_results)}")
                print("  [3] 跨智能体攻击...")
                cross_results = cross_agent_attack(svc, auth)
                print(f"      载荷数: {len(cross_results)}")
                indirect_results = test_indirect_injection(svc, auth)

            findings = generate_agent_attack_findings(
                svc, indirect_results, memory_results, tool_results, cross_results,
            )
            all_findings.extend(findings)

        # 合并已有 findings
        prior = load_json(run_id, "findings") or []
        all_findings = prior + [f.model_dump() for f in all_findings]
        save_json(run_id, "findings", all_findings)
        return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]

    # ===== 阶段四：RAG 攻击 (Ch5) =====
    def rag_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """RAG 流水线攻击。"""
        print(f"\n{'='*60}")
        print("[Phase 4] RAG 流水线攻击")
        print(f"{'='*60}")

        all_findings: list[Finding] = []

        for svc in services[:3]:
            base = svc.url.rsplit("/", 1)[0] if "/" in svc.url else svc.url

            # 向量数据库探测
            print(f"\n[VectorDB] 探测 {base}...")
            vdbs = probe_vector_dbs(base, auth)
            print(f"  发现 {len(vdbs)} 个向量数据库端点")

            # RAG 投毒
            print("[RAG] 知识库投毒...")
            poison_results = inject_rag_poison(svc, auth)
            print(f"  投毒尝试: {len(poison_results)}")

            # 检索泄露检测
            print("[RAG] 检索泄露检测...")
            leakage = check_retrieval_leakage(svc, auth)
            leaked = sum(1 for l in leakage if l.get("leaked"))
            print(f"  检出泄露: {leaked}/{len(leakage)}")

            findings = generate_rag_findings(svc, vdbs, poison_results, leakage)
            all_findings.extend(findings)

        prior = load_json(run_id, "findings") or []
        all_findings = prior + [f.model_dump() for f in all_findings]
        save_json(run_id, "findings", all_findings)
        return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]

    # ===== 阶段五：嵌入模型攻击 (Ch6) =====
    def embeddings_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """嵌入模型攻击阶段。

        AI-300 Ch6 完整攻击链：
        1. 嵌入端点探测
        2. 嵌入反转风险测试
        3. 对抗性嵌入注入
        4. 嵌入信息泄露检测
        """
        print(f"\n{'='*60}")
        print("[Phase 5] 嵌入模型攻击 (Ch6: Attacking Embeddings)")
        print(f"{'='*60}")

        all_findings: list[Finding] = []

        for svc in services[:3]:
            print(f"\n[Embeddings] 目标: [{svc.protocol}] {svc.url}")

            # 5.1 嵌入端点探测
            print("  [1/4] 嵌入端点探测...")
            emb_endpoints = probe_embedding_endpoints(svc.url, auth)
            accessible = sum(1 for ep in emb_endpoints if ep.get("accessible"))
            print(f"    发现 {len(emb_endpoints)} 个端点, {accessible} 个可访问")

            # 5.2 嵌入反转测试
            print("  [2/4] 嵌入反转风险测试...")
            inversion_results = test_embedding_inversion(svc, auth)
            inv_possible = sum(1 for r in inversion_results if r.get("inversion_possible"))
            print(f"    反转风险: {inv_possible}/{len(inversion_results)}")

            # 5.3 对抗性嵌入注入
            print("  [3/4] 对抗性嵌入注入...")
            adversarial_results = inject_adversarial_embeddings(svc, auth)
            injected = sum(1 for r in adversarial_results if r.get("injected"))
            print(f"    注入成功: {injected}/{len(adversarial_results)}")

            # 5.4 嵌入信息泄露检测
            print("  [4/4] 嵌入信息泄露检测...")
            leakage_results = check_embedding_leakage(svc, auth)
            print(f"    发现 {len(leakage_results)} 处信息泄露")

            findings = generate_embedding_findings(
                svc, emb_endpoints, inversion_results,
                adversarial_results, leakage_results,
            )
            all_findings.extend(findings)

        prior = load_json(run_id, "findings") or []
        all_findings = prior + [f.model_dump() for f in all_findings]
        save_json(run_id, "findings", all_findings)
        save_json(run_id, "phase_embeddings", {
            "total_endpoints": len([s for s in services for ep in probe_embedding_endpoints(s.url)]),
        })
        return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]

    # ===== 阶段六：AI 供应链攻击 (Ch8) =====
    def supply_chain_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """AI 供应链攻击阶段。

        AI-300 Ch8 完整攻击链：
        1. HuggingFace 模型来源可信度检测
        2. Pickle 反序列化 RCE 风险
        3. 数据集投毒风险
        4. 依赖攻击风险
        """
        print(f"\n{'='*60}")
        print("[Phase 6] AI 供应链攻击 (Ch8: Supply Chain Attacks)")
        print(f"{'='*60}")

        all_findings: list[Finding] = []

        for svc in services[:3]:
            print(f"\n[SupplyChain] 目标: [{svc.protocol}] {svc.url}")

            # 6.1 HuggingFace 模型来源检测
            print("  [1/4] 模型来源可信度检测...")
            hf_risks = detect_hf_model_source(svc)
            high_risk = sum(1 for r in hf_risks if r.get("risk_level") in ("high", "critical"))
            print(f"    发现 {len(hf_risks)} 个模型, {high_risk} 个高风险")

            # 6.2 Pickle 反序列化 RCE
            print("  [2/4] Pickle 反序列化 RCE 风险...")
            pickle_risks = check_pickle_deserialization_risk(svc, auth)
            vulnerable = sum(1 for r in pickle_risks if r.get("vulnerable"))
            print(f"    风险端点: {vulnerable}/{len(pickle_risks)}")

            # 6.3 数据集投毒风险
            print("  [3/4] 数据集投毒风险检查...")
            dataset_risks = check_dataset_poisoning_risks(svc, auth)
            print(f"    发现 {len(dataset_risks)} 个风险点")

            # 6.4 依赖攻击风险
            print("  [4/4] 依赖攻击风险检查...")
            dependency_risks = check_dependency_risks(svc)
            print(f"    发现 {len(dependency_risks)} 个风险点")

            findings = generate_supply_chain_findings(
                svc, hf_risks, pickle_risks, dataset_risks, dependency_risks,
            )
            all_findings.extend(findings)

        prior = load_json(run_id, "findings") or []
        all_findings = prior + [f.model_dump() for f in all_findings]
        save_json(run_id, "findings", all_findings)
        return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]

    # ===== 阶段七：基础设施攻击 (Ch7+Ch9) =====
    def infra_attack_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
    ) -> list[Finding]:
        """MCP 工具面 + AI 基础设施攻击 (Ch7+Ch9)。

        供应链部分已独立为 Phase 6 (supply_chain_phase)。
        本阶段聚焦：
          - MCP 端点安全扫描 (Ch7)
          - 云 AI 服务配置错误检测 (Ch9)
        """
        print(f"\n{'='*60}")
        print("[Phase 7] MCP + AI 基础设施攻击 (Ch7+Ch9)")
        print(f"{'='*60}")

        all_findings: list[Finding] = []

        # MCP 端点枚举（基于 recon 阶段已发现的端点）
        mcp_urls = [e["url"] for e in recon.endpoints if "mcp" in e.get("url", "").lower()]
        mcp_results: list[dict] = []
        if mcp_urls:
            print(f"\n[MCP] 检测到 {len(mcp_urls)} 个 MCP 端点（待手动分析）")
            for mcp_url in mcp_urls[:5]:
                print(f"  - {mcp_url}")

        # 云配置扫描 (Ch9)
        print("\n[Cloud] AI 云端配置检查...")
        cloud_findings = scan_cloud_misconfigs(recon.target)
        if cloud_findings:
            print(f"  发现 {len(cloud_findings)} 个配置问题")
        else:
            print("  未发现明显问题")

        # 供应链快速过一遍（已在 Phase 6 完成深度检查，这里仅作为补充回显）
        supply_risks: list[dict] = []

        findings = generate_infra_findings(mcp_results, supply_risks, cloud_findings)
        all_findings.extend(findings)

        prior = load_json(run_id, "findings") or []
        all_findings = prior + [f.model_dump() for f in all_findings]
        save_json(run_id, "findings", all_findings)
        return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]

    # ===== 阶段八：威胁建模与报告 (Ch10+Ch11) =====
    def report_phase(
        self,
        run_id: str,
        recon: ReconResult,
        findings: list[Finding],
        attack_chain: AttackChain | None = None,
    ) -> ReportConfig:
        """威胁建模 (Ch10) 与综合红队报告 (Ch11)。"""
        print(f"\n{'='*60}")
        print("[Phase 8] MITRE ATLAS 威胁建模 + Capstone 报告 (Ch10+Ch11)")
        print(f"{'='*60}")

        recon_data = load_json(run_id, "recon") or {}
        f_list = load_json(run_id, "findings") or []

        # 统计
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        owasp_counts: dict[str, int] = {}
        for f in f_list:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = f.get("owasp_llm", "")
            if cat:
                owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        print(f"\n  总发现: {len(f_list)}")
        print(f"  Critical: {severity_counts['critical']} | High: {severity_counts['high']} | Medium: {severity_counts['medium']}")
        if owasp_counts:
            print(f"  OWASP LLM Top 10 覆盖: {list(owasp_counts.keys())}")

        # 构建摘要
        summary_lines = [
            "# AI-300 红队评估报告",
            "",
            f"**目标**: {recon.target}",
            f"**Run ID**: {run_id}",
            "**评估方法**: OffSec AI-300 Advanced AI Red Teaming",
            "",
            "## 发现摘要",
            f"- 总发现数: {len(f_list)}",
            f"- Critical: {severity_counts['critical']}",
            f"- High: {severity_counts['high']}",
            f"- Medium: {severity_counts['medium']}",
            "",
            "## 发现列表",
        ]

        for f in sorted(f_list, key=lambda x: ("critical,high,medium,low,info").index(x.get("severity", "info"))):
            summary_lines.append(
                f"- [{f.get('severity', '').upper()}] {f.get('title', '')} "
                f"({f.get('owasp_llm', '')})"
            )

        report = ReportConfig(
            target=recon.target,
            run_id=run_id,
            summary="\n".join(summary_lines),
            recon=recon,
            findings=[Finding(**f) if isinstance(f, dict) else f for f in f_list],
            attack_chain=attack_chain,
        )

        save_json(run_id, "report", report.model_dump())
        self._write_markdown_report(run_id, report)
        return report

    def _write_markdown_report(self, run_id: str, report: ReportConfig) -> Path:
        """写入 Markdown 报告。"""
        p = Path(f"reports/{run_id}/AI300_Report.md")
        p.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# AI-300 红队评估报告",
            "",
            f"**目标**: {report.target}",
            f"**Run ID**: {report.run_id}",
            f"**评估方法**: {report.methodology}",
            f"**时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "---",
            "",
            "## 执行摘要",
            "",
        ]

        # 发现统计
        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in report.findings:
            sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

        lines.append(f"- **总发现数**: {len(report.findings)}")
        lines.append(f"- **Critical**: {sev_count['critical']} | **High**: {sev_count['high']} | **Medium**: {sev_count['medium']} | **Low**: {sev_count['low']}")
        lines.append("")

        # 侦察结果
        if report.recon:
            lines.append("## 侦察结果")
            lines.append(f"- 发现的 AI 组件: {', '.join(report.recon.components) if report.recon.components else '无'}")
            lines.append(f"- 发现的模型: {', '.join(report.recon.models[:10]) if report.recon.models else '无'}")
            lines.append("")

        # 逐条发现
        lines.append("## 发现详情")
        lines.append("")
        for idx, f in enumerate(report.findings, 1):
            lines.append(f"### Finding #{idx}: {f.title}")
            lines.append("")
            lines.append("| 属性 | 值 |")
            lines.append("|------|-----|")
            lines.append(f"| 严重程度 | **{f.severity.upper()}** |")
            lines.append(f"| 来源 | {f.source} |")
            lines.append(f"| 分类 | {f.category} |")
            if f.owasp_llm:
                lines.append(f"| OWASP LLM | {f.owasp_llm.value} |")
            if f.mitre_atlas_tactic:
                lines.append(f"| MITRE ATLAS | {f.mitre_atlas_tactic.value} |")
            if f.endpoint:
                lines.append(f"| 端点 | {f.endpoint} |")
            lines.append("")
            if f.description:
                lines.append(f"**描述**: {f.description}")
                lines.append("")
            if f.evidence:
                lines.append("**证据**:")
                lines.append("```")
                lines.append(f.evidence[:1000])
                lines.append("```")
                lines.append("")
            if f.remediation:
                lines.append(f"**修复建议**: {f.remediation}")
                lines.append("")
            lines.append("---")
            lines.append("")

        p.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n  Markdown 报告: {p}")
        return p

    # ===== 全流程一键执行 =====
    def run_all(
        self,
        target: str,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
        phases: list[str] | None = None,
    ) -> dict[str, Any]:
        """执行完整的 AI-300 红队评估流程。

        对齐 OffSec AI-300 11 章 + OSAI+ 认证考试要求。

        Args:
            target: 目标 URL
            header_text: F12 请求头文本
            header_file: F12 请求头文件路径
            run_id: 运行 ID（续跑用）
            phases: 指定只执行某些阶段
                    可选值: recon, injection, agent, rag, embeddings,
                           supply_chain, infra, report

        Returns:
            完整的评估结果字典
        """
        started = time.time()

        if phases is None:
            phases = [
                "recon", "injection", "agent", "rag",
                "embeddings", "supply_chain", "infra", "report",
            ]

        # 解析认证
        auth: AuthContext | None = None
        if header_file:
            auth = parse_headers_file(header_file)
        elif header_text:
            auth = parse_headers(header_text)
        if auth:
            print(describe_auth(auth))

        # Phase 1: Recon (Ch2)
        if "recon" in phases:
            run_id, recon, services = self.recon_phase(target, header_text, header_file, run_id)
        else:
            recon_data = load_json(run_id or "", "recon") or {}
            services_data = load_json(run_id or "", "services") or []
            recon = ReconResult(**recon_data) if recon_data else ReconResult(target=target)
            services = [AIService(**s) for s in services_data] if services_data else []
            print(f"[Resume] 跳过侦察，已有 {len(services)} 个 AI 服务")

        all_findings: list[Finding] = []
        chain: AttackChain | None = None

        # Phase 2: Prompt Injection (Ch3)
        if "injection" in phases and services:
            inj_findings, chain = self.injection_phase(run_id, recon, services, auth)
            all_findings.extend(inj_findings)

        # Phase 3: Agent Attack (Ch3+Ch4)
        if "agent" in phases and services:
            agent_findings = self.agent_attack_phase(run_id, services, auth)
            all_findings = agent_findings

        # Phase 4: RAG Attack (Ch5)
        if "rag" in phases and services:
            rag_findings = self.rag_attack_phase(run_id, services, auth)
            all_findings = rag_findings

        # Phase 5: Embeddings Attack (Ch6)
        if "embeddings" in phases and services:
            emb_findings = self.embeddings_attack_phase(run_id, services, auth)
            all_findings = emb_findings

        # Phase 6: Supply Chain Attack (Ch8)
        if "supply_chain" in phases and services:
            sc_findings = self.supply_chain_phase(run_id, services, auth)
            all_findings = sc_findings

        # Phase 7: Infrastructure Attack (Ch7+Ch9)
        if "infra" in phases:
            infra_findings = self.infra_attack_phase(run_id, recon, services)
            all_findings = infra_findings

        # Phase 8: Threat Modeling + Report (Ch10+Ch11)
        if "report" in phases:
            report = self.report_phase(run_id, recon, all_findings, chain)

        elapsed = time.time() - started

        # 最终输出
        print(f"\n{'='*60}")
        print("  评估完成!")
        print(f"  总耗时: {elapsed:.1f}s")
        print(f"  总发现: {len(all_findings)}")
        print(f"  Run ID: {run_id}")
        print(f"  报告: reports/{run_id}/AI300_Report.md")
        print(f"{'='*60}")

        return {
            "run_id": run_id,
            "recon": recon,
            "services": [s.model_dump() for s in services],
            "findings": [f.model_dump() for f in all_findings],
            "attack_chain": chain.model_dump() if chain else None,
            "total_duration_seconds": round(elapsed, 1),
        }
