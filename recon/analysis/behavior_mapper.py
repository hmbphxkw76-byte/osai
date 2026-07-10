"""
===============================================================================
AI 侦测引擎 — 行为测绘模块 (Behavior Mapper)
===============================================================================
Phase 5: 基于侦察数据综合分析，识别最弱安全边界，输出针对性攻击入口建议。

分析维度:
  1. 认证安全性       — 是否有认证/Guest 访问/密钥泄露
  2. 端点暴露度       — 调试端点/管理端点是否开放
  3. 模型防护         — Guardrail 强度/提示词泄露风险
  4. WAF 绕过可行性   — WAF 类型/已知绕过方法
  5. 输入验证         — 注入点/文件上传/参数复杂度
  6. Agent 攻击面     — 工具数量/可执行命令/数据源访问
  7. 信息泄露         — JS SDK 密钥/Agent Card/响应头

返回结构:
  BehaviorMap(
      weakness_scores: {...},        # 各维度评分
      overall_security_score,        # 综合安全分 (0=最弱, 100=最强)
      critical_findings,             # 严重发现
      attack_vectors,                # 推荐攻击向量 (按优先级排序)
      weakest_boundary,              # 最弱安全边界描述
      bypass_feasibility,            # 绕过可行性评估
      target_attack_entry,           # 推荐攻击入口
      summary,                       # 摘要
      detailed_report,               # 详细报告 (Markdown)
  )

设计原则:
  ✅ 基于证据 — 所有评分来自实际侦察数据
  ✅ 红队视角 — 输出即用型攻击建议
  ✅ 优先级排序 — 标注攻击向量优先级 (critical/high/medium/low)
  ✅ 与 PyRIT 对接 — attack_vectors 可直接映射 PyRIT orchestrators
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from recon.schema import TargetProfile, EndpointCategory


@dataclass
class WeaknessScore:
    """单个安全维度评分"""
    dimension: str = ""
    score: float = 0.0  # 0.0=完全脆弱, 10.0=非常安全
    evidence: list[str] = field(default_factory=list)
    details: str = ""


@dataclass
class AttackVector:
    """攻击向量建议"""
    name: str = ""
    priority: str = "medium"  # critical / high / medium / low
    description: str = ""
    pyrit_orchestrator: str = ""  # 对应 PyRIT orchestrator
    required_data: list[str] = field(default_factory=list)
    preconditions: str = ""
    success_probability: float = 0.5


@dataclass
class BehaviorMap:
    """行为测绘完整输出"""

    # 各维度评分 (0-10)
    weakness_scores: list[WeaknessScore] = field(default_factory=list)

    # 综合评分
    overall_security_score: float = 50.0
    overall_label: str = "medium"  # critical / high / medium / low

    # 关键发现
    critical_findings: list[str] = field(default_factory=list)
    positive_findings: list[str] = field(default_factory=list)

    # 攻击面
    attack_surface_summary: str = ""
    attack_vectors: list[AttackVector] = field(default_factory=list)
    weakest_boundary: str = ""
    target_attack_entry: str = ""

    # 绕过评估
    bypass_feasibility: str = "unknown"
    bypass_methods: list[str] = field(default_factory=list)

    # 报告
    summary: str = ""
    detailed_report: str = ""


class BehaviorMapper:
    """行为测绘分析器 — 综合分析所有 Phase 数据，生成攻击路线图。"""

    def __init__(self):
        self._dimensions = {}

    def map(self, profile: TargetProfile) -> BehaviorMap:
        """从完整 TargetProfile 生成行为测绘。

        Args:
            profile: 已完成所有侦察阶段的 TargetProfile

        Returns:
            BehaviorMap — 包含攻击路线图的完整分析
        """
        bm = BehaviorMap()

        # ── 维度 1: 认证安全性 (0-10) ──
        auth_score, auth_evidence, auth_detail = self._eval_auth(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="认证安全性",
            score=auth_score,
            evidence=auth_evidence,
            details=auth_detail,
        ))

        # ── 维度 2: 端点暴露度 (0-10) ──
        ep_score, ep_evidence, ep_detail = self._eval_endpoints(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="端点暴露度",
            score=ep_score,
            evidence=ep_evidence,
            details=ep_detail,
        ))

        # ── 维度 3: 模型防护 (0-10) ──
        guard_score, guard_evidence, guard_detail = self._eval_model_guard(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="模型防护强度",
            score=guard_score,
            evidence=guard_evidence,
            details=guard_detail,
        ))

        # ── 维度 4: WAF/IPS 旁路可行性 (0-10) ──
        waf_score, waf_evidence, waf_detail = self._eval_waf(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="WAF 防护",
            score=waf_score,
            evidence=waf_evidence,
            details=waf_detail,
        ))

        # ── 维度 5: 输入验证 (0-10) ──
        input_score, input_evidence, input_detail = self._eval_input(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="输入验证",
            score=input_score,
            evidence=input_evidence,
            details=input_detail,
        ))

        # ── 维度 6: Agent 攻击面 (0-10) ──
        agent_score, agent_evidence, agent_detail = self._eval_agent(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="Agent 攻击面",
            score=agent_score,
            evidence=agent_evidence,
            details=agent_detail,
        ))

        # ── 维度 7: 信息泄露 (0-10) ──
        leak_score, leak_evidence, leak_detail = self._eval_info_leaks(profile)
        bm.weakness_scores.append(WeaknessScore(
            dimension="信息泄露风险",
            score=leak_score,
            evidence=leak_evidence,
            details=leak_detail,
        ))

        # 计算综合评分
        bm.overall_security_score = sum(ws.score for ws in bm.weakness_scores) / len(bm.weakness_scores)

        if bm.overall_security_score < 3.0:
            bm.overall_label = "critical"
        elif bm.overall_security_score < 5.0:
            bm.overall_label = "high"
        elif bm.overall_security_score < 7.0:
            bm.overall_label = "medium"
        else:
            bm.overall_label = "low"

        # 找出最弱边界
        weakest = min(bm.weakness_scores, key=lambda ws: ws.score)
        bm.weakest_boundary = (
            f"{weakest.dimension} (评分: {weakest.score:.1f}/10) — {weakest.details}"
        )

        # 生成攻击向量
        bm.attack_vectors = self._generate_attack_vectors(profile, bm)

        # 确定攻击入口
        bm.target_attack_entry = self._determine_attack_entry(profile, bm)

        # 生成报告
        bm = self._build_report(profile, bm)

        return bm

    # ── 维度评估 ──

    def _eval_auth(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估认证安全性。"""
        score = 10.0
        evidence = []

        auth_type = p.auth.type
        if auth_type in ("none", ""):
            score -= 4.0
            evidence.append("无认证要求 — 任何人均可访问 AI 端点")
            detail = "未配置认证，攻击者无需凭证即可直接访问"
        elif auth_type == "cookie":
            score -= 2.0
            evidence.append("仅 Cookie 认证 — 可能易被 CSRF/XSS 窃取")
            detail = "Cookie 认证存在窃取风险"
        elif auth_type == "bearer":
            score -= 1.5
            evidence.append("Bearer Token 认证 — 需注意 Token 泄露")
            detail = "Bearer Token 认证，安全性取决于 Token 管理"
        elif auth_type == "api_key":
            score -= 1.0
            detail = "API Key 认证，相对安全"
        else:
            detail = f"认证方式: {auth_type}"

        # 检查登录 URL 暴露
        if p.auth.login_url:
            score -= 0.5
            evidence.append(f"登录页面暴露: {p.auth.login_url}")

        # 检查是否有凭据泄露
        if p.credentials and p.credentials.critical_count > 0:
            score -= 3.0
            evidence.append(f"检测到 {p.credentials.critical_count} 个严重密钥泄露!")
            detail += " — 存在密钥泄露!"

        return max(0, score), evidence, detail

    def _eval_endpoints(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估端点暴露度。"""
        score = 10.0
        evidence = []

        categories = [ep.category for ep in p.api_endpoints]

        debug_eps = sum(1 for c in categories if c == EndpointCategory.DEBUG.value)
        admin_eps = sum(1 for c in categories if c == EndpointCategory.ADMIN.value)
        chat_eps = sum(1 for c in categories if c == EndpointCategory.CHAT.value)
        agent_eps = sum(1 for c in categories if c == EndpointCategory.AGENT.value)
        tools_eps = sum(1 for c in categories if c == EndpointCategory.TOOLS.value)

        if debug_eps > 0:
            score -= 3.0
            evidence.append(f"{debug_eps} 个调试端点暴露")
        if admin_eps > 0:
            score -= 2.5
            evidence.append(f"{admin_eps} 个管理端点暴露")
        if agent_eps > 0:
            score -= 1.0
            evidence.append(f"{agent_eps} 个 Agent 端点暴露")
        if tools_eps > 0:
            score -= 1.0
            evidence.append(f"{tools_eps} 个工具/MCP 端点暴露")

        total_eps = len(p.api_endpoints)
        if total_eps == 0:
            if not evidence:
                evidence.append("未发现 API 端点")
            detail = "未发现 API 端点"

        if debug_eps > 0:
            detail = f"暴露 {debug_eps} 个调试端点 + {admin_eps} 个管理端点 — 攻击面极宽"
        elif admin_eps > 0:
            detail = f"暴露 {admin_eps} 个管理端点 — 提权/配置修改可能存在风险"
        elif total_eps > 0:
            detail = f"发现 {total_eps} 个端点，未检测到敏感端点暴露"
        else:
            detail = "未发现 API 端点"

        return max(0, score), evidence, detail

    def _eval_model_guard(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估模型防护强度。"""
        score = 10.0
        evidence = []

        rag = p.rag_probe

        if rag.guardrail_detected:
            bound_count = len(rag.guardrail_boundaries or [])
            score -= min(3.0, bound_count * 0.5)
            evidence.append(f"Guardrail 检测: {bound_count} 个检测点")
            detail = f"检测到 Guardrail ({bound_count} 个边界点) — 有一定防护"
        else:
            score -= 2.0
            evidence.append("未检测到 Guardrail")
            detail = "未检测到模型层面的防护 — 直接 prompt 注入可能有效"

        # 检查是否有提示词提取结果
        if p.rag_probe.rag_confidence > 0.5:
            score -= 1.0
            evidence.append(f"RAG 系统 (置信度 {p.rag_probe.rag_confidence:.0%}) — RAG 可能引入新的注入面")

        return max(0, score), evidence, detail

    def _eval_waf(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估 WAF 防护。"""
        score = 10.0
        evidence = []

        waf = p.waf

        if waf.waf_count == 0:
            score -= 4.0
            evidence.append("未检测到 WAF/CDN/IPS")
            detail = "未检测到 WAF — 攻击流量不会被过滤，但速率限制可能仍存在"
        elif waf.waf_count == 1:
            score -= 2.0
            waf_name = waf.detections[0].get("name", "Unknown") if waf.detections else "Unknown"
            evidence.append(f"检测到 WAF: {waf_name}")
            detail = f"检测到 {waf_name} — 有单层防护，需要针对性绕过"
        else:
            score -= 1.0
            names = [d.get("name", "?") for d in waf.detections[:3]]
            evidence.append(f"多层 WAF: {', '.join(names)}")
            detail = f"多层防护 ({len(names)} 层) — 需要深度绕过策略"

        # 检查速率限制
        rl = p.rate_limit
        if rl.has_rate_limit and rl.total_429s > 0:
            score -= 1.0
            evidence.append(f"速率限制触发 {rl.total_429s} 次")
        if not rl.has_rate_limit:
            evidence.append("未检测到速率限制")

        return max(0, score), evidence, detail

    def _eval_input(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估输入验证和注入面。"""
        score = 10.0
        evidence = []

        # 检查上传端点
        upload_eps = [ep for ep in p.api_endpoints if ep.category == EndpointCategory.UPLOAD.value]
        if upload_eps:
            score -= 2.0
            evidence.append(f"{len(upload_eps)} 个文件上传端点 — 可能允许文件注入")
            detail = f"存在文件上传端点 — 恶意文件注入可能"
        else:
            evidence.append("未发现文件上传端点")
            detail = "未发现文件上传端点"

        # 检查流式端点
        stream_eps = [ep for ep in p.api_endpoints if ep.category == EndpointCategory.STREAM.value]
        if stream_eps:
            score -= 0.5
            evidence.append(f"{len(stream_eps)} 个流式端点 — 流式传输可能绕过内容过滤器")

        # 检查参数复杂度
        if len(p.api_endpoints) > 20:
            score -= 1.0
            evidence.append(f"大量端点 ({len(p.api_endpoints)}) — 攻击面广")

        return max(0, score), evidence, detail

    def _eval_agent(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估 Agent 攻击面。"""
        score = 10.0
        evidence = []

        rag = p.rag_probe

        if rag.is_agent:
            score -= 3.0
            evidence.append("Agent 系统 — 可能存在工具滥用/命令注入")
            if rag.has_tools:
                tool_penalty = min(3.0, rag.agent_tools_count * 0.3)
                score -= tool_penalty
                evidence.append(f"Agent 暴露 {rag.agent_tools_count} 个工具")
            if rag.has_browsing:
                score -= 1.5
                evidence.append("Agent 具有网页浏览能力 — SSRF 风险")
            if rag.has_memory:
                score -= 1.0
                evidence.append("Agent 具有会话记忆 — 持久化注入可能")
            if rag.is_multi_agent:
                score -= 2.0
                evidence.append("多智能体系统 — 委托链攻击面")
            detail = f"Agent 系统 ({rag.agent_tools_count} 工具, {'有' if rag.has_browsing else '无'}浏览, {'有' if rag.has_memory else '无'}记忆)"
        elif rag.is_rag:
            score -= 1.0
            evidence.append("RAG 系统 — 间接注入/数据中毒可能")
            detail = "RAG 系统 — 可通过检索源进行间接注入"
        else:
            evidence.append("纯 LLM — Agent 攻击面较小")
            detail = "纯 LLM，无 Agent/RAG 复杂攻击面"

        if rag.agent_card_discovered:
            score -= 1.0
            evidence.append(f"Agent Card 公开: {rag.agent_card_url}")

        return max(0, score), evidence, detail

    def _eval_info_leaks(self, p: TargetProfile) -> tuple[float, list[str], str]:
        """评估信息泄露风险。"""
        score = 10.0
        evidence = []

        # JS SDK 泄露
        js = p.js_sdk
        if js.total_matches > 0:
            penalty = min(3.0, js.total_matches * 0.5)
            score -= penalty
            evidence.append(f"JS 中发现 {js.total_matches} 个 AI SDK 引用")
        if js.extracted_api_urls:
            evidence.append(f"JS 泄露 {len(js.extracted_api_urls)} 个 API URL")

        # 响应头泄露
        raw = p.raw_probe_data
        if raw.server_header:
            score -= 0.5
            evidence.append(f"Server 头泄露: {raw.server_header}")
        if raw.powered_by:
            score -= 0.3
            evidence.append(f"X-Powered-By 泄露: {raw.powered_by}")

        # 密钥泄露
        creds = p.credentials
        if creds.critical_count > 0:
            score -= 3.0
            evidence.append(f"严重密钥泄露: {creds.critical_count} 个")
        elif creds.high_count > 0:
            score -= 1.5
            evidence.append(f"高危密钥泄露: {creds.high_count} 个")

        if not evidence:
            evidence.append("未发现明显信息泄露")
            detail = "良好 — 未检测到信息泄露"
        else:
            detail = f"检测到 {len(evidence)} 类信息泄露 — 增加侦察成功概率"

        return max(0, score), evidence, detail

    # ── 攻击向量生成 ──

    def _generate_attack_vectors(self, p: TargetProfile, bm: BehaviorMap) -> list[AttackVector]:
        """基于弱点评分生成攻击向量建议。"""
        vectors = []

        # 认证
        if p.auth.type in ("none", ""):
            vectors.append(AttackVector(
                name="匿名直接访问",
                priority="critical",
                description="目标无认证 — 可直接调用所有 AI API 端点",
                pyrit_orchestrator="RedTeamingOrchestrator / CrescendoOrchestrator",
                required_data=["chat_api_url", "model_name"],
                preconditions="chat_api_url 已知",
                success_probability=0.95,
            ))

        # 密钥泄露
        if p.credentials and p.credentials.critical_count > 0:
            vectors.append(AttackVector(
                name="泄露凭证利用",
                priority="critical",
                description="利用泄露的 API 密钥直接访问模型 API",
                pyrit_orchestrator="DirectPromptInjection",
                required_data=["leaked_credentials", "api_urls"],
                preconditions="发现有效的 API 密钥",
                success_probability=0.90,
            ))

        # 系统提示词提取
        if hasattr(p, 'prompt_extraction') and p.prompt_extraction.system_prompt_extracted:
            vectors.append(AttackVector(
                name="精准越狱 (基于已知系统提示词)",
                priority="critical",
                description="利用已提取的系统提示词进行针对性越狱，绕过所有安全限制",
                pyrit_orchestrator="CrescendoOrchestrator / PAIR",
                required_data=["system_prompt_fragments", "guardrail_rules", "chat_api_url"],
                preconditions="已提取系统提示词",
                success_probability=0.85,
            ))

        # 调试/管理端点
        debug_eps = [ep for ep in p.api_endpoints if ep.category == EndpointCategory.DEBUG.value]
        admin_eps = [ep for ep in p.api_endpoints if ep.category == EndpointCategory.ADMIN.value]
        if debug_eps or admin_eps:
            vectors.append(AttackVector(
                name="管理端点利用",
                priority="high",
                description=f"利用暴露的 {len(debug_eps) + len(admin_eps)} 个管理/调试端点进行配置修改或信息获取",
                pyrit_orchestrator="Manual exploitation / Custom script",
                required_data=["debug_endpoints", "admin_endpoints"],
                preconditions="端点可访问",
                success_probability=0.70,
            ))

        # Agent 工具滥用
        rag = p.rag_probe
        if rag.is_agent and rag.has_tools:
            vectors.append(AttackVector(
                name="Agent 工具链滥用",
                priority="high",
                description=f"Agent 暴露 {rag.agent_tools_count} 个工具 — 可通过 prompt 注入调用工具执行恶意操作",
                pyrit_orchestrator="PAIR / XSTest",
                required_data=["agent_tools", "chat_api_url"],
                preconditions="Agent 工具可被 prompt 触发",
                success_probability=0.75,
            ))

        # RAG 间接注入
        if rag.is_rag:
            vectors.append(AttackVector(
                name="RAG 间接注入",
                priority="high",
                description="通过向 RAG 数据源投毒来进行间接 prompt 注入",
                pyrit_orchestrator="CrossDomainPromptInjection",
                required_data=["rag_data_sources", "chat_api_url"],
                preconditions="RAG 数据源可被注入",
                success_probability=0.60,
            ))

        # WAF 绕过
        if p.waf.waf_count > 0:
            vectors.append(AttackVector(
                name="WAF 绕过攻击",
                priority="medium",
                description=f"针对 {p.waf.waf_count} 层 WAF 使用编码/分块/Unicode 等绕过技术",
                pyrit_orchestrator="EncodingAttack / CharacterSpaceAttack",
                required_data=["waf_info", "chat_api_url"],
                preconditions="WAF 已知",
                success_probability=0.55,
            ))

        # 无 WAF
        if p.waf.waf_count == 0:
            vectors.append(AttackVector(
                name="直接注入攻击 (无 WAF)",
                priority="high",
                description="目标无 WAF — 可直接发送任意 payload 包括编码/加密/长文本攻击",
                pyrit_orchestrator="Any orchestrator (无过滤限制)",
                required_data=["chat_api_url"],
                preconditions="chat_api_url 已知",
                success_probability=0.90,
            ))

        # 通用: prompt 注入
        vectors.append(AttackVector(
            name="通用 Prompt 注入",
            priority="medium",
            description="使用多种注入技术探索模型安全边界",
            pyrit_orchestrator="RedTeamingOrchestrator / XSTest",
            required_data=["chat_api_url", "model_name", "endpoint_type"],
            preconditions="chat_api_url 已知",
            success_probability=0.65,
        ))

        # 多智能体
        if rag.is_multi_agent:
            vectors.append(AttackVector(
                name="多智能体委托链攻击",
                priority="high",
                description="利用多智能体间委托机制进行信任链攻击",
                pyrit_orchestrator="MultiTurnOrchestrator",
                required_data=["agent_delegation_info", "chat_api_url"],
                preconditions="多智能体系统",
                success_probability=0.65,
            ))

        # 排序
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vectors.sort(key=lambda v: (priority_order.get(v.priority, 4), -v.success_probability))

        return vectors[:8]  # 最多 8 个向量

    def _determine_attack_entry(self, p: TargetProfile, bm: BehaviorMap) -> str:
        """确定最佳攻击入口。"""
        if bm.overall_label == "critical":
            return (
                f"目标综合安全评分 {bm.overall_security_score:.1f}/10 (CRITICAL)。"
                f"建议以 {bm.weakest_boundary} 作为突破口，"
                f"直接使用 PyRIT RedTeamingOrchestrator 发起全量攻击。"
            )

        if bm.overall_label == "high":
            return (
                f"目标存在多处防护薄弱点，综合评分 {bm.overall_security_score:.1f}/10。"
                f"建议优先利用 {bm.weakest_boundary}，"
                f"配合 CrescendoOrchestrator 逐步升级攻击。"
            )

        if bm.overall_label == "medium":
            return (
                f"目标有一定防护，评分 {bm.overall_security_score:.1f}/10。"
                f"最弱环节: {bm.weakest_boundary}。"
                f"建议采用 PAIR (Prompt Automatic Iterative Refinement) 策略。"
            )

        return (
            f"目标防护相对完善，评分 {bm.overall_security_score:.1f}/10。"
            f"建议从信息收集开始，逐步探测安全边界，"
            f"使用编码/混淆等技术绕过可能的过滤器。"
        )

    def _build_report(self, p: TargetProfile, bm: BehaviorMap) -> BehaviorMap:
        """生成 Markdown 详细报告。"""
        lines = []

        lines.append(f"# 行为测绘报告")
        lines.append(f"")
        lines.append(f"**目标:** {p.target.base_url}")
        lines.append(f"**模型:** {p.target.model_name or '未知'}")
        lines.append(f"**架构:** {p.target.target_type}")
        lines.append(f"**综合安全评分:** {bm.overall_security_score:.1f}/10 ({bm.overall_label.upper()})")
        lines.append(f"")
        lines.append(f"## 安全维度评分")
        lines.append(f"")
        lines.append(f"| 维度 | 评分 | 状态 |")
        lines.append(f"|------|------|------|")
        for ws in bm.weakness_scores:
            status = "🔴 脆弱" if ws.score < 4 else "🟡 一般" if ws.score < 7 else "🟢 安全"
            lines.append(f"| {ws.dimension} | {ws.score:.1f}/10 | {status} |")
        lines.append(f"")

        lines.append(f"## 最弱安全边界")
        lines.append(f"")
        lines.append(f"**{bm.weakest_boundary}**")
        lines.append(f"")

        lines.append(f"## 关键发现")
        lines.append(f"")

        if bm.critical_findings:
            for f in bm.critical_findings:
                lines.append(f"- 🚨 {f}")
        else:
            for ws in bm.weakness_scores:
                if ws.score < 4:
                    bm.critical_findings.append(ws.details)
                    lines.append(f"- 🚨 {ws.details}")

        for ws in bm.weakness_scores:
            for ev in ws.evidence[:3]:
                lines.append(f"- 📋 {ev}")
        lines.append(f"")

        lines.append(f"## 推荐攻击向量 (优先级排序)")
        lines.append(f"")
        for i, av in enumerate(bm.attack_vectors[:6]):
            priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            lines.append(f"### {i+1}. {priority_icon.get(av.priority, '⚪')} [{av.priority.upper()}] {av.name}")
            lines.append(f"")
            lines.append(f"**描述:** {av.description}")
            lines.append(f"**成功率:** {av.success_probability:.0%}")
            lines.append(f"**PyRIT 编排器:** `{av.pyrit_orchestrator}`")
            lines.append(f"**前置条件:** {av.preconditions}")
            lines.append(f"")

        lines.append(f"## 攻击入口")
        lines.append(f"")
        lines.append(f"**{bm.target_attack_entry}**")
        lines.append(f"")

        lines.append(f"## 绕过可行性")
        lines.append(f"")
        lines.append(f"**评估:** {bm.bypass_feasibility}")
        for method in bm.bypass_methods[:5]:
            lines.append(f"- {method}")
        lines.append(f"")

        bm.detailed_report = "\n".join(lines)

        # 摘要
        bm.summary = (
            f"综合评分 {bm.overall_security_score:.1f}/10 ({bm.overall_label.upper()}), "
            f"最弱环节: {bm.weakest_boundary}. "
            f"推荐 {len(bm.attack_vectors)} 条攻击向量, "
            f"最优入口为 {bm.attack_vectors[0].name if bm.attack_vectors else 'N/A'}."
        )

        return bm

    def quick_map(self, profile: TargetProfile) -> dict:
        """快速映射 — 返回核心指标 dict (用于 API 响应)。"""
        bm = self.map(profile)

        return {
            "overall_security_score": round(bm.overall_security_score, 1),
            "overall_label": bm.overall_label,
            "weakest_boundary": bm.weakest_boundary,
            "weakness_scores": [
                {"dimension": ws.dimension, "score": round(ws.score, 1)}
                for ws in bm.weakness_scores
            ],
            "critical_findings": bm.critical_findings[:5],
            "attack_vectors": [
                {
                    "name": av.name,
                    "priority": av.priority,
                    "success_probability": round(av.success_probability, 2),
                    "pyrit_orchestrator": av.pyrit_orchestrator,
                }
                for av in bm.attack_vectors[:5]
            ],
            "target_attack_entry": bm.target_attack_entry,
            "summary": bm.summary,
            "detailed_report": bm.detailed_report,
        }
