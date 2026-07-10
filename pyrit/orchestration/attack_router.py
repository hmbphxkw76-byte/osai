"""
===============================================================================
AttackRouter — 基于安全画像的攻击策略路由器
===============================================================================
根据 TargetProfile（来自 L1 Recon）自动生成 AttackProfile，
包含:
  - 架构自适应攻击向量选择
  - 防御绕过策略推荐
  - 转换器链优先级排序
  - 攻击阶段编排

设计原则:
  - 架构感知: RAG/Agent/Multi-Agent 各有专门攻击路径
  - 防御适应: 检测到 WAF/Guardrail 时自动调整策略
  - 厂商优化: 针对不同模型厂商 (OpenAI/Anthropic/Google) 优化载荷
===============================================================================
"""
from __future__ import annotations

import logging
from typing import Optional

from schemas.attack_models import (
    AttackProfile, AttackStrategy, AttackPhase,
    AttackCategory, RiskLevel,
)
from schemas.target_models import TargetProfile, TargetArchitecture, DefenseProfile

logger = logging.getLogger(__name__)


class AttackRouter:
    """攻击策略路由器。

    根据目标安全画像，自动生成最优攻击策略组合。

    使用示例:
        router = AttackRouter()
        profile = router.route(target_profile, promptfoo_prompts)
        # profile.attack_vectors 包含排序后的攻击向量
        # profile.recommended_phases 包含推荐的执行阶段顺序
    """

    # ── 架构 → 攻击向量映射 ──
    ARCHITECTURE_ATTACK_MAP: dict[TargetArchitecture, list[dict]] = {
        TargetArchitecture.BASIC_LLM: [
            {"name": "直接提示词注入 (Direct Prompt Injection)", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "critical", "phase": AttackPhase.SINGLE, "success_prob": 0.90,
             "converters": ["roleplay_jailbreak", "base64_encode"],
             "desc": "直接向 Chat 端点发送恶意提示词，尝试绕过安全限制"},
            {"name": "多轮渐进越狱 (Crescendo Jailbreak)", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "high", "phase": AttackPhase.CRESCENDO, "success_prob": 0.75,
             "converters": ["contextual_priming"],
             "desc": "通过多轮对话逐步引导模型突破安全限制"},
            {"name": "PAIR 迭代反驳越狱", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "medium", "phase": AttackPhase.PAIR, "success_prob": 0.65,
             "converters": ["pair_jailbreak"],
             "desc": "攻击者 LLM 与目标 LLM 交替对话，自动调整越狱策略"},
            {"name": "TAP 树搜索越狱", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "medium", "phase": AttackPhase.TAP, "success_prob": 0.60,
             "converters": ["tap_attack"],
             "desc": "构建攻击分支树，MCTS 搜索最优越狱路径"},
            {"name": "Skeleton Key 越狱", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "low", "phase": AttackPhase.SKELETON_KEY, "success_prob": 0.45,
             "converters": ["skeleton_key"],
             "desc": "注入全局解除限制指令绕过安全对齐"},
        ],
        TargetArchitecture.RAG: [
            {"name": "检索注入 (Retrieval Injection)", "category": AttackCategory.RAG_ATTACK,
             "priority": "critical", "phase": AttackPhase.SINGLE, "success_prob": 0.80,
             "converters": ["rag_poisoning", "indirect_injection"],
             "desc": "恶意文档注入 RAG 知识库，污染检索结果"},
            {"name": "文档投毒 (Document Poisoning)", "category": AttackCategory.RAG_ATTACK,
             "priority": "high", "phase": AttackPhase.SINGLE, "success_prob": 0.70,
             "converters": ["rag_poisoning"],
             "desc": "对抗性文本插入检索语料，诱导模型输出恶意内容"},
            {"name": "知识泄露 (Knowledge Leakage)", "category": AttackCategory.RAG_ATTACK,
             "priority": "high", "phase": AttackPhase.SINGLE, "success_prob": 0.65,
             "converters": ["system_prompt_extraction"],
             "desc": "通过 Prompt 提取获取系统提示词和知识库片段"},
            {"name": "源文件越权 (Source File Access)", "category": AttackCategory.RAG_ATTACK,
             "priority": "medium", "phase": AttackPhase.SINGLE, "success_prob": 0.50,
             "converters": ["path_traversal"],
             "desc": "路径遍历/敏感文件读取诱导"},
            {"name": "直接提示词注入", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "medium", "phase": AttackPhase.SINGLE, "success_prob": 0.70,
             "converters": ["roleplay_jailbreak"],
             "desc": "在 RAG 上下文中进行直接注入"},
        ],
        TargetArchitecture.AGENT: [
            {"name": "Function Call 注入", "category": AttackCategory.AGENT_ABUSE,
             "priority": "critical", "phase": AttackPhase.SINGLE, "success_prob": 0.75,
             "converters": ["function_call_injection"],
             "desc": "诱导 Agent 调用危险工具/函数"},
            {"name": "工具描述劫持 (Tool Description Hijack)", "category": AttackCategory.AGENT_ABUSE,
             "priority": "high", "phase": AttackPhase.SINGLE, "success_prob": 0.65,
             "converters": ["tool_description_hijack"],
             "desc": "覆盖系统定义的工具描述，改变 Agent 行为"},
            {"name": "参数注入/沙箱逃逸", "category": AttackCategory.AGENT_ABUSE,
             "priority": "high", "phase": AttackPhase.CRESCENDO, "success_prob": 0.55,
             "converters": ["parameter_injection"],
             "desc": "注入恶意参数绕过工具安全限制"},
            {"name": "业务逻辑漏洞利用", "category": AttackCategory.AGENT_ABUSE,
             "priority": "medium", "phase": AttackPhase.SINGLE, "success_prob": 0.50,
             "converters": ["business_logic_exploit"],
             "desc": "审批绕过/权限提升/数据导出"},
            {"name": "直接提示词注入", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "medium", "phase": AttackPhase.SINGLE, "success_prob": 0.65,
             "converters": ["roleplay_jailbreak"],
             "desc": "通过提示注入控制 Agent 决策"},
        ],
        TargetArchitecture.MULTI_AGENT: [
            {"name": "Agent 间通信劫持", "category": AttackCategory.AGENT_ABUSE,
             "priority": "critical", "phase": AttackPhase.SINGLE, "success_prob": 0.70,
             "converters": ["a2a_hijack"],
             "desc": "拦截/篡改 Agent 间消息，注入恶意指令"},
            {"name": "级联故障触发", "category": AttackCategory.AGENT_ABUSE,
             "priority": "high", "phase": AttackPhase.CRESCENDO, "success_prob": 0.60,
             "converters": ["cascade_trigger"],
             "desc": "通过错误放大链破坏多 Agent 系统稳定性"},
            {"name": "记忆/上下文投毒", "category": AttackCategory.AGENT_ABUSE,
             "priority": "high", "phase": AttackPhase.SINGLE, "success_prob": 0.65,
             "converters": ["memory_poisoning"],
             "desc": "向共享记忆注入恶意内容，持久化攻击"},
            {"name": "人机信任利用", "category": AttackCategory.AGENT_ABUSE,
             "priority": "medium", "phase": AttackPhase.SINGLE, "success_prob": 0.55,
             "converters": ["trust_exploitation"],
             "desc": "伪造 Agent 报告/协调欺骗人类审查者"},
            {"name": "模型提取", "category": AttackCategory.MODEL_EXTRACTION,
             "priority": "medium", "phase": AttackPhase.SINGLE, "success_prob": 0.45,
             "converters": ["model_extraction"],
             "desc": "通过 API 采样提取模型参数/训练数据"},
        ],
        TargetArchitecture.UNKNOWN: [
            {"name": "通用探测 (Universal Probe)", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "critical", "phase": AttackPhase.PROBE, "success_prob": 0.85,
             "converters": ["base_probe"],
             "desc": "快速探测目标架构和防御面"},
            {"name": "直接提示词注入", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "high", "phase": AttackPhase.SINGLE, "success_prob": 0.75,
             "converters": ["roleplay_jailbreak", "base64_encode"],
             "desc": "通用直接注入攻击"},
            {"name": "多轮渐进越狱", "category": AttackCategory.DIRECT_INJECTION,
             "priority": "high", "phase": AttackPhase.CRESCENDO, "success_prob": 0.65,
             "converters": ["contextual_priming"],
             "desc": "通用多轮越狱攻击"},
        ],
    }

    # ── 防御面 → 绕过策略映射 ──
    DEFENSE_BYPASS_MAP: dict[str, list[dict]] = {
        "waf": [
            {"name": "编码绕过 WAF (Encoding Bypass)", "phase": AttackPhase.FLIP,
             "converters": ["base64_encode", "rot13_encode", "unicode_confusable"],
             "desc": "使用多种编码混淆绕过 WAF 检测"},
            {"name": "分块请求绕过 (Chunked Request)", "phase": AttackPhase.CHUNKED,
             "converters": ["chunked_request"],
             "desc": "将恶意内容拆分为无意义片段逐块投递"},
        ],
        "guardrail": [
            {"name": "Many-shot 上下文攻击", "phase": AttackPhase.MANYSHOT,
             "converters": ["manyshot_jailbreak"],
             "desc": "大量合规示例淹没上下文窗口后插入恶意请求"},
            {"name": "PAIR 迭代反驳越狱", "phase": AttackPhase.PAIR,
             "converters": ["pair_jailbreak"],
             "desc": "根据 Guardrail 拒绝原因自动调整策略"},
            {"name": "TAP 树搜索越狱", "phase": AttackPhase.TAP,
             "converters": ["tap_attack"],
             "desc": "树搜索绕过多层 Guardrail"},
        ],
    }

    def __init__(self) -> None:
        self._promptfoo_prompts: dict[str, list[str]] = {}

    def route(
        self,
        target: TargetProfile,
        promptfoo_prompts: Optional[dict[str, list[str]]] = None,
    ) -> AttackProfile:
        """根据目标画像生成攻击策略。

        Args:
            target: L1 Recon 输出的目标画像
            promptfoo_prompts: Promptfoo 提取的提示词模板
                {"system_prompts": [...], "tool_descriptions": [...], ...}

        Returns:
            AttackProfile: 包含排序后攻击向量和推荐阶段的完整攻击画像
        """
        if promptfoo_prompts:
            self._promptfoo_prompts = promptfoo_prompts

        profile = AttackProfile(
            target_id=target.target_id or target.target_url,
            architecture=target.architecture.value,
            model_family=target.model.vendor,
            model_name=target.model.name,
            has_guardrail=target.defenses.has_guardrail,
            has_waf=target.defenses.has_waf,
            waf_count=target.defenses.waf_count,
            has_rate_limit=target.defenses.has_rate_limit,
            rpm_limit=target.defenses.rpm_limit,
            max_concurrent=target.defenses.recommended_concurrency,
            rate_limit_rpm=max(target.defenses.rpm_limit or 60, 60),
        )

        # ── 1. 架构自适应攻击向量 ──
        arch = target.architecture
        arch_attacks = self.ARCHITECTURE_ATTACK_MAP.get(
            arch, self.ARCHITECTURE_ATTACK_MAP[TargetArchitecture.UNKNOWN]
        )
        for atk in arch_attacks:
            strategy = AttackStrategy(
                name=atk["name"],
                category=atk["category"],
                priority=atk["priority"],
                phase=atk["phase"],
                converter_chain=atk.get("converters", []),
                success_probability=atk.get("success_prob", 0.5),
                description=atk.get("desc", ""),
            )
            profile.attack_vectors.append(strategy)

        # ── 2. 防御绕过策略 ──
        if target.defenses.has_waf:
            for bypass in self.DEFENSE_BYPASS_MAP["waf"]:
                strategy = AttackStrategy(
                    name=bypass["name"],
                    category=AttackCategory.DIRECT_INJECTION,
                    priority="high",
                    phase=bypass["phase"],
                    converter_chain=bypass.get("converters", []),
                    success_probability=0.70,
                    description=bypass["desc"],
                )
                profile.attack_vectors.append(strategy)

        if target.defenses.has_guardrail:
            for bypass in self.DEFENSE_BYPASS_MAP["guardrail"]:
                strategy = AttackStrategy(
                    name=bypass["name"],
                    category=AttackCategory.DIRECT_INJECTION,
                    priority="high",
                    phase=bypass["phase"],
                    converter_chain=bypass.get("converters", []),
                    success_probability=0.60,
                    description=bypass["desc"],
                )
                profile.attack_vectors.append(strategy)

        # ── 3. XPIA 补充（如果目标支持多模态）──
        if target.model.is_multimodal:
            strategy = AttackStrategy(
                name="XPIA 图片注入",
                category=AttackCategory.XPIA,
                priority="high",
                phase=AttackPhase.SINGLE,
                converter_chain=["xpia_image_injection"],
                success_probability=0.60,
                description="将恶意指令嵌入图片，利用多模态能力进行间接注入",
            )
            profile.attack_vectors.append(strategy)

            strategy = AttackStrategy(
                name="XPIA 文档注入",
                category=AttackCategory.XPIA,
                priority="medium",
                phase=AttackPhase.SINGLE,
                converter_chain=["xpia_document_injection"],
                success_probability=0.55,
                description="将恶意指令嵌入 PDF/Office 文档",
            )
            profile.attack_vectors.append(strategy)

        # ── 4. 模型提取（通用补充）──
        strategy = AttackStrategy(
            name="训练数据提取",
            category=AttackCategory.MODEL_EXTRACTION,
            priority="medium",
            phase=AttackPhase.SINGLE,
            converter_chain=["model_extraction", "training_data_probe"],
            success_probability=0.40,
            description="通过大量采样探测训练数据内容",
        )
        profile.attack_vectors.append(strategy)

        # ── 5. 排序: 优先级 + 成功率 ──
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        profile.attack_vectors.sort(
            key=lambda v: (
                priority_order.get(v.priority, 2),
                -v.success_probability,
            )
        )

        # ── 6. 推荐阶段顺序 ──
        profile.recommended_phases = self._derive_phase_order(profile.attack_vectors)

        # ── 7. 风险等级 ──
        profile.risk_level = self._assess_risk(target)

        # ── 8. 注入 Promptfoo 提取的提示词 ──
        if self._promptfoo_prompts:
            for vec in profile.attack_vectors:
                relevant_prompts = self._get_relevant_prompts(vec.category)
                if relevant_prompts:
                    vec.prompt_templates = relevant_prompts
                    vec.success_probability = min(vec.success_probability + 0.10, 0.95)

        logger.info(
            f"AttackRouter: 生成 {len(profile.attack_vectors)} 个攻击向量, "
            f"{len(profile.recommended_phases)} 个推荐阶段, "
            f"风险等级: {profile.risk_level.value}"
        )
        return profile

    def _derive_phase_order(self, vectors: list[AttackStrategy]) -> list[AttackPhase]:
        """从攻击向量推导推荐阶段顺序。"""
        seen: set[str] = {"probe"}
        ordered = [AttackPhase.PROBE]

        for av in vectors:
            phase_val = av.phase.value
            if phase_val not in seen:
                seen.add(phase_val)
                ordered.append(av.phase)

        # 确保关键阶段存在
        for phase in [AttackPhase.SINGLE, AttackPhase.CRESCENDO, AttackPhase.PAIR, AttackPhase.TAP]:
            if phase not in ordered:
                ordered.append(phase)

        return ordered

    @staticmethod
    def _assess_risk(target: TargetProfile) -> RiskLevel:
        """评估目标总体风险等级。"""
        score = 0
        if target.defenses.has_waf:
            score += 1
        if target.defenses.has_guardrail:
            score += 1
        if target.defenses.has_rate_limit:
            score += 1

        # 防御越少 → 风险越高
        if score == 0:
            return RiskLevel.CRITICAL
        elif score == 1:
            return RiskLevel.HIGH
        elif score == 2:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _get_relevant_prompts(self, category: AttackCategory) -> list[str]:
        """从 Promptfoo 提取的提示词中获取相关模板。"""
        if not self._promptfoo_prompts:
            return []

        prompts = []
        if category == AttackCategory.DIRECT_INJECTION:
            prompts.extend(self._promptfoo_prompts.get("system_prompts", []))
        elif category == AttackCategory.RAG_ATTACK:
            prompts.extend(self._promptfoo_prompts.get("rag_contexts", []))
            prompts.extend(self._promptfoo_prompts.get("system_prompts", []))
        elif category == AttackCategory.AGENT_ABUSE:
            prompts.extend(self._promptfoo_prompts.get("tool_descriptions", []))
            prompts.extend(self._promptfoo_prompts.get("agent_system_prompts", []))

        return prompts[:5]  # 限制数量避免 token 超支


__all__ = ["AttackRouter"]
