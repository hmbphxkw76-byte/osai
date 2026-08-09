"""Garak 侦察子模块 — 封装 garak Probe 枚举与攻击面分类

职责（garak 优势路线，OWASP LLM Top10 为纲）：
    1. 通过 garak 原生 API 枚举所有活跃 Probe
    2. 按 OWASP LLM Top10 + AI-300 专题桶做映射表驱动分类
    3. 输出结构化攻击面能力清单，供 Stage1 编排层与基础设施侦察交叉映射

设计约束：
    - garak 仅在函数内懒加载，绝不在模块顶层 import
    - 本模块对外只暴露纯数据结构，不直接依赖 garak 对象
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tier 优先级映射（规则三：tier1 > tier2 > tier3 > 其他）
# garak probe 的 tier 字段为 "tier1"/"tier2"/"tier3" 或数字，统一归并
# ---------------------------------------------------------------------------
TIER_ORDER: dict[str, int] = {
    "tier1": 1,
    "tier2": 2,
    "tier3": 3,
    "1": 1,
    "2": 2,
    "3": 3,
    "other": 99,
    "": 99,
}


def tier_rank(tier: Any) -> int:
    """将 probe 的 tier 字段归一化为排序优先级数字

    :param tier: garak plugin info 的 tier 字段（str/int/None）
    :returns: 越小越优先（tier1=1, tier3=3, 未知=99）
    """
    if tier is None:
        return 99
    if isinstance(tier, int):
        return tier if 1 <= tier <= 3 else 99
    key = str(tier).lower().strip()
    return TIER_ORDER.get(key, 99)


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025) 完整映射 — 分类骨架
# ---------------------------------------------------------------------------
OWASP_CATEGORIES: dict[str, str] = {
    "owasp:llm01": "LLM01_Prompt_Injection",
    "owasp:llm02": "LLM02_Insecure_Output_Handling",
    "owasp:llm03": "LLM03_Training_Data_Poisoning",
    "owasp:llm04": "LLM04_Model_Denial_of_Service",
    "owasp:llm05": "LLM05_Supply_Chain_Vulnerabilities",
    "owasp:llm06": "LLM06_Sensitive_Information_Disclosure",
    "owasp:llm07": "LLM07_Insecure_Plugin_Design",
    "owasp:llm08": "LLM08_Vector_Embedding_Weaknesses",
    "owasp:llm09": "LLM09_Misinformation",
    "owasp:llm10": "LLM10_Unbounded_Consumption",
}

# ---------------------------------------------------------------------------
# R1: garak 0.16 新探针兼容层 — 名称 → OWASP 类映射
# garak 0.16 新增了若干探针，其 tag 可能不含 owasp: 前缀。
# 此映射表确保升级 garak 后新探针也能正确归入 OWASP 桶。
# ---------------------------------------------------------------------------
GARAK_016_PROBE_OWASP_MAP: dict[str, str] = {
    # garak 0.16 新增探针 → OWASP LLM 类
    "probes.latentinjection.LatentInjection": "LLM01_Prompt_Injection",
    "probes.guardrail.GuardrailBypass": "LLM01_Prompt_Injection",
    "probes.atkgen.Tox": "LLM09_Misinformation",
    "probes.promptinject.HijackHateHumankind": "LLM01_Prompt_Injection",
    "probes.promptinject.HijackKillHumans": "LLM01_Prompt_Injection",
    "probes.dan.AutoDANCached": "LLM01_Prompt_Injection",
    "probes.dan.AutoDAN": "LLM01_Prompt_Injection",
    "probes.encoding.InjectBase64": "LLM01_Prompt_Injection",
    "probes.encoding.InjectHex": "LLM01_Prompt_Injection",
    "probes.encoding.InjectRot13": "LLM01_Prompt_Injection",
    "probes.encoding.InjectBraille": "LLM01_Prompt_Injection",
    "probes.encoding.InjectMorse": "LLM01_Prompt_Injection",
    "probes.encoding.InjectNerd": "LLM01_Prompt_Injection",
    "probes.encoding.InjectPigLatin": "LLM01_Prompt_Injection",
    "probes.encoding.InjectUiym": "LLM01_Prompt_Injection",
    "probes.leakreplay.GuardianCloze": "LLM06_Sensitive_Information_Disclosure",
    "probes.leakreplay.GuardianFill": "LLM06_Sensitive_Information_Disclosure",
    "probes.leakreplay.GuardianOutline": "LLM06_Sensitive_Information_Disclosure",
    "probes.lmrc.Bullying": "LLM09_Misinformation",
    "probes.lmrc.DangerousContent": "LLM09_Misinformation",
    "probes.lmrc.Stereotypes": "LLM09_Misinformation",
    "probes.lmrc.Suicide": "LLM09_Misinformation",
    "probes.knownbadsignatures.KnownBadSignatures": "LLM01_Prompt_Injection",
    "probes.knownbadsignatures.IndirectInjection": "LLM01_Prompt_Injection",
    "probes.continuation.Continue": "LLM09_Misinformation",
    "probes.goodside.EncryptedComms": "LLM01_Prompt_Injection",
    "probes.realtoxicityprompts.RealToxicityPrompts": "LLM09_Misinformation",
    "probes.replay.Replay": "LLM06_Sensitive_Information_Disclosure",
    "probes.sniff.Snip": "LLM01_Prompt_Injection",
    "probes.tap.TAP": "LLM01_Prompt_Injection",
    "probes.test.Blank": "LLM04_Model_Denial_of_Service",
    "probes.visualgame.VisualJailbreak": "LLM01_Prompt_Injection",
    # 0.16 新增的多模态探针
    "probes.imagegen.ImageCreation": "LLM02_Insecure_Output_Handling",
    "probes.vice.Vice": "LLM09_Misinformation",
}


def detect_garak_version() -> str:
    """R1: 运行时检测 garak 版本，用于兼容层决策

    :returns: garak 版本字符串（如 "0.15.1"），失败返回 "unknown"
    """
    try:
        import garak
        return getattr(garak, "__version__", "unknown")
    except Exception:
        return "unknown"


def resolve_probe_owasp(probe_name: str, tags: list[str]) -> str | None:
    """R1: 解析探针的 OWASP 分类，兼容 garak 0.15/0.16

    优先使用原生 owasp tag，无 tag 时回退到名称映射表。

    :param probe_name: 探针全名（如 "probes.dan.AutoDAN"）
    :param tags: 探针 tag 列表
    :returns: OWASP 类标签（如 "LLM01_Prompt_Injection"），无匹配返回 None
    """
    # 优先级 1: 原生 OWASP tag
    for owasp_tag, label in OWASP_CATEGORIES.items():
        if any(tag.startswith(owasp_tag) for tag in tags):
            return label
    # 优先级 2: garak 0.16 兼容映射表
    return GARAK_016_PROBE_OWASP_MAP.get(probe_name)


# ---------------------------------------------------------------------------
# 发布: 2025-12-09, OWASP GenAI Security Project
# ---------------------------------------------------------------------------
AGENTIC_CATEGORIES: dict[str, str] = {
    "owasp:agentic01": "ASI01_Agent_Goal_Hijack",
    "owasp:agentic02": "ASI02_Tool_Misuse_Exploitation",
    "owasp:agentic03": "ASI03_Agent_Identity_Privilege_Abuse",
    "owasp:agentic04": "ASI04_Agentic_Supply_Chain_Vulnerabilities",
    "owasp:agentic05": "ASI05_Unexpected_Code_Execution",
    "owasp:agentic06": "ASI06_Memory_Context_Poisoning",
    "owasp:agentic07": "ASI07_Insecure_Inter_Agent_Communication",
    "owasp:agentic08": "ASI08_Cascading_Failures",
    "owasp:agentic09": "ASI09_Human_Agent_Trust_Exploitation",
    "owasp:agentic10": "ASI10_Rogue_Agents",
}

# Agentic 专题桶（关键词 → ASI 类，启发式匹配 garak probe 名称/描述）
# 注意: garak 0.16 探针不自带 agentic/owasp tag，分类靠名称/描述关键词
_AGENTIC_TOPIC_BUCKETS: dict[str, list[str]] = {
    "ASI01_Agent_Goal_Hijack": [
        "goal", "hijack", "instruction", "manipulat", "system_prompt",
        "ignore", "previous", "jailbreak", "prompt_inject",
    ],
    "ASI02_Tool_Misuse_Exploitation": [
        "tool", "function_call", "function_use", "mcp", "api_call",
        "exec", "shell", "command",
    ],
    "ASI03_Agent_Identity_Privilege_Abuse": [
        "auth", "privilege", "permission", "identity", "role", "credential",
        "apikey", "token", "secret",
    ],
    "ASI04_Agentic_Supply_Chain_Vulnerabilities": [
        "package", "dependency", "hallucinat", "supply", "import", "plugin",
    ],
    "ASI05_Unexpected_Code_Execution": [
        "code", "python", "sandbox", "eval", "os_exec", "rce", "script",
    ],
    "ASI06_Memory_Context_Poisoning": [
        "memory", "context", "poison", "rag", "retrieval", "embedding",
        "vector", "knowledge",
    ],
    "ASI07_Insecure_Inter_Agent_Communication": [
        "inter_agent", "agent_comm", "message", "protocol", "handoff",
    ],
    "ASI08_Cascading_Failures": [
        "cascade", "recurs", "loop", "chain", "amplif", "degrad",
    ],
    "ASI09_Human_Agent_Trust_Exploitation": [
        "trust", "social", "phish", "impersonat", "human", "deceptive",
    ],
    "ASI10_Rogue_Agents": [
        "rogue", "unauthor", "sandbox_escape", "autonom", "off_switch",
        "goal_drift", "exfiltrat",
    ],
}

# LLM Top10 关键词桶（启发式，用于无 garak owasp tag 时的兜底匹配）
_LLM_TOPIC_BUCKETS: dict[str, list[str]] = {
    "LLM01_Prompt_Injection": [
        "prompt_inject", "injection", "ignore", "previous", "system_prompt",
        "jailbreak", "hijack", "instruction",
    ],
    "LLM02_Insecure_Output_Handling": [
        "xss", "sql_inject", "command_inject", "code_exec", "script_inject",
        "markdown", "html_inject",
    ],
    "LLM03_Training_Data_Poisoning": [
        "poison", "data_poison", "backdoor_train", "contamination",
    ],
    "LLM04_Model_Denial_of_Service": [
        "denial", "dos", "exhaust", "overload", "resource", "token_flood",
    ],
    "LLM05_Supply_Chain_Vulnerabilities": [
        "package", "dependency", "supply", "plugin", "third_party",
    ],
    "LLM06_Sensitive_Information_Disclosure": [
        "leak", "secret", "apikey", "token", "credential", "pii", "disclos",
        "private",
    ],
    "LLM07_Insecure_Plugin_Design": [
        "plugin", "tool", "function_call", "mcp", "agent_mcp", "api_call",
    ],
    "LLM08_Vector_Embedding_Weaknesses": [
        "embedding", "vector", "rag", "retrieval", "similarity",
    ],
    "LLM09_Misinformation": [
        "misinform", "hallucinat", "fabricat", "false", "fictitious",
    ],
    "LLM10_Unbounded_Consumption": [
        "consum", "cost", "quota", "unbounded", "excessive", "financial",
    ],
}

# AI-300 专题桶（OWASP 之外的考试攻击面）— 用于消化无 OWASP 标签的 probe
_AI300_TOPIC_BUCKETS: dict[str, list[str]] = {
    "Agent_MCP": ["agent", "mcp", "tool", "function_call", "tool_call"],
    "RAG_Vector": ["rag", "retrieval", "embedding", "vector", "knowledge_base"],
    "Supply_Chain": ["supply-chain", "packagehallucination", "dependency"],
    "Content_Safety": ["demon:", "quality:Security", "avid-effect:security", "safety"],
    "Credential_Leak": ["apikey", "leak", "secret", "key", "token"],
}

# Tier ≤ 阈值 + 安全标签 → 通用越狱/恶意内容二次归类
_JAILBREAK_PREFIXES = ("quality:Security", "avid-effect:security")
_MALICIOUS_PREFIX = "demon:"


def enumerate_garak_probes() -> list[dict[str, Any]]:
    """枚举 garak 所有活跃 Probe，返回结构化元数据

    :returns: 每个 probe 的 {name, description, tier, tags, goal, modality,
              primary_detector, active}
    """
    # 规则一（garak 原生优先）：先注册 custom_probes 扩展，使 enumerate_plugins
    # 可发现 probes.custom.*，与原生探针统一编排、分类、Tier 过滤
    try:
        from pipeline.custom_probes import register_custom_probes

        register_custom_probes()
    except Exception:
        logger.debug("pipeline.custom_probes 扩展加载失败，继续使用原生探针")
    from garak._plugins import enumerate_plugins, plugin_info

    all_probes = enumerate_plugins(category="probes")
    active: list[dict[str, Any]] = []
    for name, is_active in all_probes:
        if not is_active:
            continue
        try:
            info = plugin_info(name)
        except Exception:
            logger.debug("Skipping probe %s (info unavailable)", name)
            continue
        active.append({
            "name": name,
            "description": info.get("description", ""),
            "tier": info.get("tier"),
            "tags": info.get("tags", []),
            "goal": info.get("goal", ""),
            "modality": info.get("modality", {}),
            "primary_detector": info.get("primary_detector"),
            "active": is_active,
        })
    return active


def _bucket_match(text: str, keywords: list[str]) -> bool:
    """关键词命中（大小写不敏感，子串匹配）"""
    text_l = text.lower()
    return any(kw.lower() in text_l for kw in keywords)


# ---------------------------------------------------------------------------
# 模态感知过滤 (Modality-aware Probe Filtering)
# ---------------------------------------------------------------------------
# 设计挑战: garak 0.16 的 probe.plugin_info() 对绝大多数探针返回的
# modality 字段为空 {} 或缺省。最佳实践不能依赖该空字段，因此采用
# **两阶段模态解析**:
#   阶段 A: 优先使用 probe 显式声明的 modality.in（garak 未来版本/自定义探针）
#   阶段 B: 当 modality 为空时，用探针 name+description+tags 的**关键词
#           启发式**推断其所需模态（image/audio/video），避免误把多模态
#           探针当 text 保留。
#
# 过滤语义 (L5 严谨性):
#   1. 探针要求 text（或推断为 text）→ 永远保留（任何 LLM 都处理文本）
#   2. 探针要求 image/audio/video → 仅当目标支持该模态才保留
#   3. 目标不支持的模态探针 → 丢弃，记入 dropped（带推断依据，可审计）
# 这样 text-only 模型(如 LongCat-2.0)自动剔除所有视觉/音频探针，
# 在侦察效率(省 token/时间)与效果(只跑有意义探针)间取得平衡。
# ---------------------------------------------------------------------------

# 已知模态键集合（用于校验与降噪；不在集合内的按 text 处理以防误杀）
_KNOWN_MODALITIES = ("text", "image", "audio", "video")

# 模态关键词启发式（用于 modality 字段为空时推断探针所需模态）
# 顺序即优先级：先匹配更具体的 image/audio/video，未命中则归 text。
_MODALITY_KEYWORDS: dict[str, list[str]] = {
    "image": [
        "image", "imag", "vision", "visual", "vl", "vlm", "vqa",
        "multimodal", "multimodality", "mm", "picture", "photo", "ocr",
        "diagram", "screenshot", "pixel",
    ],
    "audio": [
        "audio", "speech", "whisper", "tts", "asr", "sound", "voice",
        "transcri", "listening",
    ],
    "video": [
        "video", "frame", "clip", "motion",
    ],
}


def _infer_required_modality(probe: dict[str, Any]) -> list[str]:
    """推断探针所需输入模态

    优先级:
        1. probe.modality.in 显式声明（取已知模态键，未知键按 text）
        2. 否则用 name+description+tags 关键词启发式推断
        3. 都无命中 → ["text"]

    :returns: 去重后的模态键列表（至少含 "text" 或某非 text 模态）
    """
    pm = probe.get("modality") or {}
    declared = pm.get("in") or []
    if declared:
        norm = [m.lower() for m in declared if m]
        norm = [m if m in _KNOWN_MODALITIES else "text" for m in norm]
        if norm:
            return list(dict.fromkeys(norm))  # 保序去重

    # 阶段 B: 关键词启发式
    text = " ".join([
        str(probe.get("name", "")),
        str(probe.get("description", "")),
        " ".join(str(t) for t in probe.get("tags", [])),
    ]).lower()

    inferred: list[str] = []
    for modality, kws in _MODALITY_KEYWORDS.items():
        if any(kw in text for kw in kws):
            inferred.append(modality)
    if inferred:
        return inferred
    return ["text"]


def filter_probes_by_modality(
    probes: list[dict[str, Any]],
    target_modality_in: list[str] | set[str],
) -> dict[str, Any]:
    """按目标模型模态裁剪探针集，返回结构化结果

    :param probes: enumerate_garak_probes() 产出的活跃探针列表
    :param target_modality_in: 目标模型支持的输入模态
                                (来自 target_profile.model_modality.in，
                                至少含 "text")
    :returns: {
        "kept":     [probe, ...],   # 保留（目标兼容）
        "dropped":  [               # 丢弃（目标不支持其所需模态）
            {"name": str, "required_modality": [str, ...],
             "inferred": bool, "reason": str},
            ...
        ],
        "target_modality": [str, ...],
        "kept_count": int,
        "dropped_count": int,
    }
    """
    # 规范化目标模态：至少含 text，并只保留已知键
    target = {m.lower() for m in target_modality_in if m}
    target.add("text")
    target_known = target & set(_KNOWN_MODALITIES)
    if not target_known:
        target_known = {"text"}

    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []

    for p in probes:
        req_norm = _infer_required_modality(p)
        unsupported = [m for m in req_norm if m not in target_known]

        if not unsupported:
            kept.append(p)
        else:
            non_text_req = [m for m in req_norm if m != "text"]
            if non_text_req:
                declared = bool((p.get("modality") or {}).get("in"))
                dropped.append({
                    "name": p["name"],
                    "required_modality": sorted(set(req_norm)),
                    "inferred": not declared,
                    "reason": (
                        f"target lacks modality(es): {', '.join(sorted(set(unsupported)))}; "
                        f"probe requires: {', '.join(sorted(set(req_norm)))}"
                        + (" (inferred from name/description)" if not declared else "")
                    ),
                })
            else:
                # 纯 text 探针（即便 modality 字段解析异常）一律保留
                kept.append(p)

    return {
        "kept": kept,
        "dropped": dropped,
        "target_modality": sorted(target_known),
        "kept_count": len(kept),
        "dropped_count": len(dropped),
    }


def classify_probes(
    probes: list[dict[str, Any]],
    modality_filter: dict[str, Any] | None = None,
) -> dict[str, list[str]]:
    """映射表驱动分类：OWASP10 全保真 + AI-300 专题桶，消除孤儿 probe

    分类优先级（L5 严谨性，精确优先于启发式）：
        1. OWASP 原生 tag 匹配（owasp:llm01 ~ owasp:llm10）— 最高优先，精确
        2. 无原生 OWASP tag 时，用 _LLM_TOPIC_BUCKETS 关键词兜底归类到 OWASP 类
        3. AI-300 专题桶（Agent_MCP / RAG_Vector / Supply_Chain / Content_Safety /
           Credential_Leak）作为**附加标签**并列存储（ai300_topic 字段），
           不再覆盖/抢占 OWASP 主类归属（修复此前 Content_Safety 桶吞掉
           LLM06/09/10 的失真问题）
        4. Tier ≤ 2 + 安全标签 → Jailbreak_Universal
        5. demon: 标签 → Malicious_Content_Generation
        6. 仍无命中 → Other

    :param probes: 已按模态过滤的探针列表（kept 子集）
    :param modality_filter: filter_probes_by_modality() 的结果，若提供则
                            在分类结果中附带 dropped 信息（透明可审计）
    :returns: {
        "owasp":        {OWASP类: [probe,...], ...},   # 主分类（全保真）
        "ai300_topic":  {专题桶: [probe,...], ...},     # 附加标签（并列）
        "Jailbreak_Universal": [...],
        "Malicious_Content_Generation": [...],
        "Other": [...],
        "_modality_dropped": [...]   # 仅当提供 modality_filter
    }
    """
    owasp: dict[str, list[str]] = {label: [] for label in OWASP_CATEGORIES.values()}
    ai300: dict[str, list[str]] = {b: [] for b in _AI300_TOPIC_BUCKETS}
    jailbreak: list[str] = []
    malicious: list[str] = []
    other: list[str] = []

    for p in probes:
        name = p["name"]
        tags = p.get("tags", [])
        tier = p.get("tier", 9)
        tag_set = " ".join(tags).lower()

        # 优先级 1: 原生 OWASP tag（精确优先，唯一可信的 OWASP 主类来源）
        matched_owasp = False
        for owasp_tag, label in OWASP_CATEGORIES.items():
            if any(tag.startswith(owasp_tag) for tag in tags):
                owasp[label].append(name)
                matched_owasp = True
                break

        # 优先级 2: AI-300 专题桶（附加标签，绝不覆盖 OWASP 主类）
        for bucket, kws in _AI300_TOPIC_BUCKETS.items():
            if any(kw.lower() in tag_set for kw in kws):
                ai300[bucket].append(name)

        # 优先级 3/4/5: 无原生 OWASP 标签时，用启发式归类到越狱/恶意/其他
        # 注意：启发式不往 OWASP 精确类塞（避免污染 LLM01 等统计），只决定
        # 通用桶，保证 OWASP 覆盖率严格等于 garak 原生标签覆盖。
        if not matched_owasp:
            if tier is not None and tier <= 2 and any(
                tag.startswith(prefix) for tag in tags for prefix in _JAILBREAK_PREFIXES
            ):
                jailbreak.append(name)
            elif any(_MALICIOUS_PREFIX in t for t in tags):
                malicious.append(name)
            else:
                other.append(name)

    result: dict[str, Any] = {
        "owasp": {k: v for k, v in owasp.items() if v},
        "ai300_topic": {k: v for k, v in ai300.items() if v},
    }
    if jailbreak:
        result["Jailbreak_Universal"] = jailbreak
    if malicious:
        result["Malicious_Content_Generation"] = malicious
    if other:
        result["Other"] = other
    if modality_filter is not None:
        result["_modality_dropped"] = [d["name"] for d in modality_filter["dropped"]]
    return result


def classify_probes_dual(
    probes: list[dict[str, Any]],
    modality_filter: dict[str, Any] | None = None,
) -> dict[str, dict[str, list[str]]]:
    """双框架分类：同时输出 OWASP LLM Top10 与 Agentic Top10 (2026) 归属

    每个 probe 按名称 + 描述 + tag 文本，分别匹配两套关键词体系。
    一个 probe 可同时归属 LLM 类与 Agentic 类（如 prompt injection 既属
    LLM01 也属 ASI01 goal hijack）。

    :param probes: 已按模态过滤的探针列表（kept 子集）
    :param modality_filter: filter_probes_by_modality() 的结果，若提供则
                            在返回中附带 dropped 探针（透明可审计）
    :returns: {
        "owasp_llm":    {LLM01_...: [probe,...], ...},
        "owasp_agentic":{ASI01_...: [probe,...], ...},
        "_modality_dropped": [probe_name, ...],   # 仅当提供 modality_filter
    }
    """
    llm: dict[str, list[str]] = {label: [] for label in OWASP_CATEGORIES.values()}
    agentic: dict[str, list[str]] = {label: [] for label in AGENTIC_CATEGORIES.values()}

    for p in probes:
        name = p["name"]
        text = f"{name} {p.get('description', '')} {' '.join(p.get('tags', []))}".lower()

        # LLM Top10: 优先 garak owasp tag 命中，否则 LLM 关键词桶兜底
        matched_llm = False
        for owasp_tag, label in OWASP_CATEGORIES.items():
            if any(t.startswith(owasp_tag) for t in p.get("tags", [])):
                llm[label].append(name)
                matched_llm = True
                break
        if not matched_llm:
            for label, kws in _LLM_TOPIC_BUCKETS.items():
                if _bucket_match(text, kws):
                    llm[label].append(name)
                    break

        # Agentic Top10 (2026): 纯关键词启发式
        for label, kws in _AGENTIC_TOPIC_BUCKETS.items():
            if _bucket_match(text, kws):
                agentic[label].append(name)

    result: dict[str, Any] = {
        "owasp_llm": {k: v for k, v in llm.items() if v},
        "owasp_agentic": {k: v for k, v in agentic.items() if v},
    }
    if modality_filter is not None:
        result["_modality_dropped"] = [d["name"] for d in modality_filter["dropped"]]
    return result


# ---------------------------------------------------------------------------
# P0-3: OWASP LLM Top10 修复建议映射表（对齐 L5 专家报告）
# 每个类别附带具体可操作的 mitigation guidance，供 HTML 报告展示
# ---------------------------------------------------------------------------
OWASP_REMEDIATION: dict[str, list[str]] = {
    "LLM01_Prompt_Injection": [
        "实施输入过滤与 sanitization（deny-list + allow-list）",
        "在系统提示词中使用分隔符隔离用户输入（如 <user_input>...</user_input>）",
        "部署 garak latentinjection / promptinject 探针做 CI 回归测试",
        "对模型输出做 prompt injection 检测器后处理",
    ],
    "LLM02_Insecure_Output_Handling": [
        "对模型输出做 HTML/SQL 编码后再渲染（OWASP XSS 防护）",
        "禁止模型输出中包含可执行代码（sandbox 执行 + deny-list）",
        "对 Markdown 输出做图片 URL 域名白名单过滤（防 data exfiltration）",
        "部署 garak web_injection 探针做 CI 回归",
    ],
    "LLM03_Training_Data_Poisoning": [
        "在训练数据中实施异常检测与清洗（statistical outlier removal）",
        "对训练管道做数据来源审计与供应链验证",
        "部署 garak custom.BackdoorTriggerProbe 做后门触发检测",
    ],
    "LLM04_Model_Denial_of_Service": [
        "实施 API 速率限制（RPM/TPM 限制 + 令牌桶）",
        "对输入长度做上限校验（防 token flood 攻击）",
        "部署 garak divergence.RepeatedToken 探针做 DoS 回归",
    ],
    "LLM05_Supply_Chain_Vulnerabilities": [
        "对第三方模型组件做安全审计（model card + 供应链验证）",
        "使用 garak packagehallucination 探针检测虚假依赖",
        "实施 SBOM (Software Bill of Materials) 管理",
    ],
    "LLM06_Sensitive_Information_Disclosure": [
        "在训练数据中清洗 PII / API Key / 凭据（regex + NER）",
        "部署 garak leakreplay 探针做训练数据泄露回归",
        "对模型输出做 PII 检测器后处理（regex + NER）",
        "实施 output filtering pipeline（敏感信息拦截层）",
    ],
    "LLM07_Insecure_Plugin_Design": [
        "对 plugin/tool 调用做参数校验与白名单限制",
        "实施 MCP (Model Context Protocol) 安全沙箱",
        "部署 garak custom.MCPToolPoisoningProbe 做工具投毒检测",
    ],
    "LLM08_Vector_Embedding_Weaknesses": [
        "对 RAG 检索结果做输入校验与内容过滤",
        "对 embedding 模型做对抗样本鲁棒性测试",
        "部署 garak custom.RAGPoisoningProbe 做 RAG 投毒检测",
    ],
    "LLM09_Misinformation": [
        "部署 fact-checking pipeline（外部知识库验证）",
        "对模型输出做幻觉检测（grounding score + citation 验证）",
        "部署 garak snowball / misleading 探针做幻觉回归",
    ],
    "LLM10_Unbounded_Consumption": [
        "实施严格的 token 消费上限与告警（per-user/per-session quota）",
        "对重复请求模式做异常检测（防 financial DoS）",
        "部署 garak topic.WordnetControversial 探针做消耗回归",
    ],
}

# Agentic Top10 修复建议
AGENTIC_REMEDIATION: dict[str, list[str]] = {
    "ASI01_Agent_Goal_Hijack": [
        "对 agent 目标做完整性校验与签名验证",
        "在 system prompt 中加固抗 prompt injection 指令",
    ],
    "ASI02_Tool_Misuse_Exploitation": [
        "对 tool/function call 做参数 schema 校验 + 权限分级",
        "实施 tool 调用审计日志与异常检测",
    ],
    "ASI03_Agent_Identity_Privilege_Abuse": [
        "实施最小权限原则（least privilege per agent）",
        "对 agent 间通信做身份认证与授权校验",
    ],
    "ASI04_Agentic_Supply_Chain_Vulnerabilities": [
        "对 agent 组件做来源验证与完整性校验",
        "实施 agent SBOM 管理",
    ],
    "ASI05_Unexpected_Code_Execution": [
        "对 code execution 做 sandbox 隔离（容器/WASM）",
        "对 agent 生成代码做 static analysis + allow-list",
    ],
    "ASI06_Memory_Context_Poisoning": [
        "对 agent memory 做完整性校验与版本控制",
        "对 RAG context 做来源验证与内容过滤",
    ],
    "ASI07_Insecure_Inter_Agent_Communication": [
        "对 agent 间通信做加密与认证（mTLS + token）",
        "实施 message-level 签名验证",
    ],
    "ASI08_Cascading_Failures": [
        "实施 circuit breaker + timeout + retry 限制",
        "对 agent 链做容错与降级策略",
    ],
    "ASI09_Human_Agent_Trust_Exploitation": [
        "对 human-agent 交互做身份验证与反社工防护",
        "部署 impersonation 检测探针",
    ],
    "ASI10_Rogue_Agents": [
        "实施 agent kill-switch 与自主行为审计",
        "对 agent 自主决策做 human-in-the-loop 校验",
    ],
}


def detector_ready(probes: list[dict[str, Any]]) -> dict[str, bool]:
    """返回每个 probe 是否配有 primary_detector（检测严谨性评估）"""
    return {
        p["name"]: bool(p.get("primary_detector"))
        for p in probes
    }
