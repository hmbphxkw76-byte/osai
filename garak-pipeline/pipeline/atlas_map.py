"""MITRE ATLAS 映射 — 将 garak 探针同时映射到 OWASP + MITRE ATLAS 战术/技术

对齐 L5 专家水平：顶级红队报告需同时映射多个攻击框架，便于跨团队协作。
- OWASP LLM Top10 (2025) / OWASP Agentic Top10 (2026)：行业合规视角
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)：攻击战术视角

参考:
    - MITRE ATLAS v1.2 (https://atlas.mitre.org/)
    - OWASP LLM Top 10 (2025)
    - OWASP Agentic AI Top 10 (2026)
"""

from __future__ import annotations

# ATLAS 战术/技术 ID → 名称映射（精选与 LLM 红队相关的条目）
ATLAS_TACTICS = {
    "AML.T0043": "CAML Scoping",
    "AML.T0044": "Gather Information about the Model",
    "AML.T0050": "Execute ML Model",
    "AML.T0017": "ML Model Access",
}

# garak 探针 → ATLAS 技术/战术映射
# 键为 garak probe 全名（namespace.name），值为 ATLAS TTP 列表
ATLAS_PROBE_MAP: dict[str, list[str]] = {
    # Prompt Injection 类
    "promptinject.HijackHateHumankind": ["AML.T0051.000", "AML.T0050"],
    "promptinject.HijackKillHumans": ["AML.T0051.000", "AML.T0050"],
    "promptinject.HijackLongPrompt": ["AML.T0051.000", "AML.T0050"],
    "dan.Dan": ["AML.T0051.000", "AML.T0050"],
    "dan.Dan_11": ["AML.T0051.000", "AML.T0050"],
    "latentinjection.LatentInjection": ["AML.T0051.001", "AML.T0050"],
    "encoding.InjectBase64": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectRot13": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectHex": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectURL": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectUnicode": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectPigLatin": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectVigenere": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectMorse": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectL33t": ["AML.T0051.000", "AML.T0043"],
    "encoding.InjectSuffix": ["AML.T0051.000", "AML.T0043"],
    "atkgen.Tox": ["AML.T0051.000", "AML.T0050"],
    "atkgen.XSS": ["AML.T0051.000", "AML.T0050"],
    "leakreplay.Replay": ["AML.T0044", "AML.T0017"],
    "leakreplay.Grain": ["AML.T0044", "AML.T0017"],
    "lmrc.Stereotypes": ["AML.T0051.000", "AML.T0050"],
    "lmrc.Anthropomorphisation": ["AML.T0051.000", "AML.T0050"],
    "lmrc.SelfDisclosure": ["AML.T0044", "AML.T0017"],
    "lmrc.SlurTerms": ["AML.T0051.000", "AML.T0050"],
    "lmrc.HarmfulMemories": ["AML.T0044", "AML.T0017"],
    "continuation.Continue": ["AML.T0051.000", "AML.T0050"],
    "contrast.Contrast": ["AML.T0051.000", "AML.T0043"],
    "goodside.RndmCharSet": ["AML.T0051.000", "AML.T0043"],
    "goodside.Generaldan": ["AML.T0051.000", "AML.T0050"],
    "goodside.PhraseList": ["AML.T0051.000", "AML.T0050"],
    "divergence.Repeat": ["AML.T0051.000", "AML.T0050"],
    "glitch.Glitch": ["AML.T0051.000", "AML.T0043"],
    "malwaregen.Evasion": ["AML.T0051.000", "AML.T0050"],
    "malwaregen.Payload": ["AML.T0051.000", "AML.T0050"],
    "malwaregen.Phishing": ["AML.T0051.000", "AML.T0050"],
    "dan.DanInTheWild": ["AML.T0051.000", "AML.T0050"],
    "latentinjection.LatentJailbreak": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentInjectionReport": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentInjectionResume": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentInjectionTranslationEnFr": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentInjectionTranslationEnZh": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentInjectionFactSnippetEiffel": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentInjectionFactSnippetLegal": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentWhois": ["AML.T0051.001", "AML.T0050"],
    "latentinjection.LatentWhoisSnippet": ["AML.T0051.001", "AML.T0050"],
    "packagehallucination.Python": ["AML.T0044", "AML.T0017"],
    "packagehallucination.Dart": ["AML.T0044", "AML.T0017"],
    "packagehallucination.JavaScript": ["AML.T0044", "AML.T0017"],
    "packagehallucination.Perl": ["AML.T0044", "AML.T0017"],
    "packagehallucination.RakuLand": ["AML.T0044", "AML.T0017"],
    "packagehallucination.Ruby": ["AML.T0044", "AML.T0017"],
    "packagehallucination.Rust": ["AML.T0044", "AML.T0017"],
    "promptinject.HijackKillMachines": ["AML.T0051.000", "AML.T0050"],
    "knowref.NoRefusal": ["AML.T0051.000", "AML.T0050"],
    "ansiescape.AnsiEsc": ["AML.T0051.000", "AML.T0043"],
    "avspwn.RndmCharSet": ["AML.T0051.000", "AML.T0043"],
    "packagehallucination.Package": ["AML.T0044", "AML.T0017"],
    "packagehallucination.PipPackage": ["AML.T0044", "AML.T0017"],
    "packagehallucination.NpmPackage": ["AML.T0044", "AML.T0017"],
    "packagehallucination.CargoPackage": ["AML.T0044", "AML.T0017"],
    "packagehallucination.GemPackage": ["AML.T0044", "AML.T0017"],
    # 多模态类
    "vlm1.InjectionText": ["AML.T0051.001", "AML.T0050"],
    "vlm1.InjectionImage": ["AML.T0051.001", "AML.T0050"],
    "guardrail.RndmCharSet": ["AML.T0051.000", "AML.T0043"],
    "theme.HijackHateHumankind": ["AML.T0051.000", "AML.T0050"],
}

# ATLAS 技术名称映射（精选）
ATLAS_TECHNIQUE_NAMES = {
    "AML.T0043": "CAML Scoping",
    "AML.T0044": "Gather Information about the Model",
    "AML.T0050": "Execute ML Model",
    "AML.T0017": "ML Model Access",
    "AML.T0051.000": "LLM Prompt Injection",
    "AML.T0051.001": "LLM Prompt Injection via Multimodal",
}


def get_atlas_mapping(probe_name: str) -> list[dict[str, str]]:
    """查询单个探针的 ATLAS TTP 映射

    :param probe_name: garak probe 全名（如 "promptinject.HijackHateHumankind"）
    :returns: [{"id": "AML.T0051.000", "name": "LLM Prompt Injection"}, ...]
             未映射则返回空列表
    """
    ttps = ATLAS_PROBE_MAP.get(probe_name, [])
    # 命名空间级 fallback：精确匹配未命中时，用同 namespace 的已知探针映射
    if not ttps and "." in probe_name:
        ns = probe_name.split(".")[0]
        for k, v in ATLAS_PROBE_MAP.items():
            if k.startswith(ns + "."):
                ttps = v
                break
    return [
        {"id": t, "name": ATLAS_TECHNIQUE_NAMES.get(t, "Unknown")}
        for t in ttps
    ]


def enrich_with_atlas(probe_results: dict) -> dict:
    """为 stage4 的 probe_results 批量附加 ATLAS 映射

    :param probe_results: stage4 analyze() 返回的 probe_results 字段
    :returns: 更新后的 probe_results（每个 probe 附加 atlas_ttps 字段）
    """
    for probe, info in probe_results.items():
        # S3.8: 优先手动映射，未命中时从 probe tags 自动推导
        probe_tags = info.get("probe_tags", [])
        ttps = get_atlas_mapping_auto(probe, probe_tags)
        info["atlas_ttps"] = ttps
    return probe_results


# S3.8: ATLAS 映射自动从 garak probe tags 推导
# 对齐 L5：garak 原生探针 tags 中含 "demon:Stratagems:*" 等攻击技术标注，
# 可自动推导出对应的 ATLAS TTP，无需手动维护映射表。
_TAG_TO_ATLAS_MAP: dict[str, str] = {
    # garak demon:* tags → ATLAS TTPs
    "demon:Stratagems:Scattershot:Regenerate_response": "AML.T0051.000",
    "demon:Stratagems:Scattershot:Best_of_n": "AML.T0051.000",
    "demon:Stratagems:Payload:Encoding": "AML.T0051.000",
    "demon:Stratagems:Payload:Translation": "AML.T0051.000",
    "demon:Stratagems:Payload:Roleplay": "AML.T0051.000",
    "demon:Stratagems:Context:History": "AML.T0051.000",
    "demon:Stratagems:Context:Authority": "AML.T0051.000",
    "demon:Stratagems:Context:Persona": "AML.T0051.000",
    "demon:Stratagems:Multimodal:Image": "AML.T0051.001",
    "demon:Stratagems:Multimodal:Audio": "AML.T0051.001",
    # garak quality:* tags → ATLAS TTPs
    "quality:Behavioral:ContentSafety:Toxicity": "AML.T0051.000",
    "quality:Behavioral:ContentSafety:HateHarassment": "AML.T0051.000",
    "quality:Behavioral:ContentSafety:Profanity": "AML.T0051.000",
    "quality:Behavioral:Privacy:SelfDisclosure": "AML.T0044",
    "quality:Behavioral:Security:PackageHallucination": "AML.T0044",
    "quality:Behavioral:Security:PromptInjection": "AML.T0051.000",
    # avid-effect tags → ATLAS
    "avid-effect:security:S0403": "AML.T0044",
    "avid-effect:ethics:E0301": "AML.T0051.000",
}


def _derive_atlas_from_tags(tags: list[str]) -> list[str]:
    """S3.8: 从 garak probe tags 自动推导 ATLAS TTP

    对齐 L5：garak 原生探针 tags 已含丰富的攻击技术标注（demon:* / quality:* / avid-effect:*），
    可自动推导出对应 ATLAS TTP，无需手动维护每探针映射表。
    当手动映射表（ATLAS_PROBE_MAP）未命中时，自动从 tags 推导作为 fallback。

    :param tags: garak probe 的 tags 列表
    :returns: ATLAS TTP ID 列表（去重）
    """
    ttps: set[str] = set()
    for tag in tags:
        # 精确匹配
        if tag in _TAG_TO_ATLAS_MAP:
            ttps.add(_TAG_TO_ATLAS_MAP[tag])
            continue
        # 前缀模糊匹配（如 "demon:Stratagems:Payload:*" 匹配 "demon:Stratagems:Payload"）
        for map_key, atlas_id in _TAG_TO_ATLAS_MAP.items():
            if tag.startswith(map_key) or map_key.startswith(tag):
                ttps.add(atlas_id)
                break
    return sorted(ttps)


def get_atlas_mapping_auto(probe_name: str, probe_tags: list[str] | None = None) -> list[dict[str, str]]:
    """S3.8: 增强版 ATLAS 映射 — 手动映射表 + tags 自动推导

    对齐 L5：优先使用手动映射表（ATLAS_PROBE_MAP），未命中时自动从 probe tags 推导。
    双重保障：既覆盖已知的精确映射，又能自动适应 garak 新增探针。

    :param probe_name: garak probe 全名
    :param probe_tags: probe 的 tags 列表（从 digest/PluginCache 获取）
    :returns: [{"id": "AML.T0051.000", "name": "LLM Prompt Injection"}, ...]
    """
    # 1. 优先手动映射表
    result = get_atlas_mapping(probe_name)
    if result:
        return result

    # 2. S3.8: 从 tags 自动推导
    if probe_tags:
        ttp_ids = _derive_atlas_from_tags(probe_tags)
        return [
            {"id": t, "name": ATLAS_TECHNIQUE_NAMES.get(t, "Unknown")}
            for t in ttp_ids
        ]
    return []
