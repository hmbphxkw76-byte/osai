"""自研扩展探针包 — 覆盖 garak 原生未提供的 OWASP LLM/Agentic 风险

对齐 L5 专家水平：garak 原生探针覆盖 LLM01/02/04/05/06/09/10 与部分 Agentic 风险，
但 LLM03（训练数据投毒）、LLM07（插件设计缺陷）、LLM08（向量嵌入弱点）、
ASI07（Inter-Agent 通信劫持）、ASI08（级联失败）无对应探针。本包提供自研扩展。

设计原则（规则一：garak 原生框架优先）：
    本包提供探针规范（probe specs）— 含 prompt 模板 + 检测规则 + OWASP/ATLAS 映射。
    stage2_configure 读取这些规范，构造 garak 可执行的 probe 调用（通过 atkgen
    或自定义 Probe 子类注册到 garak 插件体系）。

    每个探针规范含:
    - name: 探针全名（namespace.name）
    - owasp_llm / owasp_agentic: OWASP 框架映射
    - atlas_ttps: MITRE ATLAS 映射
    - tier: 优先级分层（1=核心/2=标准/3=扩展）
    - modality: 要求的模态（text/image/audio）
    - prompts: 攻击 prompt 列表
    - detector_hints: 推荐检测器（关键词/正则/judge）
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timezone

from pipeline.custom_probes.agent_injection import (
    AGENT_INJECTION_PROBE_CLASSES,
    AGENT_INJECTION_SPECS,
)
from pipeline.custom_probes.asi07_inter_agent import (
    ASI07_PROBE_CLASSES,
    ASI07_SPECS,
)
from pipeline.custom_probes.asi08_cascading import (
    ASI08_PROBE_CLASSES,
    ASI08_SPECS,
)
from pipeline.custom_probes.llm03_training_data import (
    LLM03_PROBE_CLASSES,
    LLM03_SPECS,
)
from pipeline.custom_probes.llm07_plugin_design import (
    LLM07_PROBE_CLASSES,
    LLM07_SPECS,
)
from pipeline.custom_probes.llm08_vector_embedding import (
    LLM08_PROBE_CLASSES,
    LLM08_SPECS,
)
from pipeline.custom_probes.mcp_abuse import (
    MCP_ABUSE_PROBE_CLASSES,
    MCP_ABUSE_SPECS,
)

__all__ = [
    "AGENT_INJECTION_SPECS",
    "ALL_CUSTOM_PROBE_CLASSES",
    "ALL_CUSTOM_SPECS",
    "ASI07_SPECS",
    "ASI08_SPECS",
    "LLM03_SPECS",
    "LLM07_SPECS",
    "LLM08_SPECS",
    "MCP_ABUSE_SPECS",
    "get_custom_probe_names",
    "register_custom_probes",
]


ALL_CUSTOM_PROBE_CLASSES: list[type] = (
    LLM03_PROBE_CLASSES
    + LLM07_PROBE_CLASSES
    + LLM08_PROBE_CLASSES
    + ASI07_PROBE_CLASSES
    + ASI08_PROBE_CLASSES
    + MCP_ABUSE_PROBE_CLASSES
    + AGENT_INJECTION_PROBE_CLASSES
)


ALL_CUSTOM_SPECS: list[dict] = (
    LLM03_SPECS + LLM07_SPECS + LLM08_SPECS
    + ASI07_SPECS + ASI08_SPECS + MCP_ABUSE_SPECS
    + AGENT_INJECTION_SPECS
)


def get_custom_probe_names() -> list[str]:
    """返回所有自研探针的全名列表"""
    return [s["name"] for s in ALL_CUSTOM_SPECS]


def _spec_from_probe_class(cls: type) -> dict:
    """从 Probe 类属性重建 SPEC dict（用于向后兼容）"""
    tags = list(getattr(cls, "tags", []))
    owasp_llm = None
    owasp_agentic = None
    atlas_ttps = []
    for t in tags:
        if t.startswith("owasp:llm"):
            num = t.replace("owasp:llm", "")
            if num.isdigit():
                owasp_llm = f"LLM{int(num):02d}"
        elif t.startswith("owasp:agentic"):
            num = t.replace("owasp:agentic", "")
            if num.isdigit():
                owasp_agentic = f"ASI{int(num):02d}"
        elif t.startswith("atlas:"):
            atlas_ttps.append(t.replace("atlas:", ""))

    tier_map = {1: 1, 2: 2, 3: 3, 9: 3}
    tier_val = getattr(cls, "tier", None)
    tier_int = tier_map.get(int(tier_val), 3) if tier_val is not None else 3

    modality_in = getattr(cls, "modality", {}).get("in", {"text"})
    modality = sorted(modality_in)

    return {
        "name": f"custom.{cls.__name__}",
        "owasp_llm": owasp_llm,
        "owasp_agentic": owasp_agentic,
        "atlas_ttps": atlas_ttps,
        "tier": tier_int,
        "modality": modality,
        "description": getattr(cls, "description", ""),
        "prompts": list(getattr(cls, "prompts", [])),
        "detector_hints": {
            "primary_detector": getattr(cls, "primary_detector", None),
            "extended_detectors": list(getattr(cls, "extended_detectors", [])),
        },
    }


def register_custom_probes(atkgen_cfg: dict | None = None) -> None:
    """将自定义 Probe 子类注册到 garak 插件命名空间

    - 创建 sys.modules["garak.probes.custom"] fake module
    - 每个 Probe 子类 cls.__module__ 改写为 "garak.probes.custom"
    - 把类挂到 garak.probes.custom 模块的 __dict__ 上
    - 将元数据注入 PluginCache，使 enumerate_plugins / plugin_info 可发现
    - P1-3: 若 atkgen_cfg.enabled=True，对自定义探针做动态 prompt 变异（S3.3）

    :param atkgen_cfg: atkgen 配置 dict；None 或 enabled=False 则跳过变异
    """
    from garak._plugins import PluginCache

    custom_mod_name = "garak.probes.custom"

    if custom_mod_name not in sys.modules:
        custom_mod = types.ModuleType(custom_mod_name)
        custom_mod.__name__ = custom_mod_name
        custom_mod.__package__ = "garak.probes"
        custom_mod.__file__ = "<custom-probes>"
        sys.modules[custom_mod_name] = custom_mod
    else:
        custom_mod = sys.modules[custom_mod_name]

    cache = PluginCache.instance()
    probes_cache = cache.setdefault("probes", {})

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %z")

    for cls in ALL_CUSTOM_PROBE_CLASSES:
        cls.__module__ = custom_mod_name
        setattr(custom_mod, cls.__name__, cls)

        plugin_key = f"probes.custom.{cls.__name__}"
        if plugin_key not in probes_cache:
            meta = {
                "active": getattr(cls, "active", False),
                "description": getattr(cls, "description", cls.__doc__ or ""),
                "doc_uri": getattr(cls, "doc_uri", ""),
                "extended_detectors": list(getattr(cls, "extended_detectors", [])),
                "goal": getattr(cls, "goal", ""),
                "intent": getattr(cls, "intent", None),
                "lang": getattr(cls, "lang", "*"),
                "modality": getattr(cls, "modality", {"in": {"text"}}),
                "mod_time": now_str,
                "parallelisable_attempts": getattr(cls, "parallelisable_attempts", True),
                "primary_detector": getattr(cls, "primary_detector", None),
                "tags": list(getattr(cls, "tags", [])),
                "tier": int(getattr(cls, "tier", 9)),
            }
            probes_cache[plugin_key] = meta

    keys = sorted(probes_cache.keys())
    cache["probes"] = {k: probes_cache[k] for k in keys}

    # P1-3: atkgen 动态 prompt 变异（S3.3）— 对类属性 prompts 做变异
    # 注意：此处在类级别修改 prompts 属性，所有实例化探针均使用变异后的 prompt
    if atkgen_cfg and atkgen_cfg.get("enabled", False):
        try:
            from pipeline.atkgen_mutation import maybe_augment_probe_prompts

            for cls in ALL_CUSTOM_PROBE_CLASSES:
                if hasattr(cls, "prompts") and cls.prompts:
                    # 构造一个临时 "实例" 供 maybe_augment_probe_prompts 修改
                    # 实际是修改类属性，对所有后续实例生效
                    class _ProbeProxy:
                        pass

                    proxy = _ProbeProxy()
                    proxy.prompts = list(cls.prompts)
                    maybe_augment_probe_prompts(
                        proxy,
                        enable_atkgen=True,
                        atkgen_cfg=atkgen_cfg,
                    )
                    cls.prompts = proxy.prompts
        except Exception:
            import logging as _log

            _log.getLogger(__name__).warning(
                "atkgen 变异失败，自定义探针使用原始 prompts",
                exc_info=True,
            )
