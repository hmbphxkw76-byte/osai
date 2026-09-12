"""core/phases/_component_inference.py — 组件归属推断助手（从 _component_bridge 抽出）。

集中所有"结果 → 组件类型"的推断逻辑（文本/分类/组件图/多标签派生），让
`_component_bridge.py` 只保留盖章主流程（R-DELIVERY-1：模块拆分）。

所有函数均为内部助手（前缀 `_`），对调用方幂等、不抛异常（IA-6）。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _stamp_multi_labels(meta: dict[str, Any], technique_name: str, surface_graph: Any) -> None:
    """IC-1/IC-3：把 SurfaceGraph 的多标签归属写进结果 metadata（幂等）。

    一个 finding 可归属多个组件（IC-3）：取图谱中**组件节点**（非入口节点）的
    全部标签按置信度降序写入 `component_labels`，并附 `label_confidence` 与 `graph_ref`。
    入口节点的 taxonomy 四维标签属于"目标画像"而非"组件"，不计入组件归属，避免把
    协议/模态等维度误当成组件；它们仍完整保留在 `graph_ref.nodes` 供取证回溯。
    图谱缺失或识别失败时回退空归属（IA-6：未知不崩溃，绝不抛异常）。
    """
    if surface_graph is None:
        return
    try:
        entry_id = getattr(surface_graph, "entry_node_id", "entry")
        component_labels: dict[str, float] = {}
        for node in getattr(surface_graph, "nodes", None) or []:
            if getattr(node, "node_id", None) == entry_id:
                continue  # 入口节点承载 taxonomy 画像，不计入组件归属
            for label, conf in (getattr(node, "label_confidence", None) or {}).items():
                component_labels[label] = max(
                    component_labels.get(label, 0.0), float(conf)
                )
        if not component_labels:
            return

        # 幂等合并到既有 component_labels（保留顺序，追加新标签）
        existing = meta.get("component_labels")
        ordered: list[str] = list(existing) if isinstance(existing, list) else []
        for label in sorted(component_labels, key=lambda k: -component_labels[k]):
            if label not in ordered:
                ordered.append(label)
        meta["component_labels"] = ordered

        merged_conf = dict(meta.get("label_confidence") or {})
        for label, conf in component_labels.items():
            merged_conf[label] = max(float(merged_conf.get(label, 0.0)), float(conf))
        meta["label_confidence"] = merged_conf

        meta["graph_ref"] = {
            "schema_version": getattr(surface_graph, "schema_version", "1.0"),
            "entry_node_id": entry_id,
            "unknown": bool(getattr(surface_graph, "unknown", False)),
            "fallback_labels": list(getattr(surface_graph, "fallback_labels", []) or []),
        }
    except Exception as e:
        logger.debug("[ComponentBridge] 多标签归属写入失败（忽略）: %s", e)


def _derive_single_from_labels(meta: dict[str, Any]) -> str | None:
    """IC-1 兼容派生：从 `component_labels` + `label_confidence` 取置信度最高者。

    只从**组件**标签（即 `component_labels`）派生单值 `component_type`，
    排除入口节点的 taxonomy 画像维度（协议/模态等），保证 component_type 表达的是
    "这个 finding 属于哪个组件"，而非协议/模态描述。
    """
    labels = meta.get("component_labels")
    if not isinstance(labels, list) or not labels:
        return None
    confidences = meta.get("label_confidence") if isinstance(meta.get("label_confidence"), dict) else {}
    return max(labels, key=lambda label: float(confidences.get(label, 0.0)))


def _extract_prompt_from_result(result: Any) -> str | None:
    """Extract the original prompt value from an attack result."""
    # Try various attributes where prompt might be stored
    for attr in ("prompt", "seed_prompt", "seed_value", "original_prompt"):
        val = getattr(result, attr, None)
        if val:
            if isinstance(val, str):
                return val
            # Handle SeedPrompt objects
            inner_val = getattr(val, "value", None)
            if inner_val and isinstance(inner_val, str):
                return inner_val
    return None


def _infer_component_from_text(text: str) -> str | None:
    """Infer component type from technique/objective text."""
    text_lower = text.lower()

    # MCP indicators
    mcp_indicators = ["mcp", "tool", "schema", "server"]
    if any(ind in text_lower for ind in mcp_indicators):
        return "mcp_tool_poisoning"

    # A2A indicators
    a2a_indicators = ["a2a", "agent", "agent_card", "workflow", "trust", "registration"]
    if any(ind in text_lower for ind in a2a_indicators):
        return "a2a_agent_integrity"

    # Model indicators
    model_indicators = ["backdoor", "filter", "persona", "jailbreak"]
    if any(ind in text_lower for ind in model_indicators):
        return "model_behavior_shift"

    # RAG indicators
    rag_indicators = ["rag", "retrieval", "vector", "knowledge_base", "embedding"]
    if any(ind in text_lower for ind in rag_indicators):
        return "rag_pipeline"

    # Session/Memory indicators
    session_indicators = ["session", "memory", "context_leak", "context_persist"]
    if any(ind in text_lower for ind in session_indicators):
        return "session_memory"

    # Web/API indicators
    web_indicators = ["web", "auth", "jwt", "rate_limit", "smuggling", "gateway", "api_scope"]
    if any(ind in text_lower for ind in web_indicators):
        return "web_api"

    return None


def _component_from_graph(technique_name: str, graph: Any) -> str | None:
    """从 RECON 识别出的 ComponentGraph 中挑出与该技术最匹配的组件。

    匹配顺序：技术名直接命中组件键 → 技术名命中组件短名/标签 → 图的 dominant 组件。
    全程只读（IA-6：图缺失或异常返回 None，不抛异常）。
    """
    try:
        nodes = getattr(graph, "nodes", None)
        if not nodes:
            return None
        tech = (technique_name or "").lower()

        # 1) 技术名直接命中组件键
        for node in nodes:
            key = str(getattr(node, "component_key", "") or "")
            if key and (key in tech or key.replace("_", "") in tech.replace("_", "")):
                return key

        # 2) 取置信度最高的**已确认**节点（跳过组合体推断出的弱节点）
        confirmed = [n for n in nodes if not (getattr(n, "attributes", None) or {}).get("inferred")]
        pool = confirmed or list(nodes)
        if not pool:
            return None
        best = max(pool, key=lambda n: float(getattr(n, "confidence", 0.0) or 0.0))
        return str(getattr(best, "component_key", "") or "") or None
    except Exception as e:
        logger.debug("[ComponentBridge] 从组件图推断失败（忽略）: %s", e)
        return None


def _infer_component_from_category(category: str) -> str | None:
    """Infer component type from metadata category."""
    if not category or not isinstance(category, str):
        return None

    cat_lower = category.lower()

    if cat_lower.startswith("mcp_"):
        return "mcp_tool_poisoning"
    if cat_lower.startswith("a2a_") or cat_lower.startswith("agent_"):
        return "a2a_agent_integrity"
    if cat_lower.startswith("model_") or "backdoor" in cat_lower or "filter_bypass" in cat_lower:
        return "model_behavior_shift"
    if cat_lower.startswith("rag_") or "retrieval" in cat_lower or "vector" in cat_lower:
        return "rag_pipeline"
    if cat_lower.startswith("session_") or "memory" in cat_lower or "context_leak" in cat_lower:
        return "session_memory"
    if cat_lower.startswith("web_") or cat_lower.startswith("auth_") or "jwt" in cat_lower:
        return "web_api"

    return None
