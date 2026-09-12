"""recon/surface/builder.py — 从既有侦察产物构建 SurfaceGraph（REQ-150）。

复用而非重写（C3）：
    - `recon.taxonomy.derive_taxonomy`   → 四维标签（架构模式/协议/模态/认证）
    - `core.contracts.component_graph.ComponentGraph` → 组件节点与置信度
    - `recon.burp_parser.TargetFingerprint` → 端点、能力、认证方式

构造策略：
    1. 入口节点 `entry`：Burp 拦截到的端点本身（永远存在）。
    2. 组件节点：来自 ComponentGraph 的每个已确认组件。
    3. 标签来源：组件 `component_key` + taxonomy 四维标签（**多标签**，IC-1）。
    4. 边：入口 → 各组件为 `data_flow`；存在认证/网关时额外标记 `trust_boundary`。
    5. 识别失败（无任何组件节点）：走 `fallback_labels`，`unknown=True`，
       **不抛异常**（IA-6），下游据此降级为通用 LLM 扫描路径。

Note:
    本模块只读入参、只产出数据结构，**不发起任何网络请求**（recon 之外的副作用禁止）。
"""

from __future__ import annotations

import logging
from typing import Any

from recon.surface.graph import SurfaceEdge, SurfaceGraph, SurfaceNode

logger = logging.getLogger(__name__)

_TRUST_BOUNDARY_AUTH = ("oauth2", "session_cookie", "api_key")


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    getter = getattr(value, "get", None)
    if callable(getter):
        try:
            candidate = getter("__any__", None)
            return {} if candidate == "__any__" else {}
        except Exception:
            return {}
    return {}


def _fp_get(fingerprint: Any, key: str, default: Any = None) -> Any:
    """统一读取 fingerprint（支持 dict 与 dataclass 两种形态，C5 先读后写）。"""
    if fingerprint is None:
        return default
    if isinstance(fingerprint, dict):
        return fingerprint.get(key, default)
    getter = getattr(fingerprint, "get", None)
    if callable(getter):
        try:
            value = getter(key, default)
            if value is not None:
                return value
        except Exception:
            pass
    return getattr(fingerprint, key, default)


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(v) for v in value if v]
    return []


def build_surface_graph(
    *,
    fingerprint: Any = None,
    capabilities: Any = None,
    service_profile: Any = None,
    component_graph: Any = None,
    taxonomy: dict[str, Any] | None = None,
    event_ids: list[str] | None = None,
    endpoint: str | None = None,
) -> SurfaceGraph:
    """构建攻击面图谱（REQ-150）。

    Args:
        fingerprint: `TargetFingerprint` 或等价 dict（只读）。
        capabilities: 能力列表/字符串；为 None 时回退 `fingerprint.capabilities`。
        service_profile: `ctx.service_profile` dict。
        component_graph: `core.contracts.component_graph.ComponentGraph`（可为空）。
        taxonomy: `recon.taxonomy.derive_taxonomy` 产物；为 None 时**不**自行推导
            （保持本模块无 I/O 与无隐藏依赖，由调用方决定推导时机）。
        event_ids: 可回溯的 EventLog 事件 ID 列表（蓝图 I12）。
        endpoint: 入口端点 URL；为 None 时从 fingerprint 的 host/api_path 拼接。

    Returns:
        `SurfaceGraph`。**永不抛异常**：任何输入异常都退化为带兜底标签的空图。
    """
    evidence = [str(e) for e in (event_ids or []) if e]
    sp = _as_dict(service_profile)
    graph = SurfaceGraph()

    try:
        caps = _as_str_list(capabilities) or _as_str_list(_fp_get(fingerprint, "capabilities"))
        if endpoint is None:
            host = str(_fp_get(fingerprint, "host", "") or "")
            path = str(_fp_get(fingerprint, "api_path", "") or "")
            endpoint = f"{host}{path}" if host else path

        # ---- 1) 入口节点 ----
        entry = SurfaceNode(
            node_id=graph.entry_node_id,
            capabilities=sorted(set(caps)),
            endpoints=[endpoint] if endpoint else [],
            evidence=list(evidence),
            attributes={
                "framework": _fp_get(fingerprint, "framework", "Unknown"),
                "app_type": _fp_get(fingerprint, "app_type", "Web Application"),
                "api_category": _fp_get(fingerprint, "api_category", "chat"),
                "auth_type": _fp_get(fingerprint, "auth_type", "None"),
                "model_family": _fp_get(fingerprint, "model_family", None),
            },
        )
        graph.add_node(entry)

        # ---- 2) 组件节点（来自 ComponentGraph）----
        component_keys: list[tuple[str, float]] = []
        for node in getattr(component_graph, "nodes", None) or []:
            key = str(getattr(node, "component_key", "") or "")
            if not key:
                continue
            confidence = float(getattr(node, "confidence", 0.0) or 0.0)
            component_keys.append((key, confidence))

            c_node = SurfaceNode(
                node_id=key,
                endpoints=_as_str_list(getattr(node, "endpoints", None)),
                evidence=[str(x) for x in (getattr(node, "evidence_refs", None) or [])] or list(evidence),
                attributes=dict(getattr(node, "attributes", None) or {}),
            )
            c_node.add_label(key, confidence)
            graph.add_node(c_node)
            graph.add_edge(
                SurfaceEdge(
                    src=graph.entry_node_id,
                    dst=key,
                    type="data_flow",
                    confidence=confidence,
                    evidence=list(evidence),
                )
            )

        # ---- 3) taxonomy 四维标签（多标签核心，IC-1）----
        if isinstance(taxonomy, dict) and taxonomy:
            entry_labels = {
                "architecture_mode": taxonomy.get("architecture_mode"),
                "protocol": taxonomy.get("protocol"),
                "input_modality": taxonomy.get("input_modality"),
                "auth_method": taxonomy.get("auth_method"),
            }
            confidences = taxonomy.get("label_confidence") if isinstance(taxonomy.get("label_confidence"), dict) else {}
            for _dimension, labels in entry_labels.items():
                for label in _as_str_list(labels):
                    entry.add_label(label, float(confidences.get(label, 0.5)))

            fallback = _as_str_list(taxonomy.get("fallback_labels"))
            if fallback:
                graph.fallback_labels = sorted(set(fallback))

            # 认证/网关类标签 ⇒ 入口位于信任边界（IC-2 跨组件链的前提信号）
            auth_labels = set(_as_str_list(entry_labels.get("auth_method")))
            if auth_labels & set(_TRUST_BOUNDARY_AUTH):
                entry.trust_boundary = True

        # ---- 4) 信任边界边 ----
        if entry.trust_boundary:
            for key, confidence in component_keys:
                graph.add_edge(
                    SurfaceEdge(
                        src=graph.entry_node_id,
                        dst=key,
                        type="trust_boundary",
                        confidence=confidence,
                        evidence=list(evidence),
                    )
                )

        # ---- 5) 专项侦察产物挂载为属性（RAG/MCP/A2A，供 L2 编排消费）----
        for sp_key in ("rag_pipeline", "mcpsec_surface", "a2a_inventory", "mcp_local_recon", "graphql"):
            if sp.get(sp_key) is not None:
                entry.attributes.setdefault(sp_key, True)

        # ---- 6) 识别失败判定 ----
        graph.unknown = not graph.labels()
        if graph.unknown:
            for label in graph.fallback_labels:
                entry.add_label(label, 0.3)
            logger.warning(
                "[SurfaceGraph] 攻击面识别失败，启用兜底标签 %s（下游将降级为通用路径）",
                graph.fallback_labels,
            )

        logger.info(
            "[SurfaceGraph] built: nodes=%d edges=%d labels=%s",
            len(graph.nodes),
            len(graph.edges),
            graph.labels()[:6],
        )
        return graph
    except Exception as e:  # 图谱构建失败不得中断侦察主链路（NFR-8）
        logger.warning("[SurfaceGraph] 构建失败，返回空图（降级路径）: %s", e)
        fallback = SurfaceGraph()
        fallback.unknown = True
        fallback.add_node(
            SurfaceNode(
                node_id=fallback.entry_node_id,
                labels=list(fallback.fallback_labels),
                label_confidence={label: 0.3 for label in fallback.fallback_labels},
            )
        )
        return fallback
