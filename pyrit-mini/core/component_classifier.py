"""core/component_classifier.py — 多信号融合组件识别（plan Wave 1 / §4.2）。

真实企业 LLM 应用是**多组件组合体**，单一 `component_type` 标签无法表达。
本模块把黑盒可见信号做加权投票，输出**置信度而非二值**，并允许一次确认多个组件。

五层保障实现「确保 100% 侦察成功率」的工程口径（plan §2.3）：

    1. 多信号融合   path 指纹 + 响应体特征 + 能力指纹 + service_profile，加权投票
    2. 显式指定兜底 `--components mcp,rag` 直接锁定（confidence=1.0），跳过推断
    3. 组合体推断   已确认组件 → 用 `neighbors` 推断共存组件（低置信）
    4. 低置信降级   置信度 < min_confidence → degraded=True 且**强制 logger.warning**
    5. 强制可观测   分类不确定时必须留痕，禁止 `except Exception: logger.debug` 静默

**诚实声明**：黑盒条件下不存在字面意义的 100% 识别率。本模块的等价目标是
「不静默失败」——未识别必须 `logger.warning` 且写入 orchestration_log。

Academic basis:
    - Greshake et al. (arXiv:2302.12173): 间接注入面识别
    - NIST SP 800-115 Sec4: 攻击面枚举与指纹融合
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from pydantic import BaseModel, Field

from core.contracts.component_graph import ComponentEdge, ComponentGraph, ComponentNode
from core.registry import get_registry

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"

# C7 兜底默认值（仅当 defaults.yaml 缺失该键时使用；正常路径一律读配置）
_DEFAULT_WEIGHTS = {
    "weight_path": 0.40,
    "weight_body": 0.30,
    "weight_capability": 0.20,
    "weight_profile": 0.10,
    "neighbor_infer_confidence": 0.30,
    "fallback_min_confidence": 0.20,
    "max_components": 6,
}


class ClassificationResult(BaseModel):
    """组件识别结果。

    `degraded`=True 表示未能可靠识别（需降级通用 LLM 扫描），
    `reason` 必须人类可读且非空（禁止空字符串汇报）。
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    nodes: list[ComponentNode] = Field(default_factory=list)
    degraded: bool = False
    reason: str = ""
    signals: list[dict[str, Any]] = Field(default_factory=list)

    def keys(self) -> list[str]:
        return [n.component_key for n in self.nodes]

    def top(self) -> str | None:
        if not self.nodes:
            return None
        return max(self.nodes, key=lambda n: n.confidence).component_key

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def _cfg(args: Any, key: str) -> float | int:
    """C7：权重一律从 ctx.args 读（defaults.yaml → parse_args → args）。"""
    raw = getattr(args, key, None) if args is not None else None
    if raw is None:
        return _DEFAULT_WEIGHTS[key]
    return raw


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k} {v}" for k, v in value.items())
    return str(value)


def _collect_corpus(parsed_request: Any, service_profile: dict[str, Any] | None) -> tuple[str, str, str, str]:
    """收集四类信号语料：(path_text, body_text, capability_text, profile_text)。

    任一来源缺失都退化为空串而非抛异常（IA-6：未知输入不崩溃）。
    """
    path_text = ""
    body_text = ""
    capability_text = ""
    profile_text = ""

    if parsed_request is not None:
        path_text = " ".join(
            _as_text(x)
            for x in (
                getattr(parsed_request, "url", ""),
                getattr(parsed_request, "path", ""),
                getattr(parsed_request, "host", ""),
                getattr(parsed_request, "api_category", ""),
            )
        ).lower()

        fp = getattr(parsed_request, "target_fingerprint", None)
        fp_dict = fp.to_dict() if fp is not None and hasattr(fp, "to_dict") else (fp or {})
        if not isinstance(fp_dict, dict):
            fp_dict = {}

        capability_text = " ".join(
            _as_text(x)
            for x in (
                fp_dict.get("capabilities"),
                fp_dict.get("ai_framework"),
                fp_dict.get("ai_framework_category"),
                fp_dict.get("app_type"),
                fp_dict.get("session_type"),
                parsed_request_get(fp, "vector_dbs"),
                parsed_request_get(fp, "mcp_tools"),
            )
        ).lower()

        body_text = " ".join(
            _as_text(x)
            for x in (
                getattr(parsed_request, "body", ""),
                fp_dict.get("extracted_system_prompt"),
                fp_dict.get("openapi_spec_path"),
            )
        ).lower()

    if service_profile:
        profile_text = " ".join(f"{k} {_as_text(v)[:200]}" for k, v in service_profile.items()).lower()

    return path_text, body_text, capability_text, profile_text


def parsed_request_get(fp: Any, key: str) -> Any:
    """安全取 fingerprint 字段（兼容 dict / dataclass / None）。"""
    if fp is None:
        return ""
    if isinstance(fp, dict):
        return fp.get(key, "")
    getter = getattr(fp, "get", None)
    if callable(getter):
        try:
            return getter(key, "")
        except Exception:
            return ""
    return getattr(fp, key, "")


def classify(
    parsed_request: Any = None,
    *,
    override: list[str] | None = None,
    service_profile: dict[str, Any] | None = None,
    args: Any = None,
) -> ClassificationResult:
    """多信号融合组件识别。

    Args:
        parsed_request: `recon.burp_parser.ParsedBurpRequest`（可为 None → 退化路径）
        override: 来自 `--components` / `--strike` 的显式锁定列表
        service_profile: `ctx.service_profile`，专项侦察已写入的键
        args: `ctx.args`，用于读取 C7 权重配置

    Returns:
        ClassificationResult。置信度不足时 `degraded=True` 且已强制 warning 留痕。
    """
    registry = get_registry()

    # ---- 层 2：显式指定兜底（最高优先级，直接锁定）----
    if override:
        nodes: list[ComponentNode] = []
        unknown: list[str] = []
        for raw in override:
            key = (raw or "").strip()
            if not key:
                continue
            spec = registry.spec(key)
            if spec is None:
                unknown.append(key)
                continue
            nodes.append(
                ComponentNode(
                    component_key=spec.component_key,
                    confidence=1.0,
                    evidence_refs=[f"cli_override:{key}"],
                    endpoints=[],
                )
            )
        if unknown:
            # 反静默：未知组件键必须 warning（IA-6 只保证不崩溃，不保证静默）
            logger.warning(
                "[Classifier] --components 含未注册组件键，已忽略: %s（已注册: %s）",
                ", ".join(unknown),
                ", ".join(registry.keys()),
            )
        if nodes:
            return ClassificationResult(
                nodes=nodes,
                degraded=False,
                reason=f"显式指定锁定 {len(nodes)} 个组件: {', '.join(n.component_key for n in nodes)}",
                signals=[{"kind": "override", "keys": [n.component_key for n in nodes]}],
            )
        logger.warning("[Classifier] --components 全部无效，回退多信号融合识别")

    if registry.is_empty:
        logger.warning("[Classifier] 组件注册表为空（config/components/ 无声明），无法识别组件")
        return ClassificationResult(degraded=True, reason="组件注册表为空")

    path_text, body_text, capability_text, profile_text = _collect_corpus(parsed_request, service_profile)

    w_path = float(_cfg(args, "weight_path"))
    w_body = float(_cfg(args, "weight_body"))
    w_cap = float(_cfg(args, "weight_capability"))
    w_prof = float(_cfg(args, "weight_profile"))
    neighbor_conf = float(_cfg(args, "neighbor_infer_confidence"))
    max_components = int(_cfg(args, "max_components"))

    # ---- 层 1：多信号融合加权投票 ----
    scored: list[ComponentNode] = []
    signals: list[dict[str, Any]] = []

    for spec in registry.specs():
        conf = 0.0
        hits: list[str] = []

        for marker in spec.detection.path_patterns:
            if marker and marker.lower() in path_text:
                conf += w_path
                hits.append(f"path:{marker}")
                break  # 同类信号只记一次，避免单类信号叠加刷分

        for marker in spec.detection.body_markers:
            if marker and marker.lower() in body_text:
                conf += w_body
                hits.append(f"body:{marker}")
                break

        # 能力指纹：用组件键语义词 + 标签匹配 capabilities
        cap_tokens = {spec.component_key.lower(), spec.id.lower(), *(lab.lower() for lab in spec.labels)}
        if capability_text and any(tok and tok in capability_text for tok in cap_tokens):
            conf += w_cap
            hits.append("capability:fingerprint")

        for pkey in spec.service_profile_keys:
            if pkey and pkey.lower() in profile_text:
                conf += w_prof
                hits.append(f"profile:{pkey}")
                break

        if conf <= 0.0:
            continue

        conf = min(1.0, conf)
        if conf < spec.min_confidence:
            # 层 4/5：低置信不静默丢弃 —— 记录并 warning
            logger.warning(
                "[Classifier] 组件 %s 置信度 %.2f 低于阈值 %.2f，不纳入攻击链（命中信号: %s）",
                spec.component_key,
                conf,
                spec.min_confidence,
                ", ".join(hits) or "无",
            )
            signals.append({"component": spec.component_key, "confidence": conf, "hits": hits, "rejected": True})
            continue

        scored.append(
            ComponentNode(
                component_key=spec.component_key,
                confidence=round(conf, 3),
                evidence_refs=hits,
                endpoints=[],
                attributes={"asr_prior": spec.asr_prior, "preferred_attack_class": spec.preferred_attack_class},
            )
        )
        signals.append({"component": spec.component_key, "confidence": round(conf, 3), "hits": hits})

    if not scored:
        reason = "多信号融合未命中任何已注册组件（已尝试 path/body/capability/profile 四类信号）"
        logger.warning("[Classifier] %s —— 降级为通用 LLM 扫描", reason)
        return ClassificationResult(degraded=True, reason=reason, signals=signals)

    scored.sort(key=lambda n: n.confidence, reverse=True)
    if len(scored) > max_components:
        logger.warning(
            "[Classifier] 确认组件数 %d 超过上限 %d，按置信度裁剪（被裁: %s）",
            len(scored),
            max_components,
            ", ".join(n.component_key for n in scored[max_components:]),
        )
        scored = scored[:max_components]

    # ---- 层 3：组合体推断（已确认组件 → 推断邻居）----
    # 仅当锚点组件被**稳固确认**（confidence >= min_confidence 且 >= solid_floor）时才推断邻居，
    # 避免弱命中引发组合体爆炸、稀释预算（plan §2.3 层 3 + §8 风险「攻击规模爆炸」）。
    solid_floor = 0.60
    confirmed = {n.component_key for n in scored}
    for node in list(scored):
        if node.confidence < solid_floor or node.confidence < (registry.spec(node.component_key).min_confidence if registry.spec(node.component_key) else 0.0):
            continue
        spec = registry.spec(node.component_key)
        if spec is None:
            continue
        for nb in spec.neighbors:
            if nb in confirmed:
                continue
            nb_spec = registry.spec(nb)
            if nb_spec is None:
                continue
            inferred = ComponentNode(
                component_key=nb,
                confidence=neighbor_conf,
                evidence_refs=[f"inferred_from:{node.component_key}"],
                attributes={"asr_prior": nb_spec.asr_prior, "inferred": True},
            )
            if len(scored) >= max_components:
                logger.warning(
                    "[Classifier] 组合体推断已达上限 %d，停止推断（未推断: %s）", max_components, nb
                )
                break
            scored.append(inferred)
            confirmed.add(nb)
            signals.append({"component": nb, "confidence": neighbor_conf, "hits": [f"inferred:{node.component_key}"]})
        if len(scored) >= max_components:
            break

    reason = (
        f"多信号融合确认 {sum(1 for n in scored if not n.attributes.get('inferred'))} 个组件"
        f"（含 {sum(1 for n in scored if n.attributes.get('inferred'))} 个组合体推断）: "
        + ", ".join(f"{n.component_key}={n.confidence:.2f}" for n in scored)
    )
    return ClassificationResult(nodes=scored, degraded=False, reason=reason, signals=signals)


# =============================================================================
# ComponentGraph 构建（plan §1.7：识别 → 组件拓扑 → 专项侦察）
# =============================================================================

# 组件关系语义：下游组件相对于上游的关系（与 ComponentEdge.relation 取值域一致）
_RELATION_BY_DOWNSTREAM: dict[str, str] = {
    "rag_pipeline": "retrieves_from",
    "embedding": "retrieves_from",
    "mcp_tool_poisoning": "delegates_to",
    "a2a_agent_integrity": "delegates_to",
    "session_memory": "persists_to",
    "model_behavior_shift": "calls",
    "llm_gateway": "gated_by",
    "web_api": "gated_by",
    "audit_evasion": "observes",
    "supply_chain": "delegates_to",
}


def build_component_graph(
    result: ClassificationResult,
    *,
    service_profile: dict[str, Any] | None = None,
) -> ComponentGraph:
    """把识别结果升级为组件拓扑图（ComponentGraph）。

    边来源两级：
        1. `ComponentSpec.neighbors` 声明的常见共存关系（静态先验）
        2. 置信度排序产生的「入口 → 汇聚」方向（入口 = web_api/llm_gateway）

    复用资产：`recon/a2a/topology.py:105 TopologyGraph` 的图语义在此泛化到全部组件。
    """
    graph = ComponentGraph()

    for node in result.nodes:
        graph.add_node(node)
        # 端点回填：service_profile 中的 discovered_endpoints 若归属于该组件则挂上
        if service_profile:
            for pkey in (service_profile or {}):
                if pkey.startswith(node.component_key):
                    val = service_profile[pkey]
                    if isinstance(val, dict):
                        for ep in val.get("endpoints", []) or []:
                            if ep not in node.endpoints:
                                node.endpoints.append(str(ep))

    registry = get_registry()
    keys = graph.keys()
    for node in result.nodes:
        spec = registry.spec(node.component_key)
        if spec is None:
            continue
        for nb in spec.neighbors:
            if nb not in keys:
                continue
            relation = _RELATION_BY_DOWNSTREAM.get(nb, "calls")
            graph.add_edge(
                ComponentEdge(
                    src=node.component_key,
                    dst=nb,
                    relation=relation,  # type: ignore[arg-type]
                    confidence=round(min(node.confidence, 0.9), 3),
                    evidence_refs=[f"neighbor_declaration:{node.component_key}"],
                )
            )

    # 入口点：可从外部直接触达的节点（web_api / llm_gateway 优先，否则取置信度最高者）
    entry_candidates = [k for k in ("web_api", "llm_gateway") if k in keys]
    graph.entry_points = entry_candidates or ([graph.dominant()] if graph.dominant() else [])
    return graph
