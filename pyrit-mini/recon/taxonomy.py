"""recon/taxonomy.py — 目标类型分类本体（REQ-162 / CP-002 第九章 D）。

四维标签本体（**多标签 + 分维置信度**），用于让 ARM/Strike 的
「seeds / converters / strike」选择有稳定的 schema 依据：

    architecture_mode : single_llm | react_agent | multi_agent | rag | mcp_connected | hybrid
    protocol          : rest | websocket | sse | mcp_stdio | mcp_sse | grpc
    input_modality    : text | multimodal | file_upload | code_exec
    auth_method       : none | api_key | oauth2 | session_cookie

设计约束（CP-002 / 蓝图）：
    - 纯函数、无 IO、无攻击逻辑；仅从 recon 已有观测派生（R-DECIDE-5 / ID-5）。
    - 输出写入 `target_fingerprint`（recon 唯一输出总线），**不新建并行通道**（I12）。
    - 多标签（IC-1）：一个目标可同时是 rag + mcp_connected（hybrid）。
    - 识别失败不抛异常，走 `fallback_labels` 兜底（single_llm / text / none）。

学术/标准依据：
    - OWASP AI Testing Guide: Model / Implementation / System / Runtime 分层。
    - NIST SP 800-115 Sec4: Attack surface enumeration.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

ARCHITECTURE_MODES: tuple[str, ...] = (
    "single_llm",
    "react_agent",
    "multi_agent",
    "rag",
    "mcp_connected",
    "hybrid",
)
PROTOCOLS: tuple[str, ...] = ("rest", "websocket", "sse", "mcp_stdio", "mcp_sse", "grpc")
INPUT_MODALITIES: tuple[str, ...] = ("text", "multimodal", "file_upload", "code_exec")
AUTH_METHODS: tuple[str, ...] = ("none", "api_key", "oauth2", "session_cookie")

# 能力关键词 → 标签映射（关键词命中即视为该能力的弱证据）
_RAG_KEYWORDS = ("rag", "retrieval", "retrieve", "vector", "embedding", "knowledge_base", "kb")
_MCP_KEYWORDS = ("mcp", "model_context_protocol")
_TOOL_USE_KEYWORDS = ("tool_use", "tool_call", "function_calling", "function-calling")
_AGENT_KEYWORDS = ("agent", "autonomous", "react", "planning")
_MULTI_AGENT_KEYWORDS = ("multi_agent", "a2a", "agent_card", "orchestrator_agent")
_MULTIMODAL_KEYWORDS = ("multimodal", "vision", "image", "audio", "vlm", "ocr")
_FILE_UPLOAD_KEYWORDS = ("file_upload", "upload", "attachment", "document")
_CODE_EXEC_KEYWORDS = ("code_execution", "code_exec", "python_exec", "sandbox", "interpreter")


def _flatten(value: Any) -> str:
    """Normalize capability-ish values (str / list / set) into one lowercase string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(str(v) for v in value).lower()
    return str(value).lower()


def _has_any(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(n in haystack for n in needles)


def _label(value: str, confidence: float) -> tuple[list[str], dict[str, float]]:
    return [value], {value: round(confidence, 2)}


def derive_taxonomy(
    fingerprint: Any = None,
    capabilities: Any = None,
    service_profile: Any = None,
) -> dict[str, Any]:
    """Derive the four-dimension taxonomy from existing recon observations.

    Args:
        fingerprint: `recon.burp_parser.TargetFingerprint` (or dict-like) — read-only.
        capabilities: capability list/str (falls back to `fingerprint.capabilities`).
        service_profile: `ctx.service_profile` dict (rag_pipeline / mcpsec_surface / a2a_inventory).

    Returns:
        {
          "architecture_mode": [...], "protocol": [...],
          "input_modality": [...], "auth_method": [...],
          "label_confidence": {label: float},
          "fallback_labels": [...],   # 识别失败时的兜底
          "schema_version": "1.0",
        }
        Never raises; unknown inputs yield the fallback labels.
    """
    fp = fingerprint if fingerprint is not None else {}
    sp = service_profile if isinstance(service_profile, dict) else {}

    def _fp_get(key: str, default: Any = None) -> Any:
        if isinstance(fp, dict):
            return fp.get(key, default)
        getter = getattr(fp, "get", None)
        if callable(getter):
            try:
                return getter(key, default)
            except Exception:
                pass
        return getattr(fp, key, default)

    caps_text = _flatten(capabilities if capabilities is not None else _fp_get("capabilities"))
    app_type = _flatten(_fp_get("app_type"))
    api_category = _flatten(_fp_get("api_category"))
    ai_framework = _flatten(_fp_get("ai_framework"))
    signal_text = " ".join([caps_text, app_type, api_category, ai_framework])

    label_confidence: dict[str, float] = {}
    fallback_labels: list[str] = []

    # ---------------- architecture_mode ----------------
    arch: list[str] = []
    # NOTE: presence checks use `is not None` — an empty dict `{}` is a *present*
    # signal (probe ran, structure empty), not an absent one.
    rag_score = 0.9 if sp.get("rag_pipeline") is not None else 0.0
    if not rag_score and _has_any(signal_text, _RAG_KEYWORDS):
        rag_score = 0.6
    if rag_score:
        arch.append("rag")
        label_confidence["rag"] = rag_score

    mcp_score = 0.9 if sp.get("mcpsec_surface") is not None else 0.0
    if not mcp_score and _has_any(signal_text, _MCP_KEYWORDS):
        mcp_score = 0.6
    if mcp_score:
        arch.append("mcp_connected")
        label_confidence["mcp_connected"] = mcp_score

    if sp.get("a2a_inventory") is not None or _has_any(signal_text, _MULTI_AGENT_KEYWORDS):
        arch.append("multi_agent")
        label_confidence["multi_agent"] = 0.9 if sp.get("a2a_inventory") is not None else 0.6
    elif _has_any(signal_text, _AGENT_KEYWORDS) or _has_any(signal_text, _TOOL_USE_KEYWORDS):
        arch.append("react_agent")
        label_confidence["react_agent"] = 0.6

    # 组合体：命中 ≥2 个"结构型"标签（rag / mcp / multi_agent）
    structural = [a for a in arch if a in ("rag", "mcp_connected", "multi_agent")]
    if len(structural) >= 2:
        arch.append("hybrid")
        label_confidence["hybrid"] = 0.8

    if not arch:
        arch.append("single_llm")
        label_confidence["single_llm"] = 0.5
        fallback_labels.append("single_llm")

    # ---------------- protocol ----------------
    protocol: list[str] = []
    if _fp_get("is_sse") or "streaming" in caps_text or "sse" in caps_text:
        if "mcp_connected" in arch:
            protocol.append("mcp_sse")
            label_confidence["mcp_sse"] = 0.7
        protocol.append("sse")
        label_confidence["sse"] = 0.8
    if any(k in caps_text for k in ("websocket", "ws://", "wss://")):
        protocol.append("websocket")
        label_confidence["websocket"] = 0.6
    if any(k in caps_text for k in ("grpc", "protobuf")):
        protocol.append("grpc")
        label_confidence["grpc"] = 0.6
    if "mcp_connected" in arch and any(k in caps_text for k in ("stdio", "subprocess")):
        protocol.append("mcp_stdio")
        label_confidence["mcp_stdio"] = 0.6
    if not protocol:
        protocol.append("rest")
        label_confidence["rest"] = 0.7
        fallback_labels.append("rest")

    # ---------------- input_modality ----------------
    modality: list[str] = []
    if _has_any(signal_text, _MULTIMODAL_KEYWORDS):
        modality.append("multimodal")
        label_confidence["multimodal"] = 0.7
    if _has_any(signal_text, _FILE_UPLOAD_KEYWORDS):
        modality.append("file_upload")
        label_confidence["file_upload"] = 0.6
    if _has_any(signal_text, _CODE_EXEC_KEYWORDS):
        modality.append("code_exec")
        label_confidence["code_exec"] = 0.7
    modality.append("text")  # 文本永远存在
    label_confidence.setdefault("text", 0.9)

    # ---------------- auth_method ----------------
    auth_type = str(_fp_get("auth_type") or "None").lower()
    auth: list[str] = []
    if "oauth" in auth_type:
        auth.append("oauth2")
        label_confidence["oauth2"] = 0.8
        auth.append("api_key")
        label_confidence.setdefault("api_key", 0.6)
    elif "cookie" in auth_type or "session" in auth_type:
        auth.append("session_cookie")
        label_confidence["session_cookie"] = 0.8
    elif auth_type in ("none", "", "unknown"):
        auth.append("none")
        label_confidence["none"] = 0.7
        fallback_labels.append("none")
    else:
        # Bearer / Basic / Custom Auth Header 均按 API Key 类处理
        auth.append("api_key")
        label_confidence["api_key"] = 0.8

    result = {
        "architecture_mode": arch,
        "protocol": protocol,
        "input_modality": modality,
        "auth_method": auth,
        "label_confidence": label_confidence,
        "fallback_labels": sorted(set(fallback_labels)),
        "schema_version": "1.0",
    }
    return result


def taxonomy_to_prompt_hint(taxonomy: dict[str, Any]) -> str:
    """Render a compact hint for decision logging / orchestration_log."""
    if not isinstance(taxonomy, dict):
        return ""
    parts = [
        "/".join(taxonomy.get("architecture_mode") or []),
        "/".join(taxonomy.get("protocol") or []),
        "/".join(taxonomy.get("input_modality") or []),
        "/".join(taxonomy.get("auth_method") or []),
    ]
    return " | ".join(p for p in parts if p)
