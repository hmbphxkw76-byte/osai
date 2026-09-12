"""recon/_burp_models — Dataclasses for parsed Burp requests and target fingerprints.

Extracted from `recon/burp_parser.py` (SRP): the data contracts
`TargetFingerprint` and `ParsedBurpRequest` are shared by the request parsers,
the fingerprint extractor, and the downstream recon phases, so they live in their
own dependency-free module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetFingerprint:
    """Target fingerprint schema.

    Phase 1 (parse-time) fields are populated by the HTTP parser / fingerprint
    extractor; Phase 2 fields are filled in later by the capability detector and
    target router. Supports dict-like access via get/__getitem__/__setitem__.
    """

    # == Phase 1: HTTP framing (set by _extract_fingerprint) ==
    framework: str = "Unknown"
    api_path: str = ""
    host: str = ""
    auth_type: str = "None"
    content_type: str = "unknown"
    app_type: str = "Web Application"
    api_category: str = "chat"

    # == Phase 1: HTTP framing (set by _parse_raw_http) ==
    ai_framework: str | None = None
    ai_framework_category: str | None = None
    chat_id: str | None = None
    burp_model_name: str | None = None
    has_model_list: bool = False

    # == Phase 2: probing (capability_detector / target_router) ==
    language: str | None = None
    model_family: str | None = None
    capabilities: list[str] = field(default_factory=list)
    probe_count: int = 0
    probe_duration_seconds: float = 0.0

    # == Phase 2: (target_router) ==
    mcp_tools: list[str] = field(default_factory=list)
    mcp_resources: list[str] = field(default_factory=list)
    mcp_prompts: list[str] = field(default_factory=list)
    system_prompt_leaked: bool = False
    extracted_system_prompt: str | None = None
    system_prompt_extraction_method: str | None = None
    openapi_spec_path: str | None = None
    openapi_endpoints: list[str] = field(default_factory=list)
    original_prompt: str | None = None
    session_type: str | None = None

    # == (extension bucket) ==
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like .get() with attribute + extra fallback."""
        if hasattr(self, key) and not key.startswith("_"):
            val = getattr(self, key)
            return val if val is not None else default
        return self.extra.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Dict-like [key] access with attribute + extra fallback."""
        if hasattr(self, key) and not key.startswith("_"):
            return getattr(self, key)
        return self.extra[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-like [key] = value with attribute + extra storage."""
        if hasattr(self, key) and not key.startswith("_"):
            setattr(self, key, value)
        else:
            self.extra[key] = value

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict, filtering empty values."""
        from dataclasses import asdict

        result = asdict(self)
        extra = result.pop("extra", {})
        result.update(extra)
        # Filter None/empty/False/zero values for compact output
        return {k: v for k, v in result.items() if v not in (None, "", [], False, 0, 0.0)}


@dataclass
class ParsedBurpRequest:
    """A single parsed Burp HTTP request."""

    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    use_tls: bool = True
    is_sse: bool = False
    http_version: str = "HTTP/1.1"
    has_prompt_placeholder: bool = False
    response_json_path: str | None = None
    target_fingerprint: TargetFingerprint = field(default_factory=TargetFingerprint)
    chat_id: str | None = None
    chat_id_field: str | None = None
    has_chat_id_placeholder: bool = False
    original_prompt_value: str | None = None
    burp_model_name: str | None = None
    burp_model_list: str | None = None
    api_category: str = "chat"
    # 会话枚举攻击计划 (ASI09): 当非 None 时启用枚举模式
    enumeration_plan: dict[str, Any] | None = None
