"""
target_profile.json 完整 Schema 定义
====================================

这是 AI 侦测引擎与 PyRIT 攻击框架之间的标准数据交换格式。
Schema 版本化为 1.0，所有字段均有详细注释。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass, field, asdict


# ═══════════════════════════════════════════════════════════════════════════
# 枚举类型
# ═══════════════════════════════════════════════════════════════════════════

class EndpointCategory(str, Enum):
    """API 端点功能分类"""
    CHAT = "chat"               # AI 对话端点
    AUTH = "auth"               # 认证/登录
    RAG = "rag"                 # 检索增强生成
    UPLOAD = "upload"           # 文件上传
    ADMIN = "admin"             # 管理端点
    STATIC = "static"           # 静态资源
    HEALTH = "health"           # 健康检查
    INFO = "info"               # 信息/版本
    MODELS = "models"           # 模型列表
    TOOLS = "tools"             # 工具调用/MCP
    AGENT = "agent"             # 智能体
    STREAM = "stream"           # 流式端点
    SEARCH = "search"           # 搜索/查询
    DEBUG = "debug"             # 调试端点
    UNKNOWN = "other"           # 未分类


class Confidence(str, Enum):
    """置信度等级"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AuthType(str, Enum):
    """认证方式"""
    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    QUERY_TOKEN = "query_token"
    CUSTOM_HEADER = "custom_header"


class TargetType(str, Enum):
    """目标架构类型（与 PyRIT TargetType 对齐）"""
    BASIC_LLM = "basic_llm"         # 纯 LLM
    RAG = "rag"                     # 检索增强生成
    MCP = "mcp"                     # MCP 工具协议
    AGENT = "agent"                 # 智能体
    MULTI_AGENT = "multi_agent"     # 多智能体
    UNKNOWN = "unknown"


class EndpointType(str, Enum):
    """端点 API 类型"""
    OPENAI = "openai"
    AZURE = "azure"
    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    CUSTOM = "custom"
    HTML = "html"
    UNKNOWN = "unknown"


class ApiFormat(str, Enum):
    """API 请求格式"""
    OPENAI_CHAT = "openai_chat"
    OPENAI_COMPLETION = "openai_completion"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    GEMINI_CHAT = "gemini_chat"
    RAW_JSON = "raw_json"
    RAW_FORM = "raw_form"
    RAW_TEXT = "raw_text"
    SSE = "sse"                 # Server-Sent Events 流式响应


class SpaFramework(str, Enum):
    """SPA 前端框架"""
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    SVELTE = "svelte"
    NEXT = "nextjs"
    NUXT = "nuxt"
    UNKNOWN = "unknown"


class RouterMode(str, Enum):
    """SPA 路由模式"""
    HASH = "hash"
    HISTORY = "history"
    MEMORY = "memory"
    UNKNOWN = "unknown"


class ReconTool(str, Enum):
    """侦测工具标识"""
    AI_RECON = "ai-recon"


# ═══════════════════════════════════════════════════════════════════════════
# Schema 常量
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA_VERSION = "1.0"
SCHEMA_DESCRIPTION = (
    "AI 侦测引擎 → PyRIT 攻击框架标准数据交换格式。"
    "两阶段流水线桥接：Phase 1 (recon) 输出 → Phase 2 (PyRIT) 读取。"
)


# ═══════════════════════════════════════════════════════════════════════════
# 数据类定义
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ProfileMeta:
    """目标画像元信息"""
    version: str = SCHEMA_VERSION
    generated_at: str = ""                      # ISO 8601 时间戳
    tool: str = ReconTool.AI_RECON.value         # 生成工具
    target_url: str = ""                         # 侦察目标 URL
    probe_duration_ms: int = 0                   # 侦察总耗时（毫秒）
    notes: str = ""                              # 人工备注


@dataclass
class AuthInfo:
    """认证信息"""
    type: str = AuthType.NONE.value              # 认证方式
    login_url: str = ""                          # 登录页面 URL
    login_method: str = "POST"                   # 登录 HTTP 方法
    login_payload: dict = field(default_factory=dict)  # 登录请求体
    session_cookie: str = ""                     # session cookie
    cookies: dict = field(default_factory=dict)  # 全部 cookies
    custom_headers: dict = field(default_factory=dict)  # 自定义认证头
    csrf_token: str = ""                         # CSRF token
    bearer_token: str = ""                       # Bearer token
    query_token: str = ""                        # URL Query Token（如 ?token=xxx）
    token_refresh_url: str = ""                  # Token 刷新端点
    notes: str = ""                              # 认证相关备注


@dataclass
class ModelProbeInfo:
    """主动模型探测结果"""
    model_name: str = ""                         # 探测到的模型名称
    strategy: str = ""                           # 成功探测的策略描述
    confidence: float = 0.0                      # 探测置信度 (0.0-1.0)
    framework: str = "unknown"                   # 框架名称 (ollama/vllm/openai/...)
    framework_confidence: str = "low"            # 框架置信度 (high/medium/low)
    endpoint_type: str = EndpointType.UNKNOWN.value
    recommended_concurrency: int = 3             # 推荐并发数
    recommended_rpm: int = 30                    # 推荐每分钟请求数
    avg_response_ms: float = 0.0                 # 平均响应时间
    total_429s: int = 0                          # 限流次数
    discovered_endpoints: list[dict] = field(default_factory=list)  # 发现的端点详情
    all_attempts: list[dict] = field(default_factory=list)          # 所有探测尝试记录
    errors: list[str] = field(default_factory=list)                 # 探测错误


@dataclass
class TargetInfo:
    """攻击目标核心参数"""
    base_url: str = ""                           # 目标根 URL
    chat_api_url: str = ""                       # Chat API 完整 URL
    model_name: str = ""                         # 模型名称
    endpoint_type: str = EndpointType.UNKNOWN.value
    api_format: str = ApiFormat.RAW_JSON.value
    target_type: str = TargetType.UNKNOWN.value
    verify_ssl: bool = True
    custom_headers: dict = field(default_factory=dict)
    request_timeout: int = 60                    # 请求超时（秒）
    http_method: str = "POST"
    content_type: str = "application/json"
    stream: bool = False                         # 是否 SSE 流式响应
    framework: str = "unknown"                   # AI 框架/服务名称
    framework_confidence: str = "low"            # 框架识别置信度


@dataclass
class ApiEndpoint:
    """单个 API 端点详情"""
    path: str = ""                               # 端点路径，如 /ai/chat
    full_url: str = ""                           # 完整 URL
    method: str = "GET"                          # HTTP 方法
    status: int = 0                              # HTTP 状态码
    content_type: str = ""                       # 响应 Content-Type
    category: str = EndpointCategory.UNKNOWN.value
    request_schema: dict = field(default_factory=dict)    # 请求 Body 示例
    response_schema: dict = field(default_factory=dict)   # 响应 Body 结构
    param_patterns: dict = field(default_factory=dict)    # 参数模式
    is_chat_endpoint: bool = False               # 是否为对话端点
    is_streaming: bool = False                   # 是否支持流式
    requires_auth: bool = False                  # 是否需要认证
    confidence: str = Confidence.LOW.value       # 分类置信度
    response_time_ms: float = 0.0                # 响应时间
    body_snippet: str = ""                       # 响应体摘要


@dataclass
class DynamicRoute:
    """动态路由模式"""
    pattern: str = ""                            # 路由模式，如 /ai/chat/{hex_id:12}
    method: str = "POST"
    sample_value: str = ""                       # 示例值，如 0bc618bc2cd8
    inferred_from: str = ""                      # 推断来源描述
    confidence: str = Confidence.MEDIUM.value


@dataclass
class SpaInfo:
    """SPA 前端信息"""
    is_spa: bool = False                         # 是否为 SPA
    framework: str = SpaFramework.UNKNOWN.value  # 前端框架
    router_mode: str = RouterMode.UNKNOWN.value  # 路由模式
    js_bundle_urls: list[str] = field(default_factory=list)
    api_base_url: str = ""                       # API base URL（从 JS 提取）
    extracted_routes_count: int = 0
    extracted_endpoints_count: int = 0
    notes: str = ""


@dataclass
class RateLimitInfo:
    """速率限制分析"""
    has_rate_limit: bool = False
    rate_limit_type: str = "none"                # explicit / implicit / none
    rpm_limit: Optional[int] = None
    tpm_limit: Optional[int] = None
    recommended_concurrency: int = 3
    recommended_rpm: int = 30
    avg_response_ms: float = 0.0
    p95_response_ms: float = 0.0
    total_429s: int = 0
    details: str = ""


@dataclass
class RawProbeData:
    """原始探测数据"""
    dns_records: dict = field(default_factory=dict)
    ssl_certificate: dict = field(default_factory=dict)
    http_headers: dict = field(default_factory=dict)
    robots_txt: str = ""
    favicon_hash: str = ""
    waf_detected: str = ""
    server_header: str = ""
    powered_by: str = ""
    fingerprint_matches: list[str] = field(default_factory=list)
    homepage_title: str = ""
    homepage_text_snippet: str = ""


@dataclass
class JsSdkInfo:
    """JS SDK 指纹扫描结果"""
    findings: list[dict] = field(default_factory=list)
    total_scripts_scanned: int = 0
    total_matches: int = 0
    extracted_api_urls: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class CredentialInfo:
    """密钥泄露扫描结果"""
    findings: list[dict] = field(default_factory=list)
    total_scanned: int = 0
    critical_count: int = 0
    high_count: int = 0
    summary: str = ""


@dataclass
class WafInfo:
    """WAF/CDN/IPS 检测结果"""
    detections: list[dict] = field(default_factory=list)
    waf_count: int = 0
    summary: str = ""
    implications: str = ""


@dataclass
class RagInfo:
    """RAG/Agent 架构探测结果"""
    is_rag: bool = False
    is_agent: bool = False
    is_multi_agent: bool = False
    has_tools: bool = False
    has_memory: bool = False
    has_browsing: bool = False
    target_architecture: str = "unknown"
    rag_confidence: float = 0.0
    rag_data_sources: list[str] = field(default_factory=list)
    agent_tools: list[str] = field(default_factory=list)
    agent_tools_count: int = 0
    agent_delegation_detected: bool = False
    agent_card_discovered: bool = False
    agent_card_url: str = ""
    guardrail_detected: bool = False
    guardrail_boundaries: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class PromptExtractionInfo:
    """提示词提取探测结果"""
    system_prompt_fragments: list[str] = field(default_factory=list)
    system_prompt_extracted: bool = False
    system_prompt_confidence: float = 0.0
    tools_extracted: list[str] = field(default_factory=list)
    tools_count: int = 0
    guardrail_rules: list[str] = field(default_factory=list)
    guardrail_detected: bool = False
    capabilities: list[str] = field(default_factory=list)
    knowledge_cutoff: str = ""
    model_identity: str = ""
    key_prefixes: list[str] = field(default_factory=list)
    key_prefix_leaked: bool = False
    extraction_success: bool = False
    risk_score: float = 0.0
    all_responses: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)


@dataclass
class BehaviorMapInfo:
    """行为测绘分析结果"""
    overall_security_score: float = 50.0
    overall_label: str = "medium"
    weakness_scores: list[dict] = field(default_factory=list)
    critical_findings: list[str] = field(default_factory=list)
    weakest_boundary: str = ""
    attack_vectors: list[dict] = field(default_factory=list)
    target_attack_entry: str = ""
    bypass_feasibility: str = ""
    bypass_methods: list[str] = field(default_factory=list)
    summary: str = ""
    detailed_report: str = ""


@dataclass
class PhaseReport:
    """单个阶段的报告"""
    phase_name: str = ""
    phase_id: str = ""
    status: str = "skipped"  # completed / skipped / failed
    findings_count: int = 0
    key_items: list[str] = field(default_factory=list)
    summary: str = ""
    raw_data: dict = field(default_factory=dict)


@dataclass
class ReconArtifacts:
    """侦察过程产物"""
    har_file: str = ""                           # HAR 文件路径
    screenshots: list[str] = field(default_factory=list)
    js_files_saved: list[str] = field(default_factory=list)
    login_flow_trace: str = ""                   # 登录流程日志
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# 主 Schema 类
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TargetProfile:
    """target_profile.json 完整数据结构
    
    这是 AI 侦测引擎的最终输出，也是 PyRIT 攻击框架的输入。
    所有字段均有默认值，确保向后兼容。
    """
    meta: ProfileMeta = field(default_factory=ProfileMeta)
    target: TargetInfo = field(default_factory=TargetInfo)
    auth: AuthInfo = field(default_factory=AuthInfo)
    api_endpoints: list[ApiEndpoint] = field(default_factory=list)
    dynamic_routes: list[DynamicRoute] = field(default_factory=list)
    spa_info: SpaInfo = field(default_factory=SpaInfo)
    rate_limit: RateLimitInfo = field(default_factory=RateLimitInfo)
    raw_probe_data: RawProbeData = field(default_factory=RawProbeData)
    artifacts: ReconArtifacts = field(default_factory=ReconArtifacts)
    model_probe: ModelProbeInfo = field(default_factory=ModelProbeInfo)
    js_sdk: JsSdkInfo = field(default_factory=JsSdkInfo)
    credentials: CredentialInfo = field(default_factory=CredentialInfo)
    waf: WafInfo = field(default_factory=WafInfo)
    rag_probe: RagInfo = field(default_factory=RagInfo)
    prompt_extraction: PromptExtractionInfo = field(default_factory=PromptExtractionInfo)
    behavior_map: BehaviorMapInfo = field(default_factory=BehaviorMapInfo)
    phase_reports: list[PhaseReport] = field(default_factory=list)

    # ── 序列化 ──

    def to_dict(self) -> dict:
        """将 Profile 转换为可 JSON 序列化的 dict（排除空值以减小体积）"""
        def _convert(obj):
            if hasattr(obj, '__dataclass_fields__'):
                result = {}
                for k, v in asdict(obj).items():
                    converted = _convert(v)
                    # 保留非空值、0、False
                    if converted is not None and converted != "" and converted != [] and converted != {}:
                        result[k] = converted
                    elif isinstance(converted, (int, float, bool)):
                        result[k] = converted
                return result
            elif isinstance(obj, list):
                return [_convert(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: _convert(v) for k, v in obj.items() if v is not None}
            elif isinstance(obj, Enum):
                return obj.value
            return obj
        return _convert(self)

    def to_json(self, indent: int = 2, ensure_ascii: bool = False) -> str:
        """序列化为 JSON 字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=ensure_ascii)

    def save(self, filepath: str) -> str:
        """保存到文件，返回文件路径"""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return str(path)

    # ── 反序列化 ──

    @classmethod
    def from_dict(cls, data: dict) -> TargetProfile:
        """从 dict 构造 TargetProfile（容错解析）"""
        meta_data = data.get("meta", {})
        target_data = data.get("target", {})
        auth_data = data.get("auth", {})
        rate_data = data.get("rate_limit", {})
        spa_data = data.get("spa_info", {})
        raw_data = data.get("raw_probe_data", {})
        artifacts_data = data.get("artifacts", {})

        # 解析 api_endpoints
        api_endpoints = []
        for ep in data.get("api_endpoints", []):
            api_endpoints.append(ApiEndpoint(
                path=ep.get("path", ""),
                full_url=ep.get("full_url", ""),
                method=ep.get("method", "GET"),
                status=ep.get("status", 0),
                content_type=ep.get("content_type", ""),
                category=ep.get("category", EndpointCategory.UNKNOWN.value),
                request_schema=ep.get("request_schema", {}),
                response_schema=ep.get("response_schema", {}),
                param_patterns=ep.get("param_patterns", {}),
                is_chat_endpoint=ep.get("is_chat_endpoint", False),
                is_streaming=ep.get("is_streaming", False),
                requires_auth=ep.get("requires_auth", False),
                confidence=ep.get("confidence", Confidence.LOW.value),
                response_time_ms=ep.get("response_time_ms", 0.0),
                body_snippet=ep.get("body_snippet", ""),
            ))

        # 解析 dynamic_routes
        dynamic_routes = []
        for dr in data.get("dynamic_routes", []):
            dynamic_routes.append(DynamicRoute(
                pattern=dr.get("pattern", ""),
                method=dr.get("method", "POST"),
                sample_value=dr.get("sample_value", ""),
                inferred_from=dr.get("inferred_from", ""),
                confidence=dr.get("confidence", Confidence.MEDIUM.value),
            ))

        return cls(
            meta=ProfileMeta(
                version=meta_data.get("version", SCHEMA_VERSION),
                generated_at=meta_data.get("generated_at", ""),
                tool=meta_data.get("tool", ReconTool.AI_RECON.value),
                target_url=meta_data.get("target_url", ""),
                probe_duration_ms=meta_data.get("probe_duration_ms", 0),
                notes=meta_data.get("notes", ""),
            ),
            target=TargetInfo(
                base_url=target_data.get("base_url", ""),
                chat_api_url=target_data.get("chat_api_url", ""),
                model_name=target_data.get("model_name", ""),
                endpoint_type=target_data.get("endpoint_type", EndpointType.UNKNOWN.value),
                api_format=target_data.get("api_format", ApiFormat.RAW_JSON.value),
                target_type=target_data.get("target_type", TargetType.UNKNOWN.value),
                verify_ssl=target_data.get("verify_ssl", True),
                custom_headers=target_data.get("custom_headers", {}),
                request_timeout=target_data.get("request_timeout", 60),
                http_method=target_data.get("http_method", "POST"),
                content_type=target_data.get("content_type", "application/json"),
                framework=target_data.get("framework", "unknown"),
                framework_confidence=target_data.get("framework_confidence", "low"),
            ),
            auth=AuthInfo(
                type=auth_data.get("type", AuthType.NONE.value),
                login_url=auth_data.get("login_url", ""),
                login_method=auth_data.get("login_method", "POST"),
                login_payload=auth_data.get("login_payload", {}),
                session_cookie=auth_data.get("session_cookie", ""),
                cookies=auth_data.get("cookies", {}),
                custom_headers=auth_data.get("custom_headers", {}),
                csrf_token=auth_data.get("csrf_token", ""),
                bearer_token=auth_data.get("bearer_token", ""),
                token_refresh_url=auth_data.get("token_refresh_url", ""),
                notes=auth_data.get("notes", ""),
            ),
            api_endpoints=api_endpoints,
            dynamic_routes=dynamic_routes,
            spa_info=SpaInfo(
                is_spa=spa_data.get("is_spa", False),
                framework=spa_data.get("framework", SpaFramework.UNKNOWN.value),
                router_mode=spa_data.get("router_mode", RouterMode.UNKNOWN.value),
                js_bundle_urls=spa_data.get("js_bundle_urls", []),
                api_base_url=spa_data.get("api_base_url", ""),
                extracted_routes_count=spa_data.get("extracted_routes_count", 0),
                extracted_endpoints_count=spa_data.get("extracted_endpoints_count", 0),
                notes=spa_data.get("notes", ""),
            ),
            rate_limit=RateLimitInfo(
                has_rate_limit=rate_data.get("has_rate_limit", False),
                rate_limit_type=rate_data.get("rate_limit_type", "none"),
                rpm_limit=rate_data.get("rpm_limit"),
                tpm_limit=rate_data.get("tpm_limit"),
                recommended_concurrency=rate_data.get("recommended_concurrency", 3),
                recommended_rpm=rate_data.get("recommended_rpm", 30),
                avg_response_ms=rate_data.get("avg_response_ms", 0.0),
                p95_response_ms=rate_data.get("p95_response_ms", 0.0),
                total_429s=rate_data.get("total_429s", 0),
                details=rate_data.get("details", ""),
            ),
            raw_probe_data=RawProbeData(
                dns_records=raw_data.get("dns_records", {}),
                ssl_certificate=raw_data.get("ssl_certificate", {}),
                http_headers=raw_data.get("http_headers", {}),
                robots_txt=raw_data.get("robots_txt", ""),
                favicon_hash=raw_data.get("favicon_hash", ""),
                waf_detected=raw_data.get("waf_detected", ""),
                server_header=raw_data.get("server_header", ""),
                powered_by=raw_data.get("powered_by", ""),
                fingerprint_matches=raw_data.get("fingerprint_matches", []),
                homepage_title=raw_data.get("homepage_title", ""),
                homepage_text_snippet=raw_data.get("homepage_text_snippet", ""),
            ),
            artifacts=ReconArtifacts(
                har_file=artifacts_data.get("har_file", ""),
                screenshots=artifacts_data.get("screenshots", []),
                js_files_saved=artifacts_data.get("js_files_saved", []),
                login_flow_trace=artifacts_data.get("login_flow_trace", ""),
                errors=artifacts_data.get("errors", []),
                warnings=artifacts_data.get("warnings", []),
            ),
            model_probe=ModelProbeInfo(
                model_name=data.get("model_probe", {}).get("model_name", ""),
                strategy=data.get("model_probe", {}).get("strategy", ""),
                confidence=data.get("model_probe", {}).get("confidence", 0.0),
                framework=data.get("model_probe", {}).get("framework", "unknown"),
                framework_confidence=data.get("model_probe", {}).get("framework_confidence", "low"),
                endpoint_type=data.get("model_probe", {}).get("endpoint_type", EndpointType.UNKNOWN.value),
                recommended_concurrency=data.get("model_probe", {}).get("recommended_concurrency", 3),
                recommended_rpm=data.get("model_probe", {}).get("recommended_rpm", 30),
                avg_response_ms=data.get("model_probe", {}).get("avg_response_ms", 0.0),
                total_429s=data.get("model_probe", {}).get("total_429s", 0),
                discovered_endpoints=data.get("model_probe", {}).get("discovered_endpoints", []),
                all_attempts=data.get("model_probe", {}).get("all_attempts", []),
                errors=data.get("model_probe", {}).get("errors", []),
            ),
            js_sdk=JsSdkInfo(
                findings=data.get("js_sdk", {}).get("findings", []),
                total_scripts_scanned=data.get("js_sdk", {}).get("total_scripts_scanned", 0),
                total_matches=data.get("js_sdk", {}).get("total_matches", 0),
                extracted_api_urls=data.get("js_sdk", {}).get("extracted_api_urls", []),
                summary=data.get("js_sdk", {}).get("summary", ""),
            ),
            credentials=CredentialInfo(
                findings=data.get("credentials", {}).get("findings", []),
                total_scanned=data.get("credentials", {}).get("total_scanned", 0),
                critical_count=data.get("credentials", {}).get("critical_count", 0),
                high_count=data.get("credentials", {}).get("high_count", 0),
                summary=data.get("credentials", {}).get("summary", ""),
            ),
            waf=WafInfo(
                detections=data.get("waf", {}).get("detections", []),
                waf_count=data.get("waf", {}).get("waf_count", 0),
                summary=data.get("waf", {}).get("summary", ""),
                implications=data.get("waf", {}).get("implications", ""),
            ),
            rag_probe=RagInfo(
                is_rag=data.get("rag_probe", {}).get("is_rag", False),
                is_agent=data.get("rag_probe", {}).get("is_agent", False),
                is_multi_agent=data.get("rag_probe", {}).get("is_multi_agent", False),
                has_tools=data.get("rag_probe", {}).get("has_tools", False),
                has_memory=data.get("rag_probe", {}).get("has_memory", False),
                has_browsing=data.get("rag_probe", {}).get("has_browsing", False),
                target_architecture=data.get("rag_probe", {}).get("target_architecture", "unknown"),
                rag_confidence=data.get("rag_probe", {}).get("rag_confidence", 0.0),
                rag_data_sources=data.get("rag_probe", {}).get("rag_data_sources", []),
                agent_tools=data.get("rag_probe", {}).get("agent_tools", []),
                agent_tools_count=data.get("rag_probe", {}).get("agent_tools_count", 0),
                agent_delegation_detected=data.get("rag_probe", {}).get("agent_delegation_detected", False),
                agent_card_discovered=data.get("rag_probe", {}).get("agent_card_discovered", False),
                agent_card_url=data.get("rag_probe", {}).get("agent_card_url", ""),
                guardrail_detected=data.get("rag_probe", {}).get("guardrail_detected", False),
                guardrail_boundaries=data.get("rag_probe", {}).get("guardrail_boundaries", []),
                summary=data.get("rag_probe", {}).get("summary", ""),
            ),
            prompt_extraction=PromptExtractionInfo(
                system_prompt_fragments=data.get("prompt_extraction", {}).get("system_prompt_fragments", []),
                system_prompt_extracted=data.get("prompt_extraction", {}).get("system_prompt_extracted", False),
                system_prompt_confidence=data.get("prompt_extraction", {}).get("system_prompt_confidence", 0.0),
                tools_extracted=data.get("prompt_extraction", {}).get("tools_extracted", []),
                tools_count=data.get("prompt_extraction", {}).get("tools_count", 0),
                guardrail_rules=data.get("prompt_extraction", {}).get("guardrail_rules", []),
                guardrail_detected=data.get("prompt_extraction", {}).get("guardrail_detected", False),
                capabilities=data.get("prompt_extraction", {}).get("capabilities", []),
                knowledge_cutoff=data.get("prompt_extraction", {}).get("knowledge_cutoff", ""),
                model_identity=data.get("prompt_extraction", {}).get("model_identity", ""),
                key_prefixes=data.get("prompt_extraction", {}).get("key_prefixes", []),
                key_prefix_leaked=data.get("prompt_extraction", {}).get("key_prefix_leaked", False),
                extraction_success=data.get("prompt_extraction", {}).get("extraction_success", False),
                risk_score=data.get("prompt_extraction", {}).get("risk_score", 0.0),
                all_responses=data.get("prompt_extraction", {}).get("all_responses", []),
                errors=data.get("prompt_extraction", {}).get("errors", []),
                summary=data.get("prompt_extraction", {}).get("summary", ""),
                recommendations=data.get("prompt_extraction", {}).get("recommendations", []),
            ),
            behavior_map=BehaviorMapInfo(
                overall_security_score=data.get("behavior_map", {}).get("overall_security_score", 50.0),
                overall_label=data.get("behavior_map", {}).get("overall_label", "medium"),
                weakness_scores=data.get("behavior_map", {}).get("weakness_scores", []),
                critical_findings=data.get("behavior_map", {}).get("critical_findings", []),
                weakest_boundary=data.get("behavior_map", {}).get("weakest_boundary", ""),
                attack_vectors=data.get("behavior_map", {}).get("attack_vectors", []),
                target_attack_entry=data.get("behavior_map", {}).get("target_attack_entry", ""),
                bypass_feasibility=data.get("behavior_map", {}).get("bypass_feasibility", ""),
                bypass_methods=data.get("behavior_map", {}).get("bypass_methods", []),
                summary=data.get("behavior_map", {}).get("summary", ""),
                detailed_report=data.get("behavior_map", {}).get("detailed_report", ""),
            ),
            phase_reports=[
                PhaseReport(
                    phase_name=pr.get("phase_name", ""),
                    phase_id=pr.get("phase_id", ""),
                    status=pr.get("status", "skipped"),
                    findings_count=pr.get("findings_count", 0),
                    key_items=pr.get("key_items", []),
                    summary=pr.get("summary", ""),
                    raw_data=pr.get("raw_data", {}),
                )
                for pr in data.get("phase_reports", [])
            ],
        )

    @classmethod
    def from_json(cls, json_str: str) -> TargetProfile:
        """从 JSON 字符串反序列化"""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, filepath: str) -> TargetProfile:
        """从 JSON 文件加载"""
        with open(filepath, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ═══════════════════════════════════════════════════════════════════════════
# 验证函数
# ═══════════════════════════════════════════════════════════════════════════

def validate_profile(profile: TargetProfile) -> tuple[bool, list[str]]:
    """验证 TargetProfile 的完整性和一致性。
    
    返回 (is_valid, error_messages)。
    基础验证（必须字段非空），不阻止不完整的 profile。
    攻击阶段收到不完整的 profile 时可以降级处理。
    """
    errors = []

    # meta 验证
    if not profile.meta.target_url:
        errors.append("meta.target_url 为空 — 无法确定侦察目标")

    # target 验证
    if not profile.target.base_url:
        errors.append("target.base_url 为空 — 攻击阶段需要基础 URL")
    if not profile.target.chat_api_url:
        # chat_api_url 可以为空（表示未发现 chat 端点）
        errors.append("target.chat_api_url 为空 — 未发现 Chat API 端点，攻击阶段可能受限")

    # auth 验证
    if profile.auth.type != AuthType.NONE.value:
        if profile.auth.type == AuthType.COOKIE.value and not profile.auth.session_cookie:
            errors.append("auth.type=cookie 但 session_cookie 为空")
        if profile.auth.type == AuthType.BEARER.value and not profile.auth.bearer_token:
            errors.append("auth.type=bearer 但 bearer_token 为空")

    # api_endpoints 验证
    chat_endpoints = [ep for ep in profile.api_endpoints if ep.is_chat_endpoint]
    if not chat_endpoints and profile.api_endpoints:
        errors.append("api_endpoints 中发现端点但未标记任何 is_chat_endpoint=True")
    if not profile.api_endpoints:
        errors.append("api_endpoints 为空 — 未发现任何 API 端点")

    # SPA 一致性
    if profile.spa_info.is_spa and profile.spa_info.extracted_endpoints_count == 0:
        errors.append("spa_info.is_spa=True 但 extracted_endpoints_count=0 — 可能未完成 JS 提取")

    is_valid = len(errors) == 0
    return is_valid, errors


# ═══════════════════════════════════════════════════════════════════════════
# JSON Schema (用于外部工具校验)
# ═══════════════════════════════════════════════════════════════════════════

JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://ai-recon.dev/target_profile.schema.json",
    "title": "Target Profile",
    "description": SCHEMA_DESCRIPTION,
    "type": "object",
    "required": ["meta", "target"],
    "properties": {
        "meta": {
            "type": "object",
            "required": ["version", "target_url"],
            "properties": {
                "version": {"type": "string", "const": SCHEMA_VERSION},
                "generated_at": {"type": "string", "format": "date-time"},
                "tool": {"type": "string"},
                "target_url": {"type": "string", "format": "uri"},
                "probe_duration_ms": {"type": "integer"},
                "notes": {"type": "string"},
            },
        },
        "target": {
            "type": "object",
            "required": ["base_url"],
            "properties": {
                "base_url": {"type": "string"},
                "chat_api_url": {"type": "string"},
                "model_name": {"type": "string"},
                "endpoint_type": {
                    "type": "string",
                    "enum": [e.value for e in EndpointType],
                },
                "api_format": {
                    "type": "string",
                    "enum": [e.value for e in ApiFormat],
                },
                "target_type": {
                    "type": "string",
                    "enum": [e.value for e in TargetType],
                },
                "verify_ssl": {"type": "boolean"},
                "custom_headers": {"type": "object"},
                "request_timeout": {"type": "integer"},
                "http_method": {"type": "string"},
                "content_type": {"type": "string"},
            },
        },
        "auth": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": [e.value for e in AuthType],
                },
                "login_url": {"type": "string"},
                "login_method": {"type": "string"},
                "login_payload": {"type": "object"},
                "session_cookie": {"type": "string"},
                "cookies": {"type": "object"},
                "custom_headers": {"type": "object"},
                "csrf_token": {"type": "string"},
                "bearer_token": {"type": "string"},
                "token_refresh_url": {"type": "string"},
                "notes": {"type": "string"},
            },
        },
        "api_endpoints": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "full_url": {"type": "string"},
                    "method": {"type": "string"},
                    "status": {"type": "integer"},
                    "content_type": {"type": "string"},
                    "category": {"type": "string"},
                    "request_schema": {"type": "object"},
                    "response_schema": {"type": "object"},
                    "param_patterns": {"type": "object"},
                    "is_chat_endpoint": {"type": "boolean"},
                    "is_streaming": {"type": "boolean"},
                    "requires_auth": {"type": "boolean"},
                    "confidence": {"type": "string"},
                    "response_time_ms": {"type": "number"},
                    "body_snippet": {"type": "string"},
                },
            },
        },
        "dynamic_routes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "method": {"type": "string"},
                    "sample_value": {"type": "string"},
                    "inferred_from": {"type": "string"},
                    "confidence": {"type": "string"},
                },
            },
        },
        "spa_info": {
            "type": "object",
            "properties": {
                "is_spa": {"type": "boolean"},
                "framework": {"type": "string"},
                "router_mode": {"type": "string"},
                "js_bundle_urls": {"type": "array", "items": {"type": "string"}},
                "api_base_url": {"type": "string"},
                "extracted_routes_count": {"type": "integer"},
                "extracted_endpoints_count": {"type": "integer"},
                "notes": {"type": "string"},
            },
        },
        "rate_limit": {
            "type": "object",
            "properties": {
                "has_rate_limit": {"type": "boolean"},
                "rate_limit_type": {"type": "string"},
                "rpm_limit": {"type": ["integer", "null"]},
                "tpm_limit": {"type": ["integer", "null"]},
                "recommended_concurrency": {"type": "integer"},
                "recommended_rpm": {"type": "integer"},
                "avg_response_ms": {"type": "number"},
                "p95_response_ms": {"type": "number"},
                "total_429s": {"type": "integer"},
                "details": {"type": "string"},
            },
        },
        "raw_probe_data": {
            "type": "object",
            "properties": {
                "dns_records": {"type": "object"},
                "ssl_certificate": {"type": "object"},
                "http_headers": {"type": "object"},
                "robots_txt": {"type": "string"},
                "favicon_hash": {"type": "string"},
                "waf_detected": {"type": "string"},
                "server_header": {"type": "string"},
                "powered_by": {"type": "string"},
                "fingerprint_matches": {"type": "array", "items": {"type": "string"}},
                "homepage_title": {"type": "string"},
                "homepage_text_snippet": {"type": "string"},
            },
        },
        "artifacts": {
            "type": "object",
            "properties": {
                "har_file": {"type": "string"},
                "screenshots": {"type": "array", "items": {"type": "string"}},
                "js_files_saved": {"type": "array", "items": {"type": "string"}},
                "login_flow_trace": {"type": "string"},
                "errors": {"type": "array", "items": {"type": "string"}},
                "warnings": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}
