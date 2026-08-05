# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""集中式最优默认参数配置。

所有"开箱即用"的最佳实践参数都集中在此, 便于统一调优。
只有真正必须由用户填写的变量 (TARGET_URL) 以及可选凭证 (API_KEY)
才放在 .env 中; 其余所有运行参数的默认值都在 RuntimeDefaults 中定义。
.env 只需填一行 TARGET_URL 即可完成端到端侦察。

设计原则:
  - 不在此处存放任何机密或环境相关值
  - 所有耗时/规模/重试类参数在此预调优
  - 平台特定指纹在此维护 (OpenAI / Ollama / LM Studio)
  - .env 可选变量 (TARGET_TYPE / AUTH_TYPE / OUTPUT_DIR / EXPORT_FORMATS /
    ORG_DOMAINS / ALLOWED_HOSTS / DISALLOW_PATTERNS) 的默认值在 RuntimeDefaults 中
  - 运行时若 .env 未设置这些变量, 自动从 RuntimeDefaults 取值;
    若 ORG_DOMAINS 未设置则从 TARGET_URL 自动推导
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class HttpSettings:
    """HTTP 客户端全局最优参数。"""

    verify_ssl: bool = False          # 红队侦察场景通常跳过证书校验
    follow_redirects: bool = False     # 不自动跟随重定向, 由认证策略显式控制
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    max_connections: int = 32
    max_keepalive_connections: int = 16
    user_agent: str = "Mozilla/5.0 (compatible; OSAI-ReconPipeline/0.3.0)"


@dataclass(frozen=True)
class ProbeSettings:
    """探针执行最优参数。"""

    default_timeout: float = 30.0      # 单探针超时
    active_timeout: float = 10.0       # 主动探测 (chat-shape / model-list) 超时
    mcp_handshake_timeout: float = 15.0
    max_concurrency: int = 4           # 探针间并发上限
    chat_probe_path_limit: int = 5     # 每个 base URL 主动探测路径数上限
    retry_attempts: int = 2
    retry_backoff: float = 1.5


@dataclass(frozen=True)
class AuthSettings:
    """认证阶段最优参数。"""

    browser_headless: bool = True
    login_nav_timeout: float = 15.0
    auth_complete_timeout: float = 120.0   # 等待人工/二次验证完成
    wait_after_login: float = 2.0
    track_domain_transitions: bool = True
    # 探测阶段: 判定为"需要认证"的 HTTP 状态码
    auth_required_statuses: tuple[int, ...] = (401, 403)
    # 二次验证 (MFA/OTP) 常见 UI 信号
    mfa_keywords: tuple[str, ...] = (
        "verification code", "one-time", "otp", "2fa", "two-factor",
        "authenticator", "验证码", "二次验证", "短信验证码",
    )


@dataclass(frozen=True)
class TargetClassifySettings:
    """目标分类阶段最优参数。"""

    # 平台指纹: 命中即判定为 "model_platform" 而非 "llm_webapp"
    platform_signatures: dict[str, tuple[str, ...]] = field(default_factory=lambda: {
        "openai": ("/v1/", "/openai", "openai.com", "api.openai"),
        "ollama": ("/api/tags", "/api/generate", "/api/chat", "ollama"),
        "lm_studio": ("/v1/models", "lm-studio", "127.0.0.1:1234", "localhost:1234"),
        "vllm": ("/v1/completions", "vllm"),
        "llamacpp": ("/completion", "llama.cpp"),
        "textgen": ("/v1/generate", "text-generation-webui", "oobabooga"),
    })
    # 判定为 LLM Web 应用 (需认证) 的信号
    webapp_signatures: tuple[str, ...] = (
        "/chat", "/app", "/dashboard", "/workspace",
        "login", "signin", "sso", "auth",
    )
    # 认证拓扑探测路径
    auth_probe_paths: tuple[str, ...] = (
        "/login", "/signin", "/auth/login", "/sso", "/oauth",
        "/api/auth", "/account/login",
    )


@dataclass(frozen=True)
class PortScanSettings:
    """端口扫描阶段最优参数。"""

    # AI 服务常见端口 (覆盖 OpenAI/Ollama/LM Studio/vLLM/WebUI 等)
    ai_ports: tuple[int, ...] = (
        80, 443, 3000, 5000, 7860, 8000, 8080, 8181, 8888,
        11434, 1234, 8001, 8002, 8003, 8004, 8005, 8006, 8007,
        8008, 8009, 8010, 8501, 8696, 9000, 9090, 11433, 11435,
        20436, 32000, 32001,
    )
    timeout: float = 0.5


@dataclass(frozen=True)
class RuntimeDefaults:
    """运行时可由 .env 覆盖的参数默认值。

    这些参数不是机密, 不随环境变化, 适合集中在此维护。
    用户只需在 .env 中设置 TARGET_URL 即可启动侦察;
    如需微调以下任一参数, 可在 .env 中添加对应变量覆盖。
    """

    # 目标平台类型: auto (自动判断) / llm_webapp / model_platform
    target_type_hint: str = "auto"
    # 认证类型: auto (自动判断) / none / same_domain / cross_domain / otp / sliding / sms / qr
    auth_type_hint: str = "auto"
    # 报告输出目录
    output_dir: str = "outputs/reports"
    # 导出格式 (逗号分隔转元组)
    export_formats: tuple[str, ...] = ("json", "pyrit", "garak")
    # 禁止模式: 命中即拒绝 (逗号分隔转元组)
    disallow_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class PipelineSettings:
    """流水线全局最优参数。"""

    http: HttpSettings = field(default_factory=HttpSettings)
    probe: ProbeSettings = field(default_factory=ProbeSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    classify: TargetClassifySettings = field(default_factory=TargetClassifySettings)
    port_scan: PortScanSettings = field(default_factory=PortScanSettings)
    runtime: RuntimeDefaults = field(default_factory=RuntimeDefaults)

    # 默认下游侦察探针顺序 (端到端全覆盖)
    default_probe_order: tuple[str, ...] = (
        "LLMProbe",
        "RAGProbe",
        "AgentProbe",
        "MCPProbe",
        "EmbeddingProbe",
        "DOMProbe",
        "JSReconProbe",
        "NetworkProbe",
        "OpenAICompatProbe",
        "ErrorAnalyzerProbe",
        "SecurityHeaderProbe",
        "ResponseConsistencyProbe",
        "ConversationStateProbe",
        "TokenEstimatorProbe",
        "SubdomainProbe",
        "WAFDetectorProbe",
    )

    # 默认导出格式 (供下游消费)
    default_exporters: tuple[str, ...] = ("JSONExporter", "PyRITExporter", "GarakExporter")


# 全局单例 — 供各阶段直接引用
DEFAULT_SETTINGS = PipelineSettings()


def as_dict() -> dict[str, Any]:
    """返回配置的可变字典副本 (用于序列化/调试)。"""
    import dataclasses

    def _convert(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj):
            return {k.name: _convert(k.default) for k in dataclasses.fields(obj)}
        if isinstance(obj, tuple):
            return list(obj)
        return obj

    return _convert(DEFAULT_SETTINGS)
