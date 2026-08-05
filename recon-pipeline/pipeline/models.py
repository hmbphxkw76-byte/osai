# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线阶段间传递的中间产物数据模型。

这些模型与 core/ 的数据模型 (ReconReport 等) 解耦:
  - PipelineContext: 贯穿所有阶段的共享上下文 (目标 / 配置 / 认证状态)
  - TargetClassification: 阶段1 输出 (目标分类结果)
  - AuthDecision: 阶段2 输出 (认证决策)
  - StageResult: 每个阶段的标准返回 (成功/失败/耗时/产物)
  - ReconContext / ReconResult: 阶段3 输出 (传递到 ReconOrchestrator)

下游 (ReconReport / exporters) 仍然消费最终的 ReconReport,
本模块只负责"阶段之间的解耦契约"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TargetCategory(str, Enum):
    """目标大类。

    对应需求中用户给 URL 后需要自动判断的两大类别:
      - LLM_WEBAPP:      基于 LLM 开发的 Web 应用 (可能需要认证 / 跨域 / 同域 / 二次验证)
      - MODEL_PLATFORM:  OpenAI 兼容 API / Ollama / LM Studio 等自部署模型平台
    """

    LLM_WEBAPP = "llm_webapp"
    MODEL_PLATFORM = "model_platform"
    UNKNOWN = "unknown"


class PlatformVendor(str, Enum):
    """已识别的模型平台厂商。"""

    OPENAI = "openai"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    VLLM = "vllm"
    LLAMACPP = "llamacpp"
    TEXTGEN = "textgen"
    # 公网 OpenAI 兼容平台
    ZHIPU = "zhipu"
    DEEPSEEK = "deepseek"
    MOONSHOT = "moonshot"
    BAICHUAN = "baichuan"
    QWEN = "qwen"
    SPARK = "spark"
    DOUBAO = "doubao"
    HUNYUAN = "hunyuan"
    MINIMAX = "minimax"
    # 内网/私有部署
    INTRANET_LLM = "intranet_llm"
    GENERIC = "generic"
    UNKNOWN = "unknown"


@dataclass
class TargetClassification:
    """阶段1 (分类) 的输出。

    Attributes:
        category: 目标大类 (LLM_WEBAPP / MODEL_PLATFORM / UNKNOWN)
        platform_vendor: 若为模型平台, 识别出的厂商
        requires_auth: 是否检测到需要认证 (基于认证探针/HTTP 401/403)
        auth_topology: 认证拓扑 (none/same_domain/cross_domain)
        second_factor: 是否检测到二次验证信号 (otp/2fa/sliding/sms/qr)
        detection_signals: 触发本分类的证据信号 (人类可读)
        confidence: 分类置信度 0.0~1.0
    """

    category: TargetCategory = TargetCategory.UNKNOWN
    platform_vendor: PlatformVendor = PlatformVendor.UNKNOWN
    requires_auth: bool = False
    auth_topology: str = "none"
    second_factor: str = "none"
    detection_signals: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "platform_vendor": self.platform_vendor.value,
            "requires_auth": self.requires_auth,
            "auth_topology": self.auth_topology,
            "second_factor": self.second_factor,
            "detection_signals": self.detection_signals,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class AuthDecision:
    """阶段2 (认证决策) 的输出。

    Attributes:
        strategy_name: 选用的认证策略 (NoneAuth/APIKeyAuth/PlaywrightAuth/CookieAuth/...)
        needs_browser: 是否需要浏览器 (Playwright) 才能认证
        needs_human: 是否需要人工介入 (二次验证/验证码/扫码)
        login_url: 同域登录页 URL (若适用)
        idp_url: 跨域 IdP URL (若适用)
        api_key_env: 从 .env 读取的 API Key 变量名 (若适用)
        reason: 决策依据
    """

    strategy_name: str = "NoneAuth"
    needs_browser: bool = False
    needs_human: bool = False
    login_url: str = ""
    idp_url: str = ""
    api_key_env: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_name": self.strategy_name,
            "needs_browser": self.needs_browser,
            "needs_human": self.needs_human,
            "login_url": self.login_url,
            "idp_url": self.idp_url,
            "api_key_env": self.api_key_env,
            "reason": self.reason,
        }


@dataclass
class StageResult:
    """所有阶段统一返回结构。

    提供一致的"成功/失败/跳过/产物"契约, 使 PipelineRunner 可以
    无差别地处理任意阶段 (解耦关键)。
    """

    stage_name: str
    status: str = "success"  # success | skipped | failed
    duration_seconds: float = 0.0
    error: str | None = None
    artifact: Any = None

    def to_dict(self) -> dict[str, Any]:
        artifact = self.artifact
        if hasattr(artifact, "to_dict"):
            artifact = artifact.to_dict()
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 3),
            "error": self.error,
            "artifact": artifact,
        }


@dataclass
class PipelineContext:
    """贯穿整条流水线的共享上下文。

    所有阶段从 context 读取输入, 写入各自的产物, 实现阶段间解耦。
    """

    target_url: str = ""
    target_type_hint: str = "auto"   # auto | llm_webapp | model_platform
    api_key: str = ""
    auth_type_hint: str = "auto"      # auto | none | same_domain | cross_domain | otp | ...
    org_domains: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    disallow_patterns: list[str] = field(default_factory=list)
    output_dir: str = "outputs/reports"
    export_formats: list[str] = field(default_factory=lambda: ["json", "pyrit", "garak"])

    # 阶段产物 (按阶段填充)
    classification: TargetClassification | None = None
    auth_decision: AuthDecision | None = None

    # 流水线级浏览器会话 (贯穿 classify → auth → recon, 最后由 recon 关闭)
    browser_session: Any | None = None
    browser_page: Any | None = None
    auth_state: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_type_hint": self.target_type_hint,
            "api_key_set": bool(self.api_key),
            "auth_type_hint": self.auth_type_hint,
            "org_domains": self.org_domains,
            "allowed_hosts": self.allowed_hosts,
            "disallow_patterns": self.disallow_patterns,
            "output_dir": self.output_dir,
            "export_formats": self.export_formats,
            "classification": self.classification.to_dict() if self.classification else None,
            "auth_decision": self.auth_decision.to_dict() if self.auth_decision else None,
            "has_browser_session": self.browser_session is not None,
            "has_browser_page": self.browser_page is not None,
            "has_auth_state": self.auth_state is not None,
        }
