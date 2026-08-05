# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段1: 目标分类。

职责 (对应需求):
  用户输入 URL 后, 系统自行判断:
    (A) 是基于 LLM 开发的 Web 应用, 是否需要认证 / 跨域 / 同域名认证,
        以及是否账户密码之外还有二次验证 (otp/2fa/sliding/sms/qr)
    (B) 还是 OpenAI 平台部署的模型 / Ollama / LM Studio 等自部署模型平台

本阶段组合两个 core 能力:
    - core.probes.target_url_classifier.TargetUrlClassifier (路径级平台/WebApp 指纹)
    - core.auth.auth_probe.AuthProbe (认证拓扑探测, 需浏览器)

输出: pipeline.models.TargetClassification
"""

from __future__ import annotations

import logging
from typing import Any

from pipeline.models import (
    PlatformVendor,
    TargetCategory,
    TargetClassification,
)
from pipeline.stages.base import PipelineStage

logger = logging.getLogger(__name__)


class ClassifyStage(PipelineStage):
    name = "classify"

    def __init__(self, settings: object | None = None) -> None:
        # settings 来自 config.settings.PipelineSettings (可选覆盖)
        self._settings = settings

    async def run(self, context: object) -> TargetClassification:
        from core.probes.target_url_classifier import TargetUrlClassifier
        from core.auth.auth_probe import AuthProbe
        from core.auth.browser_session import BrowserSession

        ctx = context  # type: ignore[assignment]
        target_url: str = ctx.target_url
        if not target_url:
            raise ValueError("context.target_url is empty; cannot classify target")

        # ── 步骤1: 路径级指纹 (无需浏览器) ──
        classifier = TargetUrlClassifier()
        path_signal = classifier.classify(target_url)
        # path_signal.primary_category ∈ {mcp, agent, rag, embedding, llm, auth, upload, unknown}

        # ── 步骤2: 平台厂商识别 (OpenAI/Ollama/LM Studio/...) ──
        vendor = self._detect_vendor(target_url)
        is_platform_by_vendor = vendor != PlatformVendor.UNKNOWN

        classification = TargetClassification()
        if ctx.target_type_hint and ctx.target_type_hint != "auto":
            classification.category = (
                TargetCategory.LLM_WEBAPP if ctx.target_type_hint == "llm_webapp"
                else TargetCategory.MODEL_PLATFORM
            )
            classification.detection_signals.append(f"user_hint={ctx.target_type_hint}")
        else:
            # 决策: 命中厂商指纹 → 模型平台; 否则按路径信号判定 Web 应用
            if is_platform_by_vendor:
                classification.category = TargetCategory.MODEL_PLATFORM
            elif path_signal.primary_category in ("llm", "embedding", "rag", "mcp", "agent"):
                # 直接命中 AI API 路径 (如 /v1/chat/completions) → 视为模型平台入口
                classification.category = TargetCategory.MODEL_PLATFORM
                classification.detection_signals.append(
                    f"api_path={path_signal.primary_category}"
                )
            elif path_signal.primary_category in ("auth", "upload"):
                classification.category = TargetCategory.LLM_WEBAPP
            else:
                # 未知路径: 默认当作 LLM Web 应用 (需进一步浏览器探测认证)
                classification.category = TargetCategory.LLM_WEBAPP

        if is_platform_by_vendor:
            classification.platform_vendor = vendor
            classification.detection_signals.append(f"vendor={vendor.value}")
        classification.detection_signals.append(
            f"path_classifier={path_signal.primary_category}"
        )
        classification.confidence = (
            0.8 if is_platform_by_vendor else
            0.6 if path_signal.primary_category != "unknown" else 0.2
        )

        # ── 步骤3: 浏览器认证拓扑探测 (WebApp / 未知时) ──
        if classification.category in (TargetCategory.LLM_WEBAPP, TargetCategory.UNKNOWN):
            try:
                session = BrowserSession()
                page = await session.launch_with_debug_port(headless=True)
                probe = AuthProbe()
                result = await probe.probe(page, target_url)
                classification.auth_topology = result.auth_type
                classification.requires_auth = result.auth_type != "none"
                classification.detection_signals.append(result.detection_reason)
                if result.login_url_detected:
                    classification.detection_signals.append(
                        f"login_url_detected={result.login_url_detected}"
                    )
                if result.domain_transitions:
                    classification.detection_signals.append(
                        "domain_transitions=" + " → ".join(result.domain_transitions)
                    )
                classification.confidence = max(classification.confidence, 0.85)
                # 二次验证: DOM + URL 双维度检测 (不阻塞)
                sf = await self._detect_second_factor(page)
                if sf != "none":
                    classification.second_factor = sf
                    classification.detection_signals.append(f"second_factor={sf}")
                # ★ 不关闭浏览器: 保留会话到 context 供 AuthStage / ReconStage 复用
                ctx.browser_session = session
                ctx.browser_page = page
                logger.info("[classify] browser session preserved for downstream stages")
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    f"classify: browser auth probe unavailable ({e}); "
                    "falling back to path signal only"
                )
                classification.requires_auth = False

        return classification

    # ── 辅助: 厂商识别 ──
    def _detect_vendor(self, url: str) -> PlatformVendor:
        low = (url or "").lower()

        # ── 公网 OpenAI 兼容平台 (域名级精确匹配) ──
        public_platforms = {
            PlatformVendor.ZHIPU: (
                "bigmodel.cn", "bigmodel", "zhipuai", "chatglm.cn",
                "open.bigmodel",
            ),
            PlatformVendor.DEEPSEEK: (
                "deepseek.com", "api.deepseek", "platform.deepseek",
            ),
            PlatformVendor.MOONSHOT: (
                "moonshot.cn", "api.moonshot", "platform.moonshot",
            ),
            PlatformVendor.BAICHUAN: (
                "baichuan-ai.com", "api.baichuan",
            ),
            PlatformVendor.QWEN: (
                "dashscope.aliyuncs.com", "dashscope", "tongyi.aliyun",
                "qwen", "bailian.aliyun",
            ),
            PlatformVendor.SPARK: (
                "spark-api.xf-yun.com", "xf-yun", "xinghuo",
            ),
            PlatformVendor.DOUBAO: (
                "ark.cn-beijing.volces.com", "ark.volces", "doubao",
            ),
            PlatformVendor.HUNYUAN: (
                "hunyuan.cloud.tencent.com", "tencentcloud-hunyuan",
            ),
            PlatformVendor.MINIMAX: (
                "api.minimax.chat", "minimax", "api.minimaxi",
            ),
        }
        for vendor, sigs in public_platforms.items():
            if any(s in low for s in sigs):
                return vendor

        # ── 本地/自部署平台 (主机端口级匹配) ──
        host_first = {
            PlatformVendor.OLLAMA: ("ollama", "/api/tags", "/api/generate", "/api/chat"),
            PlatformVendor.LM_STUDIO: ("lm-studio", "127.0.0.1:1234", "localhost:1234"),
            PlatformVendor.OPENAI: ("openai.com", "api.openai", "azure.openai"),
            PlatformVendor.VLLM: ("vllm",),
            PlatformVendor.LLAMACPP: ("llama.cpp", "llamacpp"),
            PlatformVendor.TEXTGEN: ("text-generation-webui", "oobabooga"),
        }
        for vendor, sigs in host_first.items():
            if any(s in low for s in sigs):
                return vendor

        # ── 内网部署检测 (私有 IP 段 + AI API 路径) ──
        if self._is_intranet_url(low):
            if "/v1/" in low or "/api/" in low:
                return PlatformVendor.INTRANET_LLM

        # ── 通用 OpenAI 兼容路径 ──
        if "/v1/" in low:
            return PlatformVendor.GENERIC
        if "openai" in low:
            return PlatformVendor.OPENAI
        return PlatformVendor.UNKNOWN

    @staticmethod
    def _is_intranet_url(url_lower: str) -> bool:
        """检测 URL 是否指向内网地址 (私有 IP / localhost / 内部域名)。"""
        import re
        # 私有 IP 段: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        private_ip_patterns = [
            r"https?://10\.\d+\.\d+\.\d+",
            r"https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
            r"https?://192\.168\.\d+\.\d+",
            r"https?://localhost\b",
            r"https?://127\.0\.0\.1\b",
            r"https?://0\.0\.0\.0\b",
        ]
        for pattern in private_ip_patterns:
            if re.search(pattern, url_lower):
                return True
        # 内部域名启发 (非权威, 仅辅助)
        intranet_hints = (".local", ".internal", ".intranet", ".corp", ".lan")
        for hint in intranet_hints:
            if hint in url_lower:
                return True
        return False

    async def _detect_second_factor(self, page: Any) -> str:
        """探测二次验证信号 (otp / 2fa / sliding / sms / qr) — DOM + URL 双维度。

        维度1: DOM 选择器检测 (更可靠, 优先)
        维度2: URL 关键词启发式 (兜底)
        不阻塞、不抛异常。
        """
        # 维度1: DOM 选择器检测
        dom_selectors: dict[str, list[str]] = {
            "otp": [
                'input[autocomplete="one-time-code"]',
                'input[name*="otp"]', 'input[name*="code"]',
                'input[name*="verification"]',
                'input[maxlength="6"][pattern*="[0-9]"]',
            ],
            "2fa": [
                'input[name*="authenticator"]',
                '[class*="totp"]', '[class*="authenticator"]',
            ],
            "qr": [
                '[class*="qrcode"]', '[class*="qr-code"]',
                'canvas[class*="qr"]', 'img[alt*="QR"]',
                'img[alt*="二维码"]',
            ],
            "sliding": [
                '[class*="slider"]', '[class*="slide-verify"]',
                'div[role="slider"]', '[class*="captcha-slider"]',
                '[class*="nc_iconfont"]',
            ],
            "sms": [
                'input[name*="sms"]', 'input[name*="phone"]',
                '[class*="sms-code"]', '[class*="phone-verify"]',
            ],
        }
        for factor, selectors in dom_selectors.items():
            for selector in selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        logger.debug(f"_detect_second_factor: DOM match '{selector}' → {factor}")
                        return factor
                except Exception:
                    continue

        # 维度2: URL 关键词检测 (兜底)
        keywords = {
            "otp": ("verification code", "one-time", "otp", "验证码", "一次性"),
            "2fa": ("2fa", "two-factor", "authenticator", "二次验证"),
            "sms": ("sms", "text message", "短信验证码"),
            "qr": ("scan", "qr code", "二维码", "扫码"),
            "sliding": ("slider", "slide", "拖动", "滑块"),
        }
        try:
            current_url = (page.url or "").lower()
            if any(k in current_url for kws in keywords.values() for k in kws):
                for factor, kws in keywords.items():
                    if any(k in current_url for k in kws):
                        return factor
        except Exception:
            pass
        return "none"
