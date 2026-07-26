# -*- coding: utf-8 -*-
"""
Recon Engine
============

统一侦察引擎：
  - 目标类型自动推断（auto / spa / web_ui / api）
  - 凭据解析与认证注入
  - 分发到对应侦察器
  - 返回标准化 TargetProfile
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from src.network import TrafficAnalyzer

from .target_profile import TargetProfile

logger = logging.getLogger(__name__)


class ReconEngine:
    """统一侦察引擎"""

    DEFAULT_CONFIG = {
        "browser_connection": {
            "wait_until": "domcontentloaded",
            "timeout": 30000,
            "ignore_https_errors": True,
            "post_load_wait": 2,
        },
        "spa_config": {},
    }

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        credential_manager: Optional[Any] = None,
    ):
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.credential_manager = credential_manager

    async def probe(
        self,
        url: str,
        target_type: str = "auto",
        headless: bool = False,
        auth_profile: Optional[Any] = None,
        storage_state: str = "",
    ) -> TargetProfile:
        """
        统一侦察入口。

        Args:
            url: 目标 URL
            target_type: auto / spa / web_ui / api
            headless: 是否无头
            auth_profile: 显式认证配置
            storage_state: 浏览器状态文件

        Returns:
            TargetProfile
        """
        logger.info("Starting recon for: %s (type=%s)", url, target_type)

        # 1. 解析凭据
        if auth_profile is None and self.credential_manager:
            auth_profile = self.credential_manager.resolve_or_none(url)

        # 2. 自动判断目标类型
        if target_type == "auto":
            target_type = await self._infer_target_type(url)
            logger.info("Auto inferred target type: %s", target_type)

        # 3. 分类型侦察
        if target_type == "api":
            return await self._probe_api(url, auth_profile)

        # web_ui / spa 统一走浏览器侦察
        from src.browser_manager import BrowserManager

        browser = BrowserManager(
            headless=headless,
            auth_profile=auth_profile,
            storage_state_path=storage_state,
        )
        try:
            await browser.start(url, connection=self.config.get("browser_connection", {}))
            spa_recon = SPARecon(browser, config=self.config.get("spa_config", {}))
            profile = await spa_recon.run(url)
            profile.target_type = target_type
            return profile
        finally:
            await browser.close()

    async def _infer_target_type(self, url: str) -> str:
        """根据 URL / 元数据推断目标类型"""
        lower = url.lower()
        if any(kw in lower for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/chat/completions"]):
            return "api"
        return "spa"

    async def _probe_api(
        self,
        url: str,
        auth_profile: Optional[Any],
    ) -> TargetProfile:
        """纯 API 目标侦察（支持 OpenAI 兼容 / Ollama / 通用 LLM）"""
        profile = TargetProfile(target=url, target_type="api")
        from src.auth import extract_domain_from_url

        profile.fingerprint.domain = extract_domain_from_url(url)

        headers = {"Content-Type": "application/json"}
        if auth_profile and auth_profile.headers.get("Authorization"):
            headers["Authorization"] = auth_profile.headers["Authorization"]
        if auth_profile and auth_profile.raw_cookies:
            headers["Cookie"] = auth_profile.raw_cookies

        try:
            async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
                await self._probe_models_endpoint(client, url, headers, profile)
                await self._probe_chat_endpoint(client, url, headers, profile)
        except Exception as e:
            logger.warning("API probe failed: %s", str(e)[:120])

        profile.risk_level = profile.classify_risk()
        return profile

    async def _probe_models_endpoint(
        self,
        client: Any,
        url: str,
        headers: Dict[str, str],
        profile: TargetProfile,
    ) -> None:
        """探测 /models 或 /api/tags 模型列表端点"""
        candidates = []
        if "/api/" in url.lower():
            candidates.append(url.rstrip("/").rsplit("/", 1)[0] + "/tags")
        candidates.append(url.rstrip("/") + "/models")

        for models_url in candidates:
            try:
                resp = await client.get(models_url, headers=headers)
                if resp.status_code == 200:
                    api_type = "ollama_tags" if "/api/tags" in models_url else "openai_models"
                    profile.fingerprint.llm_api_endpoints.append(
                        {
                            "url": models_url,
                            "method": "GET",
                            "response_status": resp.status_code,
                            "api_type": api_type,
                        }
                    )
                    profile.add_entry_point(
                        entry_type="api",
                        url=models_url,
                        api_type=api_type,
                        score=0.9,
                    )
                    break
            except Exception:
                continue

    async def _probe_chat_endpoint(
        self,
        client: Any,
        url: str,
        headers: Dict[str, str],
        profile: TargetProfile,
    ) -> None:
        """探测聊天/生成端点，自动适配 Ollama 与 OpenAI 兼容格式"""
        lower_url = url.lower()
        is_ollama = "/api/" in lower_url

        if is_ollama:
            if "/api/generate" in lower_url:
                probe_payload = {"model": "llama2", "prompt": "hi", "stream": False}
            else:
                probe_payload = {"model": "llama2", "messages": [{"role": "user", "content": "hi"}], "stream": False}
        else:
            probe_payload = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]}

        try:
            resp = await client.post(url, headers=headers, json=probe_payload)
            analyzer = TrafficAnalyzer()
            entry = {
                "url": url,
                "method": "POST",
                "request_body": str(probe_payload),
                "response_body": resp.text[:5000],
                "response_headers": dict(resp.headers),
            }
            analysis = analyzer.analyze_request(entry)
            if analysis["is_llm_api"] or (is_ollama and resp.status_code == 200):
                profile.fingerprint.llm_api_endpoints.append(
                    {
                        "url": url,
                        "method": "POST",
                        "response_status": resp.status_code,
                        "api_type": analysis.get("api_type", "ollama" if is_ollama else "generic_llm"),
                        "model_name": analysis.get("model_name", ""),
                    }
                )
                profile.add_entry_point(
                    entry_type="api",
                    url=url,
                    api_type=analysis.get("api_type", "ollama" if is_ollama else "generic_llm"),
                    model_name=analysis.get("model_name", ""),
                    score=0.95,
                )
        except Exception as e:
            logger.warning("Chat endpoint probe failed: %s", str(e)[:120])
