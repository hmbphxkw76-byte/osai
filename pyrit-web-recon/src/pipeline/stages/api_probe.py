# -*- coding: utf-8 -*-
"""
阶段 3（API 目标分支）：API 探测

针对纯 API 目标（Ollama / OpenAI 兼容 / 通用 LLM API）进行探测：
  - 探测 /models 或 /api/tags 模型列表端点
  - 探测聊天/生成端点
  - 将结果写入 context.config["api_probe_result"] 供 AnalysisStage 消费
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from src.auth import AuthProfile
from src.network import TrafficAnalyzer
from src.utils import truncate_error, truncate_stage_error

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class APIProbeStage(PipelineStage):
    """API 探测阶段"""

    name = "api_probe"
    description = "探测 LLM API 端点（API 目标）"

    async def run(self, context: PipelineContext) -> StageResult:
        # 仅在 API 目标或显式启用时执行
        if context.target_type not in ("api",) and not self._config(context, "force_api_probe", False):
            return StageResult(
                success=True,
                skipped=True,
                message="非 API 目标，跳过 API 探测",
                data={},
            )

        auth_profile = context.auth_profile
        headers = self._build_headers(auth_profile)

        api_probe_cfg = self._config(context, "api_probe", {})
        network_cfg = self._config(context, "network", {})
        httpx_timeout = api_probe_cfg.get("httpx_timeout", 20.0)
        response_body_limit = api_probe_cfg.get("response_body_limit", 5000)

        entries: List[Dict[str, Any]] = []
        model_name = ""

        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx_timeout) as client:
                models_entry = await self._probe_models_endpoint(
                    client, context.target_url, headers, response_body_limit=response_body_limit, network_cfg=network_cfg
                )
                if models_entry:
                    entries.append(models_entry)

                chat_entry = await self._probe_chat_endpoint(
                    client,
                    context.target_url,
                    headers,
                    api_probe_cfg=api_probe_cfg,
                    response_body_limit=response_body_limit,
                    network_cfg=network_cfg,
                )
                if chat_entry:
                    entries.append(chat_entry)
                    model_name = chat_entry.get("model_name", "")
        except Exception as exc:
            logger.exception("API probe failed")
            return StageResult(
                success=False,
                message=f"API 探测失败: {truncate_stage_error(str(exc), context.config)}",
                data={},
            )

        context.config["api_probe_result"] = {
            "entries": entries,
            "model_name": model_name,
        }

        llm_entries = [e for e in entries if e.get("is_llm_api")]
        return StageResult(
            success=True,
            message=f"API 探测完成: 发现 {len(llm_entries)} 个 LLM 端点",
            data={
                "endpoints": [e.get("url") for e in entries],
                "model_name": model_name,
                "llm_endpoints_count": len(llm_entries),
            },
        )

    def _build_headers(self, auth_profile: Optional[AuthProfile]) -> Dict[str, str]:
        """构建 API 探测请求头"""
        headers = {"Content-Type": "application/json"}
        if not auth_profile:
            return headers
        if auth_profile.headers.get("Authorization"):
            headers["Authorization"] = auth_profile.headers["Authorization"]
        if auth_profile.raw_cookies:
            headers["Cookie"] = auth_profile.raw_cookies
        return headers

    async def _probe_models_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
        response_body_limit: int = 5000,
        network_cfg: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """探测 /models 或 /api/tags 端点"""
        candidates = []
        if "/api/" in url.lower():
            candidates.append(url.rstrip("/").rsplit("/", 1)[0] + "/tags")
        candidates.append(url.rstrip("/") + "/models")

        for models_url in candidates:
            try:
                resp = await client.get(models_url, headers=headers)
                if resp.status_code != 200:
                    continue
                api_type = "ollama_tags" if "/api/tags" in models_url else "openai_models"
                entry = {
                    "timestamp": 0,
                    "url": models_url,
                    "method": "GET",
                    "resource_type": "xhr",
                    "request_headers": headers,
                    "request_body": "",
                    "response_status": resp.status_code,
                    "response_headers": dict(resp.headers),
                    "response_body": resp.text[:response_body_limit],
                }
                analyzer = TrafficAnalyzer(config=network_cfg)
                analysis = analyzer.analyze_request(entry)
                entry.update(analysis)
                entry["api_type"] = api_type
                entry["is_llm_api"] = True
                return entry
            except Exception:
                continue
        return None

    async def _probe_chat_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
        api_probe_cfg: Dict[str, Any],
        response_body_limit: int = 5000,
        network_cfg: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """探测聊天/生成端点"""
        lower_url = url.lower()
        is_ollama = "/api/" in lower_url

        ollama_model = api_probe_cfg.get("ollama_model", "llama2")
        openai_model = api_probe_cfg.get("openai_model", "gpt-3.5-turbo")
        probe_prompt = api_probe_cfg.get("probe_prompt", "hi")

        if is_ollama:
            if "/api/generate" in lower_url:
                probe_payload = {"model": ollama_model, "prompt": probe_prompt, "stream": False}
            else:
                probe_payload = {
                    "model": ollama_model,
                    "messages": [{"role": "user", "content": probe_prompt}],
                    "stream": False,
                }
        else:
            probe_payload = {"model": openai_model, "messages": [{"role": "user", "content": probe_prompt}]}

        try:
            resp = await client.post(url, headers=headers, json=probe_payload)
            entry = {
                "timestamp": 0,
                "url": url,
                "method": "POST",
                "resource_type": "xhr",
                "request_headers": headers,
                "request_body": str(probe_payload),
                "response_status": resp.status_code,
                "response_headers": dict(resp.headers),
                "response_body": resp.text[:response_body_limit],
            }
            analyzer = TrafficAnalyzer(config=network_cfg)
            analysis = analyzer.analyze_request(entry)
            entry.update(analysis)
            if not analysis["is_llm_api"] and is_ollama and resp.status_code == 200:
                entry["is_llm_api"] = True
                entry["api_type"] = "ollama"
            return entry
        except Exception as exc:
            logger.warning("Chat endpoint probe failed: %s", truncate_error(str(exc), context.config))
        return None
