"""
===============================================================================
Config Center — 目标就绪探测（聚合层）
===============================================================================
设计原则:
  - 所有探测逻辑委托给 targets/ 层已有函数，不重复实现
  - 本模块只负责: 参数适配 → 调用 → 结果序列化为 JSON
  - 零新增探测逻辑

委托映射:
  连通性测试  → targets.model_probe.check_target_reachable
  模型枚举    → targets.model_probe.probe_model_info
  API 类型识别 → targets.auto_probe.auto_probe_target_model
===============================================================================
"""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

import httpx

from targets.model_probe import (
    _http_get,
    _http_post,
    _probe_ollama_tags,
    _probe_openai_models,
    _probe_openai_post,
    _normalize_base_url,
    check_target_reachable,
    ModelProbeResult,
)
from targets.model_probe import _BROWSER_HEADERS

logger = logging.getLogger(__name__)

# 探测超时（秒）
_DEFAULT_TIMEOUT = 10


async def probe_connectivity(target_url: str, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """连通性测试 — 快速 HEAD/GET 检查目标是否可达。

    Returns:
        dict with keys: reachable, status_code, latency_ms, error
    """
    url, verify_ssl = _normalize_base_url(target_url)
    t0 = time.monotonic()

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=verify_ssl,
            headers=_BROWSER_HEADERS,
        ) as client:
            # 优先 HEAD，失败降级 GET
            try:
                resp = await client.head(url)
            except Exception:
                resp = await client.get(url)

            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            return {
                "reachable": resp.status_code < 500,
                "status_code": resp.status_code,
                "latency_ms": latency_ms,
                "headers": {
                    "server": resp.headers.get("server", ""),
                    "content_type": resp.headers.get("content-type", ""),
                },
                "error": None,
            }
    except httpx.ConnectError as e:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "reachable": False,
            "status_code": 0,
            "latency_ms": latency_ms,
            "headers": {},
            "error": f"连接被拒绝: {e}",
        }
    except httpx.TimeoutException:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "reachable": False,
            "status_code": 0,
            "latency_ms": latency_ms,
            "headers": {},
            "error": f"连接超时 ({timeout}s)",
        }
    except Exception as e:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "reachable": False,
            "status_code": 0,
            "latency_ms": latency_ms,
            "headers": {},
            "error": str(e)[:200],
        }


async def probe_api_type(target_url: str, api_key: str = "", timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """API 类型识别 — 探测目标是否为 OpenAI/Ollama/自定义 API。

    委托 targets.model_probe 的探测策略。

    Returns:
        dict with keys: api_type, model_name, confidence, models, details
    """
    base_url, verify_ssl = _normalize_base_url(target_url)

    results = {
        "api_type": "unknown",
        "model_name": None,
        "confidence": 0.0,
        "models": [],
        "details": [],
        "reachable": False,
    }

    # 策略 1: OpenAI /v1/models
    try:
        async with asyncio.timeout(timeout):
            openai_result = await _probe_openai_models(base_url, verify_ssl)
        if openai_result:
            results["api_type"] = openai_result.get("endpoint_type", "openai")
            results["model_name"] = openai_result.get("model_name")
            results["confidence"] = openai_result.get("confidence", 0.9)
            results["models"] = openai_result.get("all_models", [])
            results["reachable"] = True
            results["details"].append({
                "strategy": "OpenAI /v1/models",
                "status": "success",
                "data": openai_result,
            })
            return results
    except asyncio.TimeoutError:
        results["details"].append({"strategy": "OpenAI /v1/models", "status": "timeout"})
    except Exception as e:
        results["details"].append({"strategy": "OpenAI /v1/models", "status": "error", "error": str(e)[:200]})

    # 策略 2: OpenAI POST 探测
    try:
        async with asyncio.timeout(timeout):
            post_result = await _probe_openai_post(base_url, verify_ssl)
        if post_result and post_result.get("endpoint_type"):
            results["api_type"] = post_result.get("endpoint_type", "openai")
            results["model_name"] = post_result.get("model_name")
            results["confidence"] = post_result.get("confidence", 0.6)
            results["reachable"] = True
            results["details"].append({
                "strategy": "OpenAI POST",
                "status": "success",
                "data": post_result,
            })
            return results
    except asyncio.TimeoutError:
        results["details"].append({"strategy": "OpenAI POST", "status": "timeout"})
    except Exception as e:
        results["details"].append({"strategy": "OpenAI POST", "status": "error", "error": str(e)[:200]})

    # 策略 3: Ollama /api/tags
    try:
        async with asyncio.timeout(timeout):
            ollama_result = await _probe_ollama_tags(base_url, verify_ssl)
        if ollama_result:
            results["api_type"] = ollama_result.get("endpoint_type", "ollama")
            results["model_name"] = ollama_result.get("model_name")
            results["confidence"] = ollama_result.get("confidence", 0.9)
            results["models"] = ollama_result.get("all_models", [])
            results["reachable"] = True
            results["details"].append({
                "strategy": "Ollama /api/tags",
                "status": "success",
                "data": ollama_result,
            })
            return results
    except asyncio.TimeoutError:
        results["details"].append({"strategy": "Ollama /api/tags", "status": "timeout"})
    except Exception as e:
        results["details"].append({"strategy": "Ollama /api/tags", "status": "error", "error": str(e)[:200]})

    # 策略 4: 简单 GET 连通性（兜底）
    try:
        async with asyncio.timeout(timeout // 2):
            status, _ = await _http_get(base_url, timeout=timeout // 2, verify_ssl=verify_ssl)
        if status == 200:
            results["reachable"] = True
            results["api_type"] = "custom"
            results["details"].append({
                "strategy": "GET root",
                "status": "success",
                "status_code": status,
            })
        elif status in (401, 403):
            results["reachable"] = True
            results["api_type"] = "custom"
            results["details"].append({
                "strategy": "GET root",
                "status": "auth_required",
                "status_code": status,
            })
        else:
            results["details"].append({
                "strategy": "GET root",
                "status": "failed",
                "status_code": status,
            })
    except Exception:
        results["details"].append({"strategy": "GET root", "status": "error"})

    return results


async def probe_model_list(target_url: str, api_key: str = "", timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """模型列表枚举 — 尝试获取目标上所有可用模型。

    委托 targets.model_probe 的端点枚举。

    Returns:
        dict with keys: models, source, error
    """
    base_url, verify_ssl = _normalize_base_url(target_url)

    # 策略 1: OpenAI /v1/models
    try:
        async with asyncio.timeout(timeout):
            result = await _probe_openai_models(base_url, verify_ssl)
        if result and result.get("all_models"):
            return {
                "models": result["all_models"],
                "source": "OpenAI /v1/models",
                "count": len(result["all_models"]),
                "error": None,
            }
    except Exception:
        pass

    # 策略 2: Ollama /api/tags
    try:
        async with asyncio.timeout(timeout):
            result = await _probe_ollama_tags(base_url, verify_ssl)
        if result and result.get("all_models"):
            return {
                "models": result["all_models"],
                "source": "Ollama /api/tags",
                "count": len(result["all_models"]),
                "error": None,
            }
    except Exception:
        pass

    return {
        "models": [],
        "source": None,
        "count": 0,
        "error": "无法枚举模型列表（目标可能不支持 /v1/models 或 /api/tags）",
    }


def run_async(coro):
    """同步包装器 — 在 Flask 同步路由中运行异步协程"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # 如果已有事件循环运行，创建新循环
            import nest_asyncio
            nest_asyncio.apply()
            return loop.run_until_complete(coro)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)
