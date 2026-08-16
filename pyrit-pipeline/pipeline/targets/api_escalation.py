# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""API Escalation — 攻击中获得 API 信息后自动切换模式 (P3).

当攻击过程中从 Agent 应用响应中发现了后端模型的 API 端点、Key、模型名称时,
自动切换到 API 直连模式, 实现深度攻击.

流程:
  1. _extract_api_credentials_from_response: 从攻击响应中提取 API 信息
  2. _verify_captured_api: 向捕获的 endpoint 发送轻量级测试请求
  3. _switch_to_api_direct_mode: 创建 OpenAIChatTarget 并注册为新的 Target

学术依据:
  - Greshake et al. (arXiv:2302.12173): 间接注入 (XPIA) 可导致 Agent 应用泄露后端配置
  - OWASP LLM Top 10 (2025) LLM06: 敏感信息泄露
  - MITRE ATT&CK T1552: 凭据存储不当
  - Perez et al. (arXiv:2302.04752): 忽略先前指令可泄露系统提示中的 API 信息

> **日期**: 2026-8-16
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── 正则模式 ──

# URL 检测: 匹配 OpenAI 兼容 API 端点
_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>,\)\]]+/(?:v1/)?(?:chat/completions|responses|embeddings|models)',
    re.IGNORECASE,
)

# API Key 检测: sk-xxx (支持连字符) 或 Bearer xxx
_KEY_PATTERN = re.compile(
    r"(sk-[a-zA-Z0-9\-]{20,}|Bearer\s+[a-zA-Z0-9._\-]{20,})",
    re.IGNORECASE,
)

# 模型名检测: OpenAI/Anthropic/DeepSeek/Llama/Qwen/Phi
# 支持 JSON 格式 ("model":"gpt-4o") 和自然语言格式 (model is gpt-4o / model: "deepseek-chat")
_MODEL_PATTERN = re.compile(
    r'(?:"model"\s*:\s*"|\bmodel\s*(?:is|:)\s*"?)('
    r'gpt-4o|gpt-4o-mini|gpt-4|gpt-3\.5-turbo|gpt-4-turbo'
    r'|claude-3[^"\s]*|claude-2[^"\s]*'
    r'|deepseek[^"\s]*|deepseek-chat|deepseek-coder'
    r'|llama[^"\s]*|llama-2[^"\s]*|llama-3[^"\s]*'
    r'|qwen[^"\s]*|qwen-2[^"\s]*|qwen2[^"\s]*'
    r'|phi-4[^"\s]*|phi-3[^"\s]*'
    r'|o1[^"\s]*|o3[^"\s]*'
    r')',
    re.IGNORECASE,
)

# 环境变量风格检测: OPENAI_API_KEY=xxx
_ENV_KEY_PATTERN = re.compile(
    r'(?:OPENAI_API_KEY|API_KEY|OPENAI_CHAT_KEY)\s*[=:]\s*["\']?(sk-[a-zA-Z0-9\-]{20,})["\']?',
    re.IGNORECASE,
)


def extract_api_credentials_from_response(response_text: str) -> dict[str, Any] | None:
    """P3: 从攻击响应中提取后端 API 信息.

    分析响应文本, 检测是否包含后端 API 的端点、Key、模型名称.
    常见泄露来源:
      - 系统提示泄露 (system prompt 中包含 API 配置)
      - 错误信息泄露 (debug 模式下返回后端调用栈)
      - 配置文件泄露 (Agent 应用暴露 /config 或 /env 端点)

    Args:
        response_text: 攻击响应文本.

    Returns:
        包含 endpoint, api_key, model_name 的字典, 或 None (未检测到).
    """
    url_match = _URL_PATTERN.search(response_text)
    key_match = _KEY_PATTERN.search(response_text)
    env_key_match = _ENV_KEY_PATTERN.search(response_text)
    model_match = _MODEL_PATTERN.search(response_text)

    # 优先使用环境变量风格的 Key (更可靠)
    api_key = None
    if env_key_match:
        api_key = env_key_match.group(1)
    elif key_match:
        api_key = key_match.group(1)
        # 清理 Bearer 前缀
        if api_key.lower().startswith("bearer "):
            api_key = api_key[7:]

    # URL
    endpoint = url_match.group() if url_match else None

    # 模型名
    model_name = model_match.group(1) if model_match else None

    # 至少需要 endpoint + api_key 才算有效
    if endpoint and api_key:
        result: dict[str, Any] = {
            "endpoint": endpoint,
            "api_key": api_key,
            "model_name": model_name or "auto",
            "source": "attack_response",
            "confidence": "high",
        }
        logger.info(
            f"P3: API credentials extracted from response — "
            f"endpoint={endpoint}, model={model_name or 'auto'}"
        )
        return result

    # 仅检测到部分信息 — 低置信度
    if endpoint or api_key:
        return {
            "endpoint": endpoint or "",
            "api_key": api_key or "",
            "model_name": model_name or "",
            "source": "attack_response_partial",
            "confidence": "low",
        }

    return None


async def verify_captured_api(captured: dict[str, Any]) -> bool:
    """P3: 验证捕获的 API 信息是否有效.

    向捕获的 endpoint 发送轻量级测试请求 (models 列表),
    验证 endpoint + api_key 是否可用.

    Args:
        captured: extract_api_credentials_from_response 返回的字典.

    Returns:
        True 如果 API 可用, False 如果不可用.
    """
    try:
        import httpx

        endpoint = captured.get("endpoint", "")
        api_key = captured.get("api_key", "")

        if not endpoint or not api_key:
            return False

        # 构建 models 列表请求 (轻量级, 不消耗 token)
        # 从 /v1/chat/completions 提取 base URL
        base_url = endpoint.rstrip("/")
        if "/chat/completions" in base_url:
            base_url = base_url.rsplit("/chat/completions", 1)[0]
        elif "/responses" in base_url:
            base_url = base_url.rsplit("/responses", 1)[0]
        elif "/embeddings" in base_url:
            base_url = base_url.rsplit("/embeddings", 1)[0]

        models_url = f"{base_url}/models"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                models_url,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code in (200, 401):
                # 200 = 可用, 401 = endpoint 存在但 key 无效
                if resp.status_code == 200:
                    logger.info(f"P3: API verification succeeded — {models_url}")
                    return True
                else:
                    logger.warning(f"P3: API endpoint exists but key invalid — {models_url}")
                    return False
            else:
                logger.warning(
                    f"P3: API verification failed — {resp.status_code} from {models_url}"
                )
                return False

    except Exception as e:
        logger.warning(f"P3: API verification error: {e}")
        return False


async def switch_to_api_direct_mode(
    ctx: Any,
    captured_api: dict[str, Any],
) -> bool:
    """P3: 从 Agent Proxy Bridge 切换到 API 直连模式.

    使用捕获的 API 信息创建新的 OpenAIChatTarget,
    注册为新的 adversarial_chat + scoring_target (或全量切换为 default + objective).

    策略:
      - 默认: 将捕获的 API 注册为新的 adversarial + scorer, 原 Burp 保持为 objective
      - 全量切换 (--auto-escalate): 将捕获的 API 注册为 default + objective

    Args:
        ctx: PipelineContext (含 metadata).
        captured_api: 含 endpoint, api_key, model_name 的字典.

    Returns:
        True 如果切换成功.
    """
    try:
        from pyrit.prompt_target import OpenAIChatTarget
        from pyrit.registry import TargetRegistry

        endpoint = captured_api.get("endpoint", "")
        api_key = captured_api.get("api_key", "")
        model_name = captured_api.get("model_name", "auto")

        if not endpoint or not api_key:
            return False

        # 构建 OpenAIChatTarget 参数
        kwargs: dict[str, Any] = {
            "endpoint": endpoint,
            "api_key": api_key,
        }
        if model_name and model_name != "auto":
            kwargs["model_name"] = model_name

        new_target = OpenAIChatTarget(**kwargs)

        # 注册到 TargetRegistry
        registry = TargetRegistry.get_registry_singleton()

        # 全量切换: 将捕获的 API 注册为 default + objective
        # 原 Burp Target 降级为辅助
        registry.instances.register(
            instance=new_target,
            name="captured_api_target",
            tags={
                "target_type": "OpenAIChatTarget",
                "default": {},
                "default_objective_target": {},
                "scorer": {},
                "adversarial_chat": {},
                "captured": {},
            },
        )

        # 更新 Context metadata
        ctx.metadata["captured_api"] = captured_api
        ctx.metadata["api_escalation_mode"] = True
        ctx.metadata["escalated_endpoint"] = endpoint
        ctx.metadata["escalated_model"] = model_name

        print("  [P3] API 直连模式已启用:")
        print(f"    endpoint: {endpoint}")
        print(f"    model: {model_name}")
        print(f"    source: {captured_api.get('source', 'unknown')}")
        print(f"    confidence: {captured_api.get('confidence', 'unknown')}")

        logger.info(
            f"P3: Escalated to API direct mode — endpoint={endpoint}, model={model_name}"
        )
        return True

    except Exception as e:
        logger.error(f"P3: Failed to switch to API direct mode: {e}")
        return False


async def process_attack_response_for_api(
    ctx: Any,
    response_text: str,
) -> bool:
    """P3: 处理攻击响应, 检测是否包含 API 信息.

    在每次攻击后调用此函数, 检测响应中是否泄露了后端 API 信息.
    如果检测到且验证通过, 自动切换到 API 直连模式.

    Args:
        ctx: PipelineContext.
        response_text: 攻击响应文本.

    Returns:
        True 如果检测到 API 信息并成功切换模式.
    """
    # 如果已经升级, 不再检测
    if ctx.metadata.get("api_escalation_mode"):
        return False

    # 提取 API 信息
    captured = extract_api_credentials_from_response(response_text)
    if captured is None or captured.get("confidence") != "high":
        return False

    # 切换到 API 直连模式
    auto_escalate = getattr(ctx.args, "auto_escalate", False)
    if auto_escalate:
        # 验证 API 可用性 (仅在自动切换时验证)
        verified = await verify_captured_api(captured)
        if not verified:
            print(f"  [P3] 检测到 API 信息但验证失败: {captured.get('endpoint', '')}")
            return False
        return await switch_to_api_direct_mode(ctx, captured)
    else:
        # 仅记录, 不验证, 不自动切换
        ctx.metadata["detected_api_info"] = captured
        print("  [P3] 检测到后端 API 信息 (使用 --auto-escalate 自动切换):")
        print(f"    endpoint: {captured.get('endpoint', '')}")
        print(f"    model: {captured.get('model_name', '')}")
        return False
