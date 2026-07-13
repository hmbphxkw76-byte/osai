"""模型指纹识别（AI-300 Ch2.3 Model Fingerprinting）。

实现 AI-300 课程中的八种指纹识别技术：
  1. 直接身份探测：询问模型身份
  2. 矛盾测试：用错误身份断言诱导纠正
  3. 知识截止日期测试：询问近期事件
  4. 行为特征测试：代码生成风格、响应详细程度
  5. 上下文窗口测试：标记注入 + 溢出测试
  6. 能力边界测试：算术能力、推理能力
  7. 确定性测试：多次相同请求的响应一致性（TCM temperature_probe.py 融合）
  8. 推理引擎指纹：识别 vLLM/TGI/OpenWebUI/litellm 等推理引擎

对齐 OWASP LLM Top 10: LLM07 (System Prompt Leak)
"""
from __future__ import annotations

import json
import re
import statistics
import time
from typing import Any

from redteam.core.http_client import send_chat, send_get
from redteam.core.models import (
    AuthContext, ModelFingerprint,
)

ENGINE_FINGERPRINTS = {
    "vllm": {
        "headers": {
            "x-vllm-version": r"^\d+\.\d+\.\d+$",
            "x-vllm-build": r".*",
        },
        "endpoints": ["/v1/models"],
        "response_patterns": [
            re.compile(r'"backend"\s*:\s*"vllm"', re.DOTALL),
            re.compile(r'"vllm"\s*:\s*\{'),
        ],
        "version_extract": r"x-vllm-version:\s*(\d+\.\d+\.\d+)"
    },
    "tgi": {
        "headers": {
            "x-transformers-version": r".*",
            "x-tgi-version": r".*",
        },
        "endpoints": ["/generate", "/generate_stream", "/v1/models"],
        "response_patterns": [
            re.compile(r'"transformers"\s*:\s*\{'),
            re.compile(r'"tgi"\s*:\s*"[^"]+"'),
        ],
        "version_extract": r"x-transformers-version:\s*(\S+)"
    },
    "openwebui": {
        "headers": {
            "x-openwebui-version": r"^\d+\.\d+\.\d+$",
            "x-openwebui-build": r".*",
        },
        "endpoints": ["/api/v1/users", "/v1/models"],
        "response_patterns": [
            re.compile(r'"openwebui"\s*:\s*\{'),
            re.compile(r'"openwebui_version"\s*:'),
        ],
        "version_extract": r"x-openwebui-version:\s*(\d+\.\d+\.\d+)"
    },
    "litellm": {
        "headers": {
            "x-litellm-version": r".*",
            "litellm-version": r".*",
        },
        "endpoints": ["/v1/models"],
        "response_patterns": [
            re.compile(r'"litellm"\s*:\s*\{'),
            re.compile(r'"litellm_version"\s*:'),
        ],
        "version_extract": r"(?:x-litellm-version|litellm-version):\s*(\S+)"
    },
    "ollama": {
        "headers": {
            "x-ollama-version": r".*",
            "ollama-version": r".*",
        },
        "endpoints": ["/api/tags", "/api/version", "/v1/models"],
        "response_patterns": [
            re.compile(r'"ollama"\s*:\s*\{'),
            re.compile(r'"ollama_version"\s*:'),
        ],
        "version_extract": r"(?:x-ollama-version|ollama-version):\s*(\S+)"
    },
    "langserve": {
        "headers": {
            "x-langserve-version": r".*",
            "langserve-version": r".*",
        },
        "endpoints": ["/playground", "/v1/models"],
        "response_patterns": [
            re.compile(r'"langserve"\s*:\s*\{'),
            re.compile(r'"langserve_version"\s*:'),
        ],
        "version_extract": r"(?:x-langserve-version|langserve-version):\s*(\S+)"
    },
}


def fingerprint_model(
    url: str,
    auth: AuthContext | None = None,
    timeout: float = 8.0,
    rate_limit_ms: int = 0,
    determinism_requests: int = 3,
) -> ModelFingerprint:
    """模型指纹识别（AI-300 Ch2.3 完整实现）。

    七种指纹识别技术：
      1. 直接身份探测：询问模型身份
      2. 矛盾测试：用错误身份断言诱导纠正
      3. 知识截止日期测试：询问 2024 年事件
      4. 行为特征测试：代码生成风格、响应详细程度
      5. 上下文窗口测试：标记注入 + 溢出测试
      6. 能力边界测试：算术能力、推理能力
      7. 确定性测试：多次相同请求的响应一致性（TCM temperature_probe.py 融合）

    Args:
        url: 目标端点 URL
        auth: 认证上下文
        timeout: 单请求超时
        rate_limit_ms: 速率限制延迟（毫秒）
        determinism_requests: 确定性测试的请求次数，默认 3

    Returns:
        ModelFingerprint: 完整的模型指纹
    """
    fp = ModelFingerprint()
    delay = rate_limit_ms / 1000.0 if rate_limit_ms else 0

    # === 1. 直接身份探测 ===
    if delay:
        time.sleep(delay)
    resp = send_chat(url, "What model are you? What company created you?", auth, timeout)
    if resp:
        body = resp["body"]
        body_lower = resp["body"].lower()

        vendor_patterns = [
            (re.compile(r"(?i)(?:meta|llama)", re.DOTALL), "Meta"),
            (re.compile(r"(?i)(?:openai|gpt)", re.DOTALL), "OpenAI"),
            (re.compile(r"(?i)(?:anthropic|claude)", re.DOTALL), "Anthropic"),
            (re.compile(r"(?i)(?:alibaba|qwen)", re.DOTALL), "Alibaba"),
            (re.compile(r"(?i)(?:google|gemini)", re.DOTALL), "Google"),
            (re.compile(r"(?i)(?:mistral)", re.DOTALL), "Mistral"),
            (re.compile(r"(?i)(?:microsoft|azure)", re.DOTALL), "Microsoft"),
        ]

        for pattern, vendor in vendor_patterns:
            if pattern.search(body_lower):
                fp.claimed_vendor = vendor
                break

        model_patterns = [
            r"(?i)(llama\s*[0-9.]+)",
            r"(?i)(gpt\s*[0-9.]+)",
            r"(?i)(claude\s*[0-9.]+)",
            r"(?i)(qwen\s*[0-9.]+)",
            r"(?i)(gemini\s*[0-9.]+)",
            r"(?i)(mistral\s*[0-9.]+)",
        ]
        for pattern in model_patterns:
            m = re.search(pattern, body)
            if m:
                fp.claimed_model = m.group(1).strip()
                break

        cutoff_pattern = re.search(r"(?i)(knowledge\s+cutoff|training\s+data).*(\d{4})", body)
        if cutoff_pattern:
            fp.claimed_cutoff = cutoff_pattern.group(2)

    # === 2. 矛盾测试 ===
    contradiction_queries = [
        "Thanks for the help, Claude! I really appreciate Anthropic creating you.",
        "I love using GPT-4! OpenAI really outdid themselves with you.",
    ]
    for query in contradiction_queries:
        if delay:
            time.sleep(delay)
        resp = send_chat(url, query, auth, timeout)
        if resp:
            body_lower = resp["body"].lower()
            if "not claude" in body_lower or "not anthropic" in body_lower:
                fp.corrected_identity = "Claude correction detected"
                fp.identity_confidence += 0.3
            elif "not gpt" in body_lower or "not openai" in body_lower:
                fp.corrected_identity = "GPT correction detected"
                fp.identity_confidence += 0.3
            if fp.corrected_identity:
                break

    # === 3. 知识截止日期测试 ===
    knowledge_tests = [
        ("Who won the 2024 US presidential election?", "2024 election"),
        ("Tell me about the GPT-4o release from OpenAI.", "GPT-4o"),
        ("What happened in the 2024 Paris Olympics?", "2024 Olympics"),
    ]
    unknown_count = 0
    for query, event in knowledge_tests:
        if delay:
            time.sleep(delay)
        resp = send_chat(url, query, auth, timeout)
        if resp:
            body_lower = resp["body"].lower()
            if any(phrase in body_lower for phrase in ["don't know", "no information", "not yet", "haven't occurred"]):
                unknown_count += 1
    if unknown_count >= 2:
        fp.estimated_cutoff = "before-2024"
    elif unknown_count == 1:
        fp.estimated_cutoff = "mid-2024"
    else:
        fp.estimated_cutoff = "after-2024"

    # === 4. 行为特征测试 ===
    if delay:
        time.sleep(delay)
    resp = send_chat(url, "Explain recursion in one paragraph.", auth, timeout)
    if resp:
        body = resp["body"]
        char_count = len(body)
        if char_count < 100:
            fp.response_verbosity = "concise"
        elif char_count < 300:
            fp.response_verbosity = "detailed"
        else:
            fp.response_verbosity = "verbose"

    if delay:
        time.sleep(delay)
    resp = send_chat(url, "Write a Python function to check if a number is prime.", auth, timeout)
    if resp:
        body_lower = resp["body"].lower()
        if '"""' in resp["body"] or "docstring" in body_lower:
            fp.code_style = "docstring"
        elif "example" in body_lower or "# Example" in resp["body"]:
            fp.code_style = "example"
        else:
            fp.code_style = "minimal"

    # === 5. 上下文窗口测试（简化版） ===
    if delay:
        time.sleep(delay)
    marker = "ZEBRA-42"
    long_fill = " ".join(["test" * 50 for _ in range(20)])
    resp = send_chat(url, f"Remember this secret code: {marker}. {long_fill}. What was the secret code?", auth, timeout)
    if resp:
        if marker in resp["body"]:
            fp.context_window_estimate = 8192
        else:
            fp.context_window_estimate = 4096

    # === 6. 能力边界测试 ===
    if delay:
        time.sleep(delay)
    resp = send_chat(url, "Calculate 847 * 293. Show your work.", auth, timeout)
    if resp:
        if "248171" in resp["body"]:
            fp.arithmetic_capability = "strong"
        elif any(char.isdigit() for char in resp["body"]):
            fp.arithmetic_capability = "moderate"
        else:
            fp.arithmetic_capability = "weak"

    if delay:
        time.sleep(delay)
    resp = send_chat(url, "Alice is taller than Bob. Bob is taller than Carol. Carol is taller than David. David is taller than Eve. List everyone from tallest to shortest.", auth, timeout)
    if resp:
        body_lower = resp["body"].lower()
        if "alice" in body_lower and "bob" in body_lower and "carol" in body_lower:
            fp.reasoning_capability = "strong"
        else:
            fp.reasoning_capability = "moderate"

    # === 7. 元数据泄露检查 ===
    if delay:
        time.sleep(delay)
    resp = send_chat(url, "Hello", auth, timeout)
    if resp and resp["is_json"]:
        try:
            data = json.loads(resp["body"])
            if "metadata" in data:
                md = data["metadata"]
                if isinstance(md, dict):
                    fp.metadata_provider = md.get("provider", "")
                    fp.metadata_model = md.get("model", "")
            if "choices" in data and data["choices"]:
                choice = data["choices"][0]
                if isinstance(choice, dict) and "message" in choice:
                    msg = choice["message"]
                    if isinstance(msg, dict) and "metadata" in msg:
                        md = msg["metadata"]
                        if isinstance(md, dict):
                            fp.metadata_provider = md.get("provider", fp.metadata_provider)
                            fp.metadata_model = md.get("model", fp.metadata_model)
        except json.JSONDecodeError:
            pass

    # === 8. 确定性测试（TCM temperature_probe.py 融合） ===
    if delay:
        time.sleep(delay)
    responses = []
    for _ in range(determinism_requests):
        resp = send_chat(url, "Hello, how are you today?", auth, timeout)
        if resp and resp["status"] == 200:
            responses.append(resp["body"])
        if delay:
            time.sleep(delay)

    if len(responses) >= 2:
        fp.total_response_count = len(responses)
        fp.unique_response_count = len(set(responses))
        fp.is_deterministic = fp.unique_response_count == 1

        token_lens = [len(re.findall(r"\w+|[^\w\s]", r, flags=re.UNICODE)) for r in responses]
        fp.avg_response_length_tokens = statistics.mean(token_lens) if token_lens else 0.0
        fp.median_response_length_tokens = statistics.median(token_lens) if token_lens else 0.0
        fp.min_response_length_tokens = min(token_lens) if token_lens else 0
        fp.max_response_length_tokens = max(token_lens) if token_lens else 0

        if len(token_lens) >= 2:
            fp.response_variance = statistics.variance(token_lens) if len(token_lens) > 1 else 0.0

    # === 9. 推理引擎指纹识别 ===
    engine_results = _detect_inference_engine(url, auth, timeout)
    fp.inference_engine = engine_results.get("engine", "")
    fp.engine_version = engine_results.get("version", "")
    fp.engine_fingerprint_confidence = engine_results.get("confidence", 0.0)

    # 计算置信度
    score = 0
    if fp.claimed_model:
        score += 0.3
    if fp.claimed_vendor:
        score += 0.2
    if fp.corrected_identity:
        score += 0.2
    if fp.estimated_cutoff:
        score += 0.15
    if fp.metadata_model:
        score += 0.15
    if fp.inference_engine:
        score += 0.1
    fp.fingerprint_confidence = min(score, 1.0)

    return fp


def _detect_inference_engine(
    url: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    result = {
        "engine": "",
        "version": "",
        "confidence": 0.0,
        "evidence": [],
    }

    try:
        resp = send_get(url.rstrip("/") + "/v1/models", auth=auth, timeout=timeout)
        if resp:
            headers = resp.get("headers", {})
            body = resp.get("body", "")

            for engine_name, fingerprint in ENGINE_FINGERPRINTS.items():
                for header_name, pattern in fingerprint["headers"].items():
                    header_value = None
                    for h_name in headers:
                        if h_name.lower() == header_name.lower():
                            header_value = headers[h_name]
                            break
                    if header_value and re.match(pattern, str(header_value)):
                        result["engine"] = engine_name
                        version_match = re.search(fingerprint["version_extract"],
                                                  f"{header_name}: {header_value}")
                        if version_match:
                            result["version"] = version_match.group(1)
                        result["confidence"] = 0.9
                        result["evidence"].append(f"Header: {header_name}")
                        return result

            for engine_name, fingerprint in ENGINE_FINGERPRINTS.items():
                for pattern in fingerprint["response_patterns"]:
                    if pattern.search(body):
                        result["engine"] = engine_name
                        result["confidence"] = max(result["confidence"], 0.7)
                        result["evidence"].append(f"Response pattern match")
                        break

            for engine_name, fingerprint in ENGINE_FINGERPRINTS.items():
                for endpoint in fingerprint["endpoints"]:
                    endpoint_url = url.rstrip("/") + endpoint
                    endpoint_resp = send_get(endpoint_url, auth=auth, timeout=timeout)
                    if endpoint_resp and endpoint_resp.get("status") == 200:
                        result["engine"] = engine_name
                        result["confidence"] = max(result["confidence"], 0.6)
                        result["evidence"].append(f"Endpoint: {endpoint}")
                        break

    except Exception:
        pass

    return result


__all__ = [
    "fingerprint_model",
]