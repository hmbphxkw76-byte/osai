#!/usr/bin/env python3
"""
Target Factory 验证脚本 — L5 Expert
验证所有 Target 类型的创建逻辑
"""

import os
import sys

# Fix Windows encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import asyncio
from src.targets import (
    TargetParams,
    TargetFactory,
    TARGET_TYPE_OPENAI_CHAT,
    TARGET_TYPE_OPENAI_RESPONSES,
    TARGET_TYPE_LITELLM,
    TARGET_TYPE_HTTP_API,
    TARGET_TYPE_HTTP_RAW,
    TARGET_TYPE_PLAYWRIGHT,
    TARGET_TYPE_WEBSOCKET_COPILOT,
    TARGET_TYPE_PLAYWRIGHT_COPILOT,
    TARGET_TYPE_AZURE_BLOB,
    TARGET_TYPE_PROMPT_SHIELD,
    TARGET_TYPE_TEXT,
    create_target_params_from_env,
)
from src.targets.target_factory import _LEGACY_TYPE_ALIASES


async def main():
    # Initialize PyRIT memory (required by PromptTarget.__init__)
    from pyrit.setup import initialize_pyrit_async
    await initialize_pyrit_async(memory_db_type="InMemory", silent=True)

    print("=" * 60)
    print("  Target Factory L5 验证")
    print("=" * 60)

    # Test 1: OpenAI Chat target creation
    params = TargetParams(
        temperature=0.0,
        httpx_timeout=180,
        httpx_verify=False,
        model_name="gpt-4o",
    )
    target = TargetFactory.create_target("openai_chat", "https://api.openai.com", params)
    print(f"\n[OK] Test 1: OpenAIChatTarget created → {type(target).__name__}")

    # Test 2: OpenAI Responses target creation (o1/o3 + agentic tool calling)
    params = TargetParams(
        reasoning_effort="high",
        reasoning_summary="auto",
        max_output_tokens=16384,
        model_name="o3-mini",
    )
    target = TargetFactory.create_target("openai_responses", "https://api.openai.com", params)
    print(f"[OK] Test 2: OpenAIResponseTarget created → {type(target).__name__}")

    # Test 3: Auth mode detection (Azure without API key -> identity)
    auth = TargetFactory.detect_auth_mode(
        "https://myresource.openai.azure.com/openai/v1",
        TargetParams(api_key=None),
    )
    assert auth == "identity", f"Expected 'identity', got '{auth}'"
    print(f"[OK] Test 3: Azure auth_mode = {auth}")

    # Test 4: Auth mode detection (non-Azure with API key -> api_key)
    auth = TargetFactory.detect_auth_mode(
        "http://localhost:11434",
        TargetParams(api_key="sk-xxx"),
    )
    assert auth == "api_key", f"Expected 'api_key', got '{auth}'"
    print(f"[OK] Test 4: Local auth_mode = {auth}")

    # Test 5: httpx_client_kwargs building
    kwargs = TargetFactory._build_httpx_client_kwargs(
        TargetParams(httpx_timeout=300, httpx_verify=False, httpx_proxy="http://proxy:8080")
    )
    assert kwargs["timeout"] == 300
    assert kwargs["verify"] == False
    assert kwargs["proxy"] == "http://proxy:8080"
    print(f"[OK] Test 5: httpx_kwargs = {kwargs}")

    # Test 6: Legacy type aliases
    assert _LEGACY_TYPE_ALIASES["openai_compatible"] == "openai_chat"
    assert _LEGACY_TYPE_ALIASES["structured_http"] == "http_api"
    assert _LEGACY_TYPE_ALIASES["custom_http"] == "http_raw"
    print(f"[OK] Test 6: Legacy aliases verified ({len(_LEGACY_TYPE_ALIASES)} mappings)")

    # Test 7: Env-based params loading
    os.environ["TARGET_TEMPERATURE"] = "0.5"
    os.environ["TARGET_HTTPX_TIMEOUT"] = "300"
    os.environ["TARGET_SEED"] = "42"
    params = create_target_params_from_env()
    assert params.temperature == 0.5
    assert params.httpx_timeout == 300.0
    assert params.seed == 42
    print(f"[OK] Test 7: Env params loaded: temp={params.temperature}, timeout={params.httpx_timeout}, seed={params.seed}")

    # Test 8: HTTP API target creation
    params = TargetParams(
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"messages": [{"role": "user", "content": "{PROMPT}"}]},
    )
    target = TargetFactory.create_target("http_api", "http://localhost:8080/api", params)
    print(f"[OK] Test 8: HTTPXAPITarget created → {type(target).__name__}")

    # Test 9: TextTarget creation (debugging)
    params = TargetParams(file_path="output/test_output.txt")
    target = TargetFactory.create_target("text", "", params)
    print(f"[OK] Test 9: TextTarget created → {type(target).__name__}")

    # Test 10: TargetParams dataclass completeness
    p = TargetParams()
    fields = [
        "target_type", "endpoint", "api_key", "model_name", "underlying_model",
        "auth_mode", "httpx_timeout", "httpx_verify", "httpx_proxy", "httpx_client_kwargs",
        "temperature", "top_p", "max_completion_tokens", "frequency_penalty",
        "presence_penalty", "seed", "n", "max_output_tokens", "reasoning_effort",
        "reasoning_summary", "custom_functions", "fail_on_missing_function",
        "extra_body_parameters", "max_requests_per_minute", "method", "headers",
        "json_data", "form_data", "params", "file_path", "raw_http_request",
        "prompt_regex_string", "use_tls", "callback_function",
        "interaction_func", "page",
        "copilot_username", "copilot_password", "copilot_access_token",
        "container_url", "sas_token", "blob_content_type",
        "azure_endpoint", "force_entry_field",
        "discover_capabilities", "apply_discovered_capabilities", "per_probe_timeout_s",
        "force_json_output",
    ]
    for f_name in fields:
        assert hasattr(p, f_name), f"Missing field: {f_name}"
    print(f"[OK] Test 10: TargetParams has {len(fields)} fields (all verified)")

    # Test 11: Creator registry completeness
    from src.targets.target_factory import _TARGET_CREATORS
    expected_types = {
        TARGET_TYPE_OPENAI_CHAT, TARGET_TYPE_OPENAI_RESPONSES, TARGET_TYPE_LITELLM,
        TARGET_TYPE_HTTP_API, TARGET_TYPE_HTTP_RAW,
        TARGET_TYPE_PLAYWRIGHT, TARGET_TYPE_WEBSOCKET_COPILOT, TARGET_TYPE_PLAYWRIGHT_COPILOT,
        TARGET_TYPE_AZURE_BLOB, TARGET_TYPE_PROMPT_SHIELD, TARGET_TYPE_TEXT,
    }
    actual_types = set(_TARGET_CREATORS.keys())
    missing = expected_types - actual_types
    assert not missing, f"Missing creators: {missing}"
    print(f"[OK] Test 11: Creator registry has {len(actual_types)} target types")

    print("\n" + "=" * 60)
    print("  All 11 tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
