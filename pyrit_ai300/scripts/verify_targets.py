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
    TARGET_TYPE_AZURE_ML,
    TARGET_TYPE_OPENAI_IMAGE,
    TARGET_TYPE_OPENAI_VIDEO,
    TARGET_TYPE_OPENAI_TTS,
    TARGET_TYPE_TEXT,
    create_target_params_from_env,
)
from src.targets.target_factory import _LEGACY_TYPE_ALIASES, _TARGET_CREATORS


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
    assert not kwargs["verify"]
    assert kwargs["proxy"] == "http://proxy:8080"
    print(f"[OK] Test 5: httpx_kwargs = {kwargs}")

    # Test 6: Legacy type aliases (15 mappings)
    assert _LEGACY_TYPE_ALIASES["openai_compatible"] == "openai_chat"
    assert _LEGACY_TYPE_ALIASES["structured_http"] == "http_api"
    assert _LEGACY_TYPE_ALIASES["custom_http"] == "http_raw"
    assert _LEGACY_TYPE_ALIASES["openai"] == "openai_chat"
    assert _LEGACY_TYPE_ALIASES["openai_dalle"] == "openai_image"
    assert _LEGACY_TYPE_ALIASES["dalle"] == "openai_image"
    assert _LEGACY_TYPE_ALIASES["image_generation"] == "openai_image"
    assert _LEGACY_TYPE_ALIASES["sora"] == "openai_video"
    assert _LEGACY_TYPE_ALIASES["video_generation"] == "openai_video"
    assert _LEGACY_TYPE_ALIASES["tts"] == "openai_tts"
    assert _LEGACY_TYPE_ALIASES["audio_generation"] == "openai_tts"
    assert _LEGACY_TYPE_ALIASES["azureml"] == "azure_ml"
    assert len(_LEGACY_TYPE_ALIASES) == 15, f"Expected 15 aliases, got {len(_LEGACY_TYPE_ALIASES)}"
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

    # Test 10: TargetParams dataclass completeness (70+ fields)
    p = TargetParams()
    fields = [
        # 基础参数 (5)
        "target_type", "endpoint", "api_key", "model_name", "underlying_model",
        # 认证 (1)
        "auth_mode",
        # HTTP 客户端 (4)
        "httpx_timeout", "httpx_verify", "httpx_proxy", "httpx_client_kwargs",
        # OpenAI Chat 推理参数 (7)
        "temperature", "top_p", "max_completion_tokens",
        "frequency_penalty", "presence_penalty", "seed", "n",
        # Responses API 专用 (5)
        "max_output_tokens", "reasoning_effort", "reasoning_summary",
        "custom_functions", "fail_on_missing_function",
        # 通用透传 (2)
        "extra_body_parameters", "max_requests_per_minute",
        # HTTP API/Raw 专用 (10)
        "method", "headers", "json_data", "form_data", "params", "file_path",
        "raw_http_request", "prompt_regex_string", "use_tls", "callback_function",
        # Playwright 专用 (2)
        "interaction_func", "page",
        # Copilot 专用 (3)
        "copilot_username", "copilot_password", "copilot_access_token",
        # Azure Blob 专用 (3)
        "container_url", "sas_token", "blob_content_type",
        # Prompt Shield 专用 (2)
        "azure_endpoint", "force_entry_field",
        # OpenAI Image 专用 (4)
        "image_size", "output_format", "image_quality", "image_background",
        # OpenAI Video 专用 (2)
        "video_resolution", "video_n_seconds",
        # OpenAI TTS 专用 (4)
        "tts_voice", "tts_response_format", "tts_language", "tts_speed",
        # Azure ML 专用 (6)
        "azure_ml_endpoint", "azure_ml_api_key", "azure_ml_max_new_tokens",
        "azure_ml_temperature", "azure_ml_top_p", "azure_ml_repetition_penalty",
        # LiteLLM 专用 (3)
        "drop_unsupported_params", "stop", "litellm_max_tokens",
        # TargetConfiguration / CapabilityHandlingPolicy (6)
        "custom_configuration", "capability_policy", "use_developer_role",
        "system_message_behavior", "message_normalizer", "validate_requirements",
        # 能力探测 (4)
        "discover_capabilities", "apply_discovered_capabilities",
        "per_probe_timeout_s", "use_model_profile",
        # 评分器专用 (1)
        "force_json_output",
    ]
    for f_name in fields:
        assert hasattr(p, f_name), f"Missing field: {f_name}"
    print(f"[OK] Test 10: TargetParams has {len(fields)} fields (all verified)")

    # Test 11: Creator registry completeness (15 types)
    expected_types = {
        TARGET_TYPE_OPENAI_CHAT, TARGET_TYPE_OPENAI_RESPONSES, TARGET_TYPE_LITELLM,
        TARGET_TYPE_HTTP_API, TARGET_TYPE_HTTP_RAW,
        TARGET_TYPE_PLAYWRIGHT, TARGET_TYPE_WEBSOCKET_COPILOT, TARGET_TYPE_PLAYWRIGHT_COPILOT,
        TARGET_TYPE_AZURE_BLOB, TARGET_TYPE_PROMPT_SHIELD,
        TARGET_TYPE_OPENAI_IMAGE, TARGET_TYPE_OPENAI_VIDEO, TARGET_TYPE_OPENAI_TTS,
        TARGET_TYPE_AZURE_ML, TARGET_TYPE_TEXT,
    }
    actual_types = set(_TARGET_CREATORS.keys())
    missing = expected_types - actual_types
    assert not missing, f"Missing creators: {missing}"
    assert len(actual_types) == 15, f"Expected 15 types, got {len(actual_types)}"
    print(f"[OK] Test 11: Creator registry has {len(actual_types)} target types (all 15 verified)")

    print("\n" + "=" * 60)
    print("  All 11 tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
