"""
Target Factory L5 测试
======================

测试 PyRIT 1.0.0 Targets 子系统的 target_factory.py 模块。

覆盖范围：
  P0-1: OpenAIImageTarget bug 修复（detect_auth_mode / model_name / max_requests_per_minute）
  P0-2: custom_configuration 参数透传
  P1-3: CapabilityHandlingPolicy（ADAPT vs RAISE）
  P1-4: TargetRequirements / CHAT_TARGET_REQUIREMENTS 验证
  P1-5: get_known_capabilities / get_default_configuration 模型档案查询
  P2-6: MessageNormalizer（ChatMessageNormalizer / GenericSystemSquashNormalizer / ConversationContextNormalizer）
  P2-7: OpenAIVideoTarget 支持
  P2-8: OpenAITTSTarget 支持
  P3-9: AzureMLChatTarget 支持
  P3-10: LiteLLMChatTarget 推理参数补全

遵循开发规则 1.4.9 测试先行原则
"""

from unittest.mock import MagicMock

from src.targets.target_factory import (
    TargetFactory,
    TargetParams,
    _LEGACY_TYPE_ALIASES,
    _TARGET_CREATORS,
    _TARGET_CLASSES,
    _OPENAI_MULTIMODAL_TYPES,
    _CUSTOM_CONFIG_TYPES,
    TARGET_TYPE_OPENAI_CHAT,
    TARGET_TYPE_OPENAI_RESPONSES,
    TARGET_TYPE_LITELLM,
    TARGET_TYPE_OPENAI_IMAGE,
    TARGET_TYPE_OPENAI_VIDEO,
    TARGET_TYPE_OPENAI_TTS,
    TARGET_TYPE_AZURE_ML,
)

from pyrit.prompt_target import (
    OpenAIChatTarget,
    OpenAIResponseTarget,
    OpenAIImageTarget,
    OpenAIVideoTarget,
    OpenAITTSTarget,
    TargetConfiguration,
)
from pyrit.prompt_target.common.target_capabilities import (
    CapabilityHandlingPolicy,
    CapabilityName,
    UnsupportedCapabilityBehavior,
)
from pyrit.message_normalizer import (
    ChatMessageNormalizer,
    ConversationContextNormalizer,
    GenericSystemSquashNormalizer,
)


# ============================================================
# P0-1: OpenAIImageTarget Bug 修复验证
# ============================================================


class TestP01ImageTargetFix:
    """P0-1: OpenAIImageTarget bug 修复"""

    def test_image_target_creator_registered(self):
        """验证 OpenAIImageTarget 创建器已注册"""
        assert TARGET_TYPE_OPENAI_IMAGE in _TARGET_CREATORS

    def test_image_target_class_in_mapping(self):
        """验证 OpenAIImageTarget 类在 _TARGET_CLASSES 映射中"""
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_IMAGE] is OpenAIImageTarget

    def test_image_params_has_model_name_not_deployment(self):
        """验证 image target 不再使用 deployment 参数名"""
        # P0-1 修复前: kwargs["deployment"] = ...
        # P0-1 修复后: kwargs["model_name"] = ...
        # 通过检查 _create_openai_image 函数源码确认
        import inspect
        from src.targets.target_factory import _create_openai_image
        source = inspect.getsource(_create_openai_image)
        assert 'kwargs["model_name"]' in source or "kwargs['model_name']" in source
        # 不应存在 kwargs["deployment"] 赋值
        assert 'kwargs["deployment"]' not in source and "kwargs['deployment']" not in source

    def test_image_params_has_detect_auth_mode_with_class_prefix(self):
        """验证 detect_auth_mode 调用使用 TargetFactory. 前缀"""
        import inspect
        from src.targets.target_factory import _create_openai_image
        source = inspect.getsource(_create_openai_image)
        assert "TargetFactory.detect_auth_mode" in source
        # 不应存在裸调用 detect_auth_mode
        assert "auth_mode = detect_auth_mode(" not in source

    def test_image_params_has_build_httpx_with_class_prefix(self):
        """验证 _build_openai_httpx_kwargs 调用使用 TargetFactory. 前缀"""
        import inspect
        from src.targets.target_factory import _create_openai_image
        source = inspect.getsource(_create_openai_image)
        assert "TargetFactory._build_openai_httpx_kwargs" in source
        assert "httpx_kwargs = _build_openai_httpx_kwargs(" not in source

    def test_image_params_has_max_requests_per_minute(self):
        """验证 image target 支持 max_requests_per_minute"""
        import inspect
        from src.targets.target_factory import _create_openai_image
        source = inspect.getsource(_create_openai_image)
        assert "max_requests_per_minute" in source

    def test_image_params_has_custom_configuration(self):
        """验证 image target 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_openai_image
        source = inspect.getsource(_create_openai_image)
        assert "custom_configuration" in source


# ============================================================
# P0-2: custom_configuration 参数透传
# ============================================================


class TestP02CustomConfiguration:
    """P0-2: custom_configuration 参数透传"""

    def test_target_params_has_custom_configuration_field(self):
        """验证 TargetParams 有 custom_configuration 字段"""
        params = TargetParams()
        assert hasattr(params, "custom_configuration")
        assert params.custom_configuration is None

    def test_custom_config_types_includes_all_openai_types(self):
        """验证 _CUSTOM_CONFIG_TYPES 包含所有 OpenAI 类型"""
        assert TARGET_TYPE_OPENAI_CHAT in _CUSTOM_CONFIG_TYPES
        assert TARGET_TYPE_OPENAI_RESPONSES in _CUSTOM_CONFIG_TYPES
        assert TARGET_TYPE_LITELLM in _CUSTOM_CONFIG_TYPES
        assert TARGET_TYPE_OPENAI_IMAGE in _CUSTOM_CONFIG_TYPES
        assert TARGET_TYPE_OPENAI_VIDEO in _CUSTOM_CONFIG_TYPES
        assert TARGET_TYPE_OPENAI_TTS in _CUSTOM_CONFIG_TYPES
        assert TARGET_TYPE_AZURE_ML in _CUSTOM_CONFIG_TYPES

    def test_openai_chat_creator_has_custom_configuration(self):
        """验证 _create_openai_chat 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_openai_chat
        source = inspect.getsource(_create_openai_chat)
        assert "custom_configuration" in source

    def test_openai_responses_creator_has_custom_configuration(self):
        """验证 _create_openai_responses 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_openai_responses
        source = inspect.getsource(_create_openai_responses)
        assert "custom_configuration" in source

    def test_litellm_creator_has_custom_configuration(self):
        """验证 _create_litellm 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "custom_configuration" in source


# ============================================================
# P1-3: CapabilityHandlingPolicy（ADAPT vs RAISE）
# ============================================================


class TestP13CapabilityHandlingPolicy:
    """P1-3: CapabilityHandlingPolicy 支持"""

    def test_target_params_has_capability_policy_field(self):
        """验证 TargetParams 有 capability_policy 字段"""
        params = TargetParams()
        assert hasattr(params, "capability_policy")
        assert params.capability_policy is None

    def test_build_capability_policy_adapt(self):
        """验证 ADAPT 策略构建"""
        params = TargetParams(capability_policy="adapt")
        policy = TargetFactory._build_capability_policy(params)
        assert policy is not None
        assert isinstance(policy, CapabilityHandlingPolicy)
        # 所有能力的行为应该是 ADAPT
        for cap, behavior in policy.behaviors.items():
            assert behavior == UnsupportedCapabilityBehavior.ADAPT

    def test_build_capability_policy_raise(self):
        """验证 RAISE 策略构建"""
        params = TargetParams(capability_policy="raise")
        policy = TargetFactory._build_capability_policy(params)
        assert policy is not None
        assert isinstance(policy, CapabilityHandlingPolicy)
        for cap, behavior in policy.behaviors.items():
            assert behavior == UnsupportedCapabilityBehavior.RAISE

    def test_build_capability_policy_none(self):
        """验证无策略时返回 None"""
        params = TargetParams()
        policy = TargetFactory._build_capability_policy(params)
        assert policy is None

    def test_build_capability_policy_covers_adaptable_capabilities(self):
        """验证策略仅覆盖可适配能力（MULTI_TURN + SYSTEM_PROMPT）

        对齐 PyRIT 1.0.0 targets_principles.md §4.2：
        只有可适配能力可以被 PyRIT 自动处理。
        不可适配能力（EDITABLE_HISTORY 等）不在策略中表示。
        """
        params = TargetParams(capability_policy="adapt")
        policy = TargetFactory._build_capability_policy(params)
        expected_caps = {
            CapabilityName.MULTI_TURN,
            CapabilityName.SYSTEM_PROMPT,
        }
        assert set(policy.behaviors.keys()) == expected_caps


# ============================================================
# P1-4: TargetRequirements / CHAT_TARGET_REQUIREMENTS 验证
# ============================================================


class TestP14TargetRequirements:
    """P1-4: TargetRequirements 验证"""

    def test_target_params_has_validate_requirements_field(self):
        """验证 TargetParams 有 validate_requirements 字段"""
        params = TargetParams()
        assert hasattr(params, "validate_requirements")
        assert params.validate_requirements is True

    def test_validate_target_requirements_method_exists(self):
        """验证 validate_target_requirements 方法存在"""
        assert hasattr(TargetFactory, "validate_target_requirements")

    def test_validate_target_requirements_with_mock_pass(self):
        """验证通过需求检查的目标不报错"""
        mock_target = MagicMock()
        mock_target.configuration = MagicMock()
        mock_target.configuration.includes.return_value = True
        mock_target.configuration.ensure_can_handle = MagicMock()
        # 不应抛出异常
        TargetFactory.validate_target_requirements(mock_target)

    def test_validate_target_requirements_with_mock_fail(self):
        """验证不满足需求的目标记录警告但不抛出异常"""
        mock_target = MagicMock()
        mock_target.configuration = MagicMock()
        mock_target.configuration.includes.return_value = False
        mock_target.configuration.ensure_can_handle.side_effect = ValueError("not supported")
        # 不应抛出异常（只记录警告）
        TargetFactory.validate_target_requirements(mock_target)


# ============================================================
# P1-5: get_known_capabilities / get_default_configuration 模型档案查询
# ============================================================


class TestP15ModelProfile:
    """P1-5: 模型能力档案查询"""

    def test_target_params_has_use_model_profile_field(self):
        """验证 TargetParams 有 use_model_profile 字段"""
        params = TargetParams()
        assert hasattr(params, "use_model_profile")
        assert params.use_model_profile is True

    def test_resolve_model_capabilities_returns_none_for_no_config(self):
        """验证无配置时返回 None"""
        params = TargetParams(use_model_profile=False, capability_policy=None, message_normalizer=None)
        result = TargetFactory._resolve_model_capabilities(TARGET_TYPE_OPENAI_CHAT, params)
        assert result is None

    def test_resolve_model_capabilities_with_explicit_config(self):
        """验证显式 custom_configuration 直接返回（叠加 policy）"""
        from pyrit.prompt_target import OpenAIChatTarget
        default_config = OpenAIChatTarget.get_default_configuration()
        params = TargetParams(
            custom_configuration=default_config,
            capability_policy=None,
            message_normalizer=None,
        )
        result = TargetFactory._resolve_model_capabilities(TARGET_TYPE_OPENAI_CHAT, params)
        assert result is not None
        assert isinstance(result, TargetConfiguration)

    def test_resolve_model_capabilities_with_known_model(self):
        """验证 get_known_capabilities 查询已知模型"""
        params = TargetParams(
            model_name="gpt-4o",
            use_model_profile=True,
            capability_policy=None,
            message_normalizer=None,
        )
        result = TargetFactory._resolve_model_capabilities(TARGET_TYPE_OPENAI_CHAT, params)
        assert result is not None
        # gpt-4o 应支持多轮对话
        assert result.capabilities.supports_multi_turn is True

    def test_resolve_model_capabilities_with_unknown_model(self):
        """验证未知模型返回 None（无档案时）"""
        params = TargetParams(
            model_name="unknown-model-xyz",
            use_model_profile=True,
            capability_policy=None,
            message_normalizer=None,
        )
        result = TargetFactory._resolve_model_capabilities(TARGET_TYPE_OPENAI_CHAT, params)
        assert result is None

    def test_resolve_model_capabilities_with_policy_overlay(self):
        """验证 policy 叠加到已知模型档案"""
        params = TargetParams(
            model_name="gpt-4o",
            use_model_profile=True,
            capability_policy="adapt",
            message_normalizer=None,
        )
        result = TargetFactory._resolve_model_capabilities(TARGET_TYPE_OPENAI_CHAT, params)
        assert result is not None
        assert result.policy is not None
        assert result.policy.behaviors[CapabilityName.MULTI_TURN] == UnsupportedCapabilityBehavior.ADAPT

    def test_target_classes_mapping_has_all_multimodal(self):
        """验证 _TARGET_CLASSES 包含所有多模态类型"""
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_CHAT] is OpenAIChatTarget
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_RESPONSES] is OpenAIResponseTarget
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_IMAGE] is OpenAIImageTarget
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_VIDEO] is OpenAIVideoTarget
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_TTS] is OpenAITTSTarget


# ============================================================
# P2-6: MessageNormalizer 集成
# ============================================================


class TestP26MessageNormalizer:
    """P2-6: MessageNormalizer 集成"""

    def test_target_params_has_normalizer_fields(self):
        """验证 TargetParams 有所有 normalizer 相关字段"""
        params = TargetParams()
        assert hasattr(params, "message_normalizer")
        assert hasattr(params, "use_developer_role")
        assert hasattr(params, "system_message_behavior")
        assert params.message_normalizer is None
        assert params.use_developer_role is False
        assert params.system_message_behavior is None

    def test_build_message_normalizer_default(self):
        """验证默认 ChatMessageNormalizer 构建"""
        params = TargetParams(
            message_normalizer="default",
            use_developer_role=True,
            system_message_behavior="keep",
        )
        normalizer = TargetFactory._build_message_normalizer(params)
        assert normalizer is not None
        assert isinstance(normalizer, ChatMessageNormalizer)

    def test_build_message_normalizer_system_squash(self):
        """验证 GenericSystemSquashNormalizer 构建"""
        params = TargetParams(message_normalizer="system_squash")
        normalizer = TargetFactory._build_message_normalizer(params)
        assert normalizer is not None
        assert isinstance(normalizer, GenericSystemSquashNormalizer)

    def test_build_message_normalizer_context(self):
        """验证 ConversationContextNormalizer 构建"""
        params = TargetParams(message_normalizer="context")
        normalizer = TargetFactory._build_message_normalizer(params)
        assert normalizer is not None
        assert isinstance(normalizer, ConversationContextNormalizer)

    def test_build_message_normalizer_none(self):
        """验证无配置时返回 None"""
        params = TargetParams()
        normalizer = TargetFactory._build_message_normalizer(params)
        assert normalizer is None

    def test_build_message_normalizer_auto_default_on_behavior(self):
        """验证设置 system_message_behavior 但未指定 normalizer 类型时自动使用 default"""
        params = TargetParams(system_message_behavior="squash")
        normalizer = TargetFactory._build_message_normalizer(params)
        assert normalizer is not None
        assert isinstance(normalizer, ChatMessageNormalizer)

    def test_build_normalizer_overrides_maps_to_system_prompt(self):
        """验证 normalizer_overrides 映射到 CapabilityName.SYSTEM_PROMPT"""
        params = TargetParams(message_normalizer="default", use_developer_role=True)
        overrides = TargetFactory._build_normalizer_overrides(params)
        assert overrides is not None
        assert CapabilityName.SYSTEM_PROMPT in overrides
        assert isinstance(overrides[CapabilityName.SYSTEM_PROMPT], ChatMessageNormalizer)

    def test_build_normalizer_overrides_none(self):
        """验证无 normalizer 时返回 None"""
        params = TargetParams()
        overrides = TargetFactory._build_normalizer_overrides(params)
        assert overrides is None

    def test_overlay_configuration_preserves_capabilities(self):
        """验证 _overlay_configuration 保留原有 capabilities"""
        from pyrit.prompt_target import OpenAIChatTarget
        default_config = OpenAIChatTarget.get_default_configuration()
        params = TargetParams(capability_policy="adapt", message_normalizer=None)
        result = TargetFactory._overlay_configuration(default_config, params)
        assert result.capabilities == default_config.capabilities
        assert result.policy is not None

    def test_tokenizer_model_aliases_defined(self):
        """验证 TokenizerTemplateNormalizer 模型别名映射已定义（对齐 §18.6）"""
        aliases = TargetFactory._TOKENIZER_MODEL_ALIASES
        assert "chatml" in aliases
        assert "phi3" in aliases
        assert "qwen" in aliases
        assert "llama3" in aliases
        assert "gemma" in aliases
        assert "mistral" in aliases
        assert len(aliases) == 6

    def test_build_message_normalizer_tokenizer_unknown_alias_fallback(self):
        """验证 tokenizer 未知别名时回退到 ChatMessageNormalizer"""
        params = TargetParams(message_normalizer="tokenizer:unknown_model")
        normalizer = TargetFactory._build_message_normalizer(params)
        assert normalizer is not None
        assert isinstance(normalizer, ChatMessageNormalizer)

    def test_env_message_normalizer_accepts_tokenizer_prefix(self):
        """验证 TARGET_MESSAGE_NORMALIZER 环境变量接受 tokenizer: 前缀"""
        import os
        old_val = os.environ.get("TARGET_MESSAGE_NORMALIZER", "")
        try:
            os.environ["TARGET_MESSAGE_NORMALIZER"] = "tokenizer:chatml"
            params = TargetParams()
            from src.targets.target_factory import _apply_env_defaults
            _apply_env_defaults(params)
            assert params.message_normalizer == "tokenizer:chatml"
        finally:
            if old_val:
                os.environ["TARGET_MESSAGE_NORMALIZER"] = old_val
            else:
                os.environ.pop("TARGET_MESSAGE_NORMALIZER", None)


# ============================================================
# P2-7: OpenAIVideoTarget 支持
# ============================================================


class TestP27VideoTarget:
    """P2-7: OpenAIVideoTarget 支持"""

    def test_video_target_type_constant_exists(self):
        """验证 TARGET_TYPE_OPENAI_VIDEO 常量存在"""
        assert TARGET_TYPE_OPENAI_VIDEO == "openai_video"

    def test_video_target_creator_registered(self):
        """验证 OpenAIVideoTarget 创建器已注册"""
        assert TARGET_TYPE_OPENAI_VIDEO in _TARGET_CREATORS

    def test_video_target_class_in_mapping(self):
        """验证 OpenAIVideoTarget 类在 _TARGET_CLASSES 映射中"""
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_VIDEO] is OpenAIVideoTarget

    def test_video_target_in_multimodal_types(self):
        """验证 video 类型在 _OPENAI_MULTIMODAL_TYPES 中"""
        assert TARGET_TYPE_OPENAI_VIDEO in _OPENAI_MULTIMODAL_TYPES

    def test_video_target_in_custom_config_types(self):
        """验证 video 类型在 _CUSTOM_CONFIG_TYPES 中"""
        assert TARGET_TYPE_OPENAI_VIDEO in _CUSTOM_CONFIG_TYPES

    def test_target_params_has_video_fields(self):
        """验证 TargetParams 有 video 相关字段"""
        params = TargetParams()
        assert hasattr(params, "video_resolution")
        assert hasattr(params, "video_n_seconds")
        assert params.video_resolution is None
        assert params.video_n_seconds is None

    def test_video_legacy_alias(self):
        """验证 video 向后兼容别名"""
        assert _LEGACY_TYPE_ALIASES["sora"] == TARGET_TYPE_OPENAI_VIDEO
        assert _LEGACY_TYPE_ALIASES["video_generation"] == TARGET_TYPE_OPENAI_VIDEO

    def test_video_creator_source_has_custom_configuration(self):
        """验证 _create_openai_video 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_openai_video
        source = inspect.getsource(_create_openai_video)
        assert "custom_configuration" in source
        assert "resolution_dimensions" in source
        assert "n_seconds" in source
        assert "TargetFactory.detect_auth_mode" in source


# ============================================================
# P2-8: OpenAITTSTarget 支持
# ============================================================


class TestP28TTSTarget:
    """P2-8: OpenAITTSTarget 支持"""

    def test_tts_target_type_constant_exists(self):
        """验证 TARGET_TYPE_OPENAI_TTS 常量存在"""
        assert TARGET_TYPE_OPENAI_TTS == "openai_tts"

    def test_tts_target_creator_registered(self):
        """验证 OpenAITTSTarget 创建器已注册"""
        assert TARGET_TYPE_OPENAI_TTS in _TARGET_CREATORS

    def test_tts_target_class_in_mapping(self):
        """验证 OpenAITTSTarget 类在 _TARGET_CLASSES 映射中"""
        assert _TARGET_CLASSES[TARGET_TYPE_OPENAI_TTS] is OpenAITTSTarget

    def test_tts_target_in_multimodal_types(self):
        """验证 tts 类型在 _OPENAI_MULTIMODAL_TYPES 中"""
        assert TARGET_TYPE_OPENAI_TTS in _OPENAI_MULTIMODAL_TYPES

    def test_target_params_has_tts_fields(self):
        """验证 TargetParams 有 TTS 相关字段"""
        params = TargetParams()
        assert hasattr(params, "tts_voice")
        assert hasattr(params, "tts_response_format")
        assert hasattr(params, "tts_language")
        assert hasattr(params, "tts_speed")
        assert params.tts_voice is None
        assert params.tts_response_format is None
        assert params.tts_language is None
        assert params.tts_speed is None

    def test_tts_legacy_alias(self):
        """验证 TTS 向后兼容别名"""
        assert _LEGACY_TYPE_ALIASES["tts"] == TARGET_TYPE_OPENAI_TTS
        assert _LEGACY_TYPE_ALIASES["audio_generation"] == TARGET_TYPE_OPENAI_TTS

    def test_tts_creator_source_has_custom_configuration(self):
        """验证 _create_openai_tts 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_openai_tts
        source = inspect.getsource(_create_openai_tts)
        assert "custom_configuration" in source
        assert "voice" in source
        assert "response_format" in source
        assert "language" in source
        assert "speed" in source


# ============================================================
# P3-9: AzureMLChatTarget 支持
# ============================================================


class TestP39AzureMLTarget:
    """P3-9: AzureMLChatTarget 支持"""

    def test_azure_ml_target_type_constant_exists(self):
        """验证 TARGET_TYPE_AZURE_ML 常量存在"""
        assert TARGET_TYPE_AZURE_ML == "azure_ml"

    def test_azure_ml_target_creator_registered(self):
        """验证 AzureMLChatTarget 创建器已注册"""
        assert TARGET_TYPE_AZURE_ML in _TARGET_CREATORS

    def test_azure_ml_target_in_custom_config_types(self):
        """验证 azure_ml 类型在 _CUSTOM_CONFIG_TYPES 中"""
        assert TARGET_TYPE_AZURE_ML in _CUSTOM_CONFIG_TYPES

    def test_target_params_has_azure_ml_fields(self):
        """验证 TargetParams 有 Azure ML 相关字段"""
        params = TargetParams()
        assert hasattr(params, "azure_ml_endpoint")
        assert hasattr(params, "azure_ml_api_key")
        assert hasattr(params, "azure_ml_max_new_tokens")
        assert hasattr(params, "azure_ml_temperature")
        assert hasattr(params, "azure_ml_top_p")
        assert hasattr(params, "azure_ml_repetition_penalty")

    def test_azure_ml_legacy_alias(self):
        """验证 Azure ML 向后兼容别名"""
        assert _LEGACY_TYPE_ALIASES["azureml"] == TARGET_TYPE_AZURE_ML

    def test_azure_ml_creator_source_has_custom_configuration(self):
        """验证 _create_azure_ml 支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_azure_ml
        source = inspect.getsource(_create_azure_ml)
        assert "custom_configuration" in source
        assert "max_new_tokens" in source
        assert "repetition_penalty" in source
        assert "AZURE_ML_MANAGED_ENDPOINT" in source
        assert "AZURE_ML_KEY" in source


# ============================================================
# P3-10: LiteLLMChatTarget 推理参数补全
# ============================================================


class TestP310LiteLLMParams:
    """P3-10: LiteLLMChatTarget 推理参数补全"""

    def test_target_params_has_litellm_fields(self):
        """验证 TargetParams 有 LiteLLM 专用字段"""
        params = TargetParams()
        assert hasattr(params, "drop_unsupported_params")
        assert hasattr(params, "stop")
        assert hasattr(params, "litellm_max_tokens")
        assert params.drop_unsupported_params is True
        assert params.stop is None
        assert params.litellm_max_tokens is None

    def test_litellm_creator_uses_model_name_not_model(self):
        """验证 LiteLLM 创建器使用 model_name 而非 model"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert '"model_name"' in source
        # 不应使用旧的 "model" 键
        assert '"model":' not in source

    def test_litellm_creator_has_frequency_penalty(self):
        """验证 LiteLLM 创建器支持 frequency_penalty"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "frequency_penalty" in source

    def test_litellm_creator_has_presence_penalty(self):
        """验证 LiteLLM 创建器支持 presence_penalty"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "presence_penalty" in source

    def test_litellm_creator_has_n_param(self):
        """验证 LiteLLM 创建器支持 n 参数"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert '"n"' in source

    def test_litellm_creator_has_stop_param(self):
        """验证 LiteLLM 创建器支持 stop 参数"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert '"stop"' in source

    def test_litellm_creator_has_drop_unsupported_params(self):
        """验证 LiteLLM 创建器支持 drop_unsupported_params"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "drop_unsupported_params" in source

    def test_litellm_creator_has_underlying_model(self):
        """验证 LiteLLM 创建器支持 underlying_model"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "underlying_model" in source

    def test_litellm_creator_has_reasoning_effort_passthrough(self):
        """验证 LiteLLM 创建器通过 extra_body_parameters 透传 reasoning_effort"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "reasoning_effort" in source
        assert "extra_body" in source

    def test_litellm_creator_has_custom_configuration(self):
        """验证 LiteLLM 创建器支持 custom_configuration"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert "custom_configuration" in source

    def test_litellm_creator_uses_max_tokens_not_max_completion_tokens(self):
        """验证 LiteLLM 创建器使用 max_tokens 而非 max_completion_tokens"""
        import inspect
        from src.targets.target_factory import _create_litellm
        source = inspect.getsource(_create_litellm)
        assert '"max_tokens"' in source


# ============================================================
# 注册表完整性验证
# ============================================================


class TestRegistryCompleteness:
    """注册表完整性验证"""

    def test_creator_registry_has_15_types(self):
        """验证创建器注册表有 15 种目标类型"""
        assert len(_TARGET_CREATORS) == 15

    def test_all_new_types_registered(self):
        """验证所有新增类型已注册"""
        new_types = {
            TARGET_TYPE_OPENAI_VIDEO,
            TARGET_TYPE_OPENAI_TTS,
            TARGET_TYPE_AZURE_ML,
        }
        actual = set(_TARGET_CREATORS.keys())
        missing = new_types - actual
        assert not missing, f"Missing creators: {missing}"

    def test_legacy_aliases_count(self):
        """验证向后兼容别名数量（新增了 sora/video_generation/tts/audio_generation/azureml）"""
        # 原始 9 个 + 新增 6 个 = 15
        assert len(_LEGACY_TYPE_ALIASES) >= 15

    def test_target_classes_has_7_entries(self):
        """验证 _TARGET_CLASSES 有 7 个条目（chat/responses/image/video/tts + litellm/azure_ml）"""
        # 核心 SDK 类型 5 个 + 可选依赖类型 2 个（LiteLLM + AzureML）
        assert len(_TARGET_CLASSES) >= 5
        # 验证核心类型始终存在
        assert TARGET_TYPE_OPENAI_CHAT in _TARGET_CLASSES
        assert TARGET_TYPE_OPENAI_RESPONSES in _TARGET_CLASSES
        assert TARGET_TYPE_OPENAI_IMAGE in _TARGET_CLASSES
        assert TARGET_TYPE_OPENAI_VIDEO in _TARGET_CLASSES
        assert TARGET_TYPE_OPENAI_TTS in _TARGET_CLASSES

    def test_openai_multimodal_types_has_3_entries(self):
        """验证 _OPENAI_MULTIMODAL_TYPES 有 3 个条目（image/video/tts）"""
        assert len(_OPENAI_MULTIMODAL_TYPES) == 3

    def test_custom_config_types_includes_azure_ml(self):
        """验证 _CUSTOM_CONFIG_TYPES 包含 azure_ml"""
        assert TARGET_TYPE_AZURE_ML in _CUSTOM_CONFIG_TYPES


# ============================================================
# TargetParams 字段完整性验证
# ============================================================


class TestTargetParamsCompleteness:
    """TargetParams 字段完整性验证"""

    def test_all_new_fields_present(self):
        """验证所有新增字段都存在"""
        params = TargetParams()
        new_fields = [
            # P2-7 Video
            "video_resolution",
            "video_n_seconds",
            # P2-8 TTS
            "tts_voice",
            "tts_response_format",
            "tts_language",
            "tts_speed",
            # P3-9 Azure ML
            "azure_ml_endpoint",
            "azure_ml_api_key",
            "azure_ml_max_new_tokens",
            "azure_ml_temperature",
            "azure_ml_top_p",
            "azure_ml_repetition_penalty",
            # P3-10 LiteLLM
            "drop_unsupported_params",
            "stop",
            "litellm_max_tokens",
            # P0-2 / P1-3 / P1-4 / P1-5 / P2-6
            "custom_configuration",
            "capability_policy",
            "use_developer_role",
            "system_message_behavior",
            "message_normalizer",
            "validate_requirements",
            "use_model_profile",
        ]
        for field_name in new_fields:
            assert hasattr(params, field_name), f"Missing field: {field_name}"

    def test_target_params_total_field_count(self):
        """验证 TargetParams 字段总数（原始 48 + 新增约 22 = 70+）"""
        import dataclasses
        fields = dataclasses.fields(TargetParams)
        assert len(fields) >= 70, f"Expected 70+ fields, got {len(fields)}"


# ============================================================
# 环境变量加载验证
# ============================================================


class TestEnvDefaults:
    """环境变量加载验证"""

    def test_env_capability_policy(self, monkeypatch):
        """验证 TARGET_CAPABILITY_POLICY 环境变量"""
        monkeypatch.setenv("TARGET_CAPABILITY_POLICY", "adapt")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.capability_policy == "adapt"

    def test_env_message_normalizer(self, monkeypatch):
        """验证 TARGET_MESSAGE_NORMALIZER 环境变量"""
        monkeypatch.setenv("TARGET_MESSAGE_NORMALIZER", "system_squash")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.message_normalizer == "system_squash"

    def test_env_use_developer_role(self, monkeypatch):
        """验证 TARGET_USE_DEVELOPER_ROLE 环境变量"""
        monkeypatch.setenv("TARGET_USE_DEVELOPER_ROLE", "true")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.use_developer_role is True

    def test_env_system_message_behavior(self, monkeypatch):
        """验证 TARGET_SYSTEM_MESSAGE_BEHAVIOR 环境变量"""
        monkeypatch.setenv("TARGET_SYSTEM_MESSAGE_BEHAVIOR", "squash")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.system_message_behavior == "squash"

    def test_env_tts_voice(self, monkeypatch):
        """验证 TARGET_TTS_VOICE 环境变量"""
        monkeypatch.setenv("TARGET_TTS_VOICE", "alloy")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.tts_voice == "alloy"

    def test_env_video_resolution(self, monkeypatch):
        """验证 TARGET_VIDEO_RESOLUTION 环境变量"""
        monkeypatch.setenv("TARGET_VIDEO_RESOLUTION", "1280x720")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.video_resolution == "1280x720"

    def test_env_azure_ml_endpoint(self, monkeypatch):
        """验证 AZURE_ML_MANAGED_ENDPOINT 环境变量"""
        monkeypatch.setenv("AZURE_ML_MANAGED_ENDPOINT", "https://ml.azureml.net/v1")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.azure_ml_endpoint == "https://ml.azureml.net/v1"

    def test_env_stop(self, monkeypatch):
        """验证 TARGET_STOP 环境变量"""
        monkeypatch.setenv("TARGET_STOP", "<end>")
        from src.targets.target_factory import _apply_env_defaults
        params = TargetParams()
        _apply_env_defaults(params)
        assert params.stop == "<end>"
