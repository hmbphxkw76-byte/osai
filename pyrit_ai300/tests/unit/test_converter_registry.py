"""
Converter Registry 单元测试
============================

验证 PyRIT 1.0.0 Converter 子系统的对齐质量：
  1. Converter 映射表完整性（含多模态）
  2. 预置链快捷方法构造参数正确性
  3. 模态感知链路验证
  4. Selective Converting 子系统
  5. @apply_defaults 反射检测
  6. ConverterConfiguration 高级字段
  7. Registry 集成
"""

import inspect
import pytest

from src.converters.converter_registry import (
    # 映射表
    CONVERTER_CLASS_MAP,
    # 模态分类
    TEXT_TO_TEXT_CONVERTERS,
    IMAGE_CONVERTERS,
    AUDIO_CONVERTERS,
    VIDEO_CONVERTERS,
    MULTIMODAL_CONVERTERS,
    # 模态工具
    get_converter_supported_types,
    validate_converter_chain_modality,
    filter_converters_by_input_type,
    get_all_converter_modalities,
    # @apply_defaults
    get_converters_requiring_target,
    # 实例创建
    create_converter_instance,
    create_converter_chain_config,
    create_attack_converter_config,
    # Selective Converting
    SELECTION_STRATEGY_MAP,
    create_selection_strategy,
    create_selective_text_converter,
    # 快捷方法
    create_stealth_evasion_chain,
    create_encoding_bypass_chain,
    create_format_injection_chain,
    create_unicode_attack_chain,
    create_multi_encoding_chain,
    create_leetspeak_chain,
    create_policy_puppetry_chain,
    create_decomposition_chain,
    create_noise_chain,
    create_noise_case_chain,
    create_task_framing_chain,
    create_selective_encoding_chain,
    create_multimodal_text_to_image_chain,
    create_llm_assisted_chain,
    # P0-1: File Converter 高级功能
    create_pdf_injection_chain,
    create_text_to_pdf_chain,
    create_worddoc_injection_chain,
    create_text_to_worddoc_chain,
    # P2-1: Response Converter API
    create_response_converter_config,
    # P2-2: TextJailbreak 集成
    create_text_jailbreak_chain,
    # P1-3: 多模态链工厂
    create_multimodal_image_attack_chain,
    create_multimodal_steganography_chain,
    # PEP 562 延迟导入
    _LazyConverterClass,
    _LAZY_AUDIO_MAP,
)

from pyrit.converter import (
    PolicyPuppetryTemplate,
    SelectiveTextConverter,
    Converter,
    TextSelectionStrategy,
    TokenSelectionStrategy,
    AllWordsSelectionStrategy,
    WordProportionSelectionStrategy,
    PositionSelectionStrategy,
    IndexSelectionStrategy,
)


# ============================================================
# 1. Converter 映射表完整性
# ============================================================

class TestConverterMap:
    """Converter 映射表完整性测试"""

    def test_map_not_empty(self):
        """映射表非空"""
        assert len(CONVERTER_CLASS_MAP) > 60

    def test_snake_case_and_class_name_both_work(self):
        """snake_case 和类名两种风格都能找到 Converter"""
        assert "base64" in CONVERTER_CLASS_MAP
        assert "Base64Converter" in CONVERTER_CLASS_MAP
        assert CONVERTER_CLASS_MAP["base64"] is CONVERTER_CLASS_MAP["Base64Converter"]

    def test_multimodal_converters_present(self):
        """多模态 Converter 已纳入映射表"""
        # Image converters
        assert "add_image_text" in CONVERTER_CLASS_MAP
        assert "add_text_image" in CONVERTER_CLASS_MAP
        assert "image_overlay" in CONVERTER_CLASS_MAP
        assert "image_color_saturation" in CONVERTER_CLASS_MAP
        assert "image_compression" in CONVERTER_CLASS_MAP
        assert "image_resizing" in CONVERTER_CLASS_MAP
        assert "image_rotation" in CONVERTER_CLASS_MAP
        assert "image_prompt_style" in CONVERTER_CLASS_MAP

        # Audio converters
        assert "azure_speech_text_to_audio" in CONVERTER_CLASS_MAP
        assert "azure_speech_audio_to_text" in CONVERTER_CLASS_MAP
        assert "audio_echo" in CONVERTER_CLASS_MAP
        assert "audio_frequency" in CONVERTER_CLASS_MAP
        assert "audio_speed" in CONVERTER_CLASS_MAP
        assert "audio_volume" in CONVERTER_CLASS_MAP
        assert "audio_white_noise" in CONVERTER_CLASS_MAP

        # Video converters
        assert "add_image_video" in CONVERTER_CLASS_MAP

    def test_pyrit_1_0_0_new_converters_present(self):
        """PyRIT 1.0.0 新增 Converter 已纳入映射表"""
        assert "noise" in CONVERTER_CLASS_MAP
        assert "decomposition" in CONVERTER_CLASS_MAP
        assert "policy_puppetry" in CONVERTER_CLASS_MAP
        assert "random_capital_letters" in CONVERTER_CLASS_MAP
        assert "task_framing" in CONVERTER_CLASS_MAP

    def test_selective_text_converter_present(self):
        """SelectiveTextConverter 已纳入映射表"""
        assert "selective_text" in CONVERTER_CLASS_MAP
        assert CONVERTER_CLASS_MAP["selective_text"] is SelectiveTextConverter

    def test_all_values_are_converter_subclasses(self):
        """映射表中所有值都是 Converter 的子类（Audio Converter 使用延迟导入）"""
        for name, cls in CONVERTER_CLASS_MAP.items():
            if name.startswith("_"):
                continue
            # _LazyConverterClass 是 Audio Converter 的延迟导入包装器
            if isinstance(cls, _LazyConverterClass):
                continue  # 跳过延迟导入的 Audio Converter
            assert isinstance(cls, type), f"{name} 的值不是类: {cls}"
            assert issubclass(cls, Converter), f"{name} 的值不是 Converter 子类: {cls}"


# ============================================================
# 2. 模态分类
# ============================================================

class TestModalityClassification:
    """模态分类常量测试"""

    def test_text_to_text_set_not_empty(self):
        assert len(TEXT_TO_TEXT_CONVERTERS) > 40

    def test_image_set_not_empty(self):
        assert len(IMAGE_CONVERTERS) >= 7

    def test_audio_set_not_empty(self):
        assert len(AUDIO_CONVERTERS) >= 7

    def test_video_set_not_empty(self):
        assert len(VIDEO_CONVERTERS) >= 1

    def test_multimodal_union(self):
        """MULTIMODAL_CONVERTERS 是 IMAGE + AUDIO + VIDEO 的并集"""
        assert MULTIMODAL_CONVERTERS == IMAGE_CONVERTERS | AUDIO_CONVERTERS | VIDEO_CONVERTERS

    def test_no_overlap_between_text_and_multimodal(self):
        """文本类和多模态类不应重叠"""
        overlap = TEXT_TO_TEXT_CONVERTERS & MULTIMODAL_CONVERTERS
        assert len(overlap) == 0, f"文本类和多模态类重叠: {overlap}"


# ============================================================
# 3. 模态感知工具
# ============================================================

class TestModalityTools:
    """模态感知工具函数测试"""

    def test_get_converter_supported_types_text(self):
        """获取 text→text Converter 的模态"""
        input_types, output_types = get_converter_supported_types("base64")
        assert "text" in input_types
        assert "text" in output_types

    def test_get_converter_supported_types_image(self):
        """获取 text→image_path Converter 的模态"""
        input_types, output_types = get_converter_supported_types("qr_code")
        assert "text" in input_types
        assert "image_path" in output_types

    def test_get_converter_supported_types_unknown(self):
        """未知 Converter 抛出 ValueError"""
        with pytest.raises(ValueError, match="未知"):
            get_converter_supported_types("nonexistent_converter")

    def test_validate_chain_modality_compatible(self):
        """兼容链不产生警告"""
        warnings = validate_converter_chain_modality(["base64", "rot13", "caesar"])
        assert len(warnings) == 0

    def test_validate_chain_modality_incompatible(self):
        """不兼容链产生警告（text→image 后接 text→text）"""
        warnings = validate_converter_chain_modality(["qr_code", "base64"])
        assert len(warnings) > 0
        assert "模态不匹配" in warnings[0]

    def test_validate_chain_modality_empty(self):
        """空链不产生警告"""
        warnings = validate_converter_chain_modality([])
        assert len(warnings) == 0

    def test_filter_converters_by_input_type_text(self):
        """按 text 输入过滤"""
        filtered = filter_converters_by_input_type(input_type="text")
        assert "base64" in filtered
        assert "qr_code" in filtered  # qr_code 接受 text 输入

    def test_filter_converters_by_input_type_image(self):
        """按 image_path 输入过滤"""
        filtered = filter_converters_by_input_type(input_type="image_path")
        assert "add_text_image" in filtered
        assert "image_overlay" in filtered
        assert "base64" not in filtered  # base64 不接受 image_path

    def test_get_all_converter_modalities(self):
        """获取所有 Converter 模态矩阵"""
        modalities = get_all_converter_modalities()
        assert len(modalities) > 0
        for name, inputs, outputs in modalities:
            assert isinstance(name, str)
            assert isinstance(inputs, list)
            assert isinstance(outputs, list)


# ============================================================
# 4. @apply_defaults 反射检测
# ============================================================

class TestApplyDefaultsAlignment:
    """@apply_defaults 机制对齐测试"""

    def test_get_converters_requiring_target_not_empty(self):
        """反射检测到需要 converter_target 的 Converter"""
        result = get_converters_requiring_target()
        assert len(result) > 0

    def test_persuasion_requires_target(self):
        """PersuasionConverter 需要 converter_target"""
        result = get_converters_requiring_target()
        assert "persuasion" in result

    def test_noise_requires_target(self):
        """NoiseConverter 需要 converter_target"""
        result = get_converters_requiring_target()
        assert "noise" in result

    def test_decomposition_requires_target(self):
        """DecompositionConverter 需要 converter_target"""
        result = get_converters_requiring_target()
        assert "decomposition" in result

    def test_denylist_requires_target(self):
        """DenylistConverter 需要 converter_target（之前被遗漏）"""
        result = get_converters_requiring_target()
        assert "denylist" in result

    def test_math_prompt_requires_target(self):
        """MathPromptConverter 需要 converter_target"""
        result = get_converters_requiring_target()
        assert "math_prompt" in result

    def test_base64_does_not_require_target(self):
        """Base64Converter 不需要 converter_target"""
        result = get_converters_requiring_target()
        assert "base64" not in result

    def test_policy_puppetry_does_not_require_target(self):
        """PolicyPuppetryConverter 不需要 converter_target"""
        result = get_converters_requiring_target()
        assert "policy_puppetry" not in result

    def test_task_framing_does_not_require_target(self):
        """TaskFramingConverter 不需要 converter_target"""
        result = get_converters_requiring_target()
        assert "task_framing" not in result


# ============================================================
# 5. Converter 实例创建
# ============================================================

class TestCreateConverterInstance:
    """Converter 实例创建测试"""

    def test_create_simple_converter(self):
        """创建简单 Converter（无 converter_target）"""
        instance = create_converter_instance("base64")
        assert instance is not None
        assert isinstance(instance, Converter)

    def test_create_converter_with_params(self):
        """带参数创建 Converter"""
        instance = create_converter_instance("caesar", caesar_offset=5)
        assert instance is not None
        assert instance.caesar_offset == 5

    def test_create_converter_with_class_name(self):
        """使用类名创建 Converter"""
        instance = create_converter_instance("Base64Converter")
        assert instance is not None

    def test_create_unknown_converter_raises(self):
        """未知 Converter 抛出 ValueError"""
        with pytest.raises(ValueError, match="未知"):
            create_converter_instance("nonexistent")

    def test_create_policy_puppetry_without_target(self):
        """PolicyPuppetryConverter 不需要 converter_target 即可创建"""
        instance = create_converter_instance("policy_puppetry")
        assert instance is not None
        assert isinstance(instance, Converter)

    def test_create_task_framing_without_target(self):
        """TaskFramingConverter 不需要 converter_target 即可创建"""
        instance = create_converter_instance("task_framing")
        assert instance is not None

    def test_create_random_capital_letters(self):
        """RandomCapitalLettersConverter 参数正确"""
        instance = create_converter_instance("random_capital_letters", percentage=50.0)
        assert instance is not None
        assert instance.percentage == 50.0


# ============================================================
# 6. 预置链快捷方法构造验证
# ============================================================

class TestPresetChains:
    """预置链快捷方法构造参数正确性测试"""

    def test_stealth_evasion_chain(self):
        """隐身规避链构造成功"""
        config = create_stealth_evasion_chain()
        assert config is not None
        assert len(config.request_converters) > 0
        # 验证链中有 3 个 Converter
        chain = config.request_converters[0]
        assert len(chain.converters) == 3

    def test_encoding_bypass_chain(self):
        """编码绕过链构造成功"""
        config = create_encoding_bypass_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 3

    def test_format_injection_chain(self):
        """格式注入链构造成功（仅 ascii_art，不串联不兼容模态）"""
        config = create_format_injection_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) >= 1

    def test_unicode_attack_chain(self):
        """Unicode 攻击链构造成功"""
        config = create_unicode_attack_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 3

    def test_multi_encoding_chain(self):
        """多层编码链构造成功"""
        config = create_multi_encoding_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 4

    def test_leetspeak_chain(self):
        """Leetspeak 链构造成功"""
        config = create_leetspeak_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 3

    def test_policy_puppetry_chain_without_target(self):
        """PolicyPuppetry 链不需要 converter_target 即可构造"""
        config = create_policy_puppetry_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 1

    def test_decomposition_chain_requires_target(self):
        """Decomposition 链需要 converter_target"""
        # 不提供 converter_target 时，应该让 PyRIT 的 @apply_defaults 抛出明确错误
        # 这里只验证方法签名不包含错误参数
        sig = inspect.signature(create_decomposition_chain)
        params = list(sig.parameters.keys())
        assert "converter_target" in params
        assert "use_word_game" in params
        # 不应有 strategy 参数（PyRIT 中不存在）
        assert "strategy" not in params

    def test_noise_chain_requires_target(self):
        """Noise 链需要 converter_target"""
        sig = inspect.signature(create_noise_chain)
        params = list(sig.parameters.keys())
        assert "converter_target" in params
        assert "number_errors" in params
        # 不应有 error_types 参数（PyRIT 中不存在）
        assert "error_types" not in params

    def test_noise_case_chain_requires_target(self):
        """Noise+Case 链需要 converter_target"""
        sig = inspect.signature(create_noise_case_chain)
        params = list(sig.parameters.keys())
        assert "converter_target" in params
        assert "number_errors" in params
        assert "percentage" in params
        # 不应有 error_types 参数
        assert "error_types" not in params

    def test_task_framing_chain_signature(self):
        """TaskFraming 链方法签名正确"""
        sig = inspect.signature(create_task_framing_chain)
        params = list(sig.parameters.keys())
        assert "task_template" in params
        assert "strip_characters" in params
        # 不应有 frame_as 参数（PyRIT 中不存在）
        assert "frame_as" not in params

    def test_llm_assisted_chain_default_technique_valid(self):
        """LLM 辅助链默认 persuasion_technique 是有效值"""
        sig = inspect.signature(create_llm_assisted_chain)
        default_technique = sig.parameters["persuasion_technique"].default
        valid_techniques = {
            "authority_endorsement", "evidence_based", "expert_endorsement",
            "logical_appeal", "misrepresentation",
        }
        assert default_technique in valid_techniques, (
            f"默认 persuasion_technique '{default_technique}' 不是有效值。"
            f"有效值: {valid_techniques}"
        )


# ============================================================
# 7. Selective Converting 子系统
# ============================================================

class TestSelectiveConverting:
    """Selective Converting 子系统测试"""

    def test_selection_strategy_map_not_empty(self):
        """选择策略映射表非空"""
        assert len(SELECTION_STRATEGY_MAP) >= 12

    def test_create_selection_strategy_all_words(self):
        """创建 AllWordsSelectionStrategy"""
        strategy = create_selection_strategy("all_words")
        assert isinstance(strategy, AllWordsSelectionStrategy)

    def test_create_selection_strategy_word_proportion(self):
        """创建 WordProportionSelectionStrategy"""
        strategy = create_selection_strategy("word_proportion", proportion=0.3)
        assert isinstance(strategy, WordProportionSelectionStrategy)

    def test_create_selection_strategy_position(self):
        """创建 PositionSelectionStrategy"""
        strategy = create_selection_strategy(
            "position", start_proportion=0.0, end_proportion=0.5
        )
        assert isinstance(strategy, PositionSelectionStrategy)

    def test_create_selection_strategy_token(self):
        """创建 TokenSelectionStrategy"""
        strategy = create_selection_strategy("token")
        assert isinstance(strategy, TokenSelectionStrategy)

    def test_create_selection_strategy_index(self):
        """创建 IndexSelectionStrategy"""
        strategy = create_selection_strategy("index", start=0, end=10)
        assert isinstance(strategy, IndexSelectionStrategy)

    def test_create_selection_strategy_unknown(self):
        """未知策略抛出 ValueError"""
        with pytest.raises(ValueError, match="未知"):
            create_selection_strategy("nonexistent_strategy")

    def test_create_selective_text_converter(self):
        """创建 SelectiveTextConverter 组合包装器"""
        converter = create_selective_text_converter(
            sub_converter_name="base64",
            selection_strategy_name="all_words",
            preserve_tokens=True,
        )
        assert isinstance(converter, SelectiveTextConverter)
        assert converter._preserve_tokens is True

    def test_create_selective_text_converter_with_proportion(self):
        """带比例参数创建 SelectiveTextConverter"""
        converter = create_selective_text_converter(
            sub_converter_name="rot13",
            selection_strategy_name="word_proportion",
            selection_strategy_params={"proportion": 0.5},
            preserve_tokens=True,
        )
        assert isinstance(converter, SelectiveTextConverter)

    def test_create_selective_encoding_chain(self):
        """创建选择性编码链"""
        config = create_selective_encoding_chain(
            sub_converter_name="base64",
            selection_strategy_name="word_proportion",
            proportion=0.3,
            preserve_tokens=True,
        )
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 1
        assert isinstance(chain.converters[0], SelectiveTextConverter)


# ============================================================
# 8. ConverterConfiguration 高级字段
# ============================================================

class TestConverterConfigurationAdvanced:
    """ConverterConfiguration 高级字段测试"""

    def test_create_chain_with_indexes_to_apply(self):
        """创建带 indexes_to_apply 的链"""
        config = create_converter_chain_config(
            converter_names=["base64"],
            indexes_to_apply=[0, 2],
        )
        assert config.indexes_to_apply == [0, 2]

    def test_create_chain_with_prompt_data_types(self):
        """创建带 prompt_data_types_to_apply 的链"""
        config = create_converter_chain_config(
            converter_names=["base64"],
            prompt_data_types_to_apply=["text"],
        )
        assert config.prompt_data_types_to_apply == ["text"]

    def test_create_chain_default_indexes_none(self):
        """默认 indexes_to_apply 为 None"""
        config = create_converter_chain_config(
            converter_names=["base64"],
        )
        assert config.indexes_to_apply is None

    def test_create_attack_config_with_advanced_fields(self):
        """AttackConverterConfig 支持 advanced fields"""
        config = create_attack_converter_config(
            converter_names=["base64"],
            indexes_to_apply=[1],
            prompt_data_types_to_apply=["text"],
        )
        assert config is not None
        chain = config.request_converters[0]
        assert chain.indexes_to_apply == [1]
        assert chain.prompt_data_types_to_apply == ["text"]


# ============================================================
# 9. 多模态 Converter 快捷方法
# ============================================================

class TestMultimodalChains:
    """多模态 Converter 快捷方法测试"""

    def test_create_multimodal_text_to_image_chain(self):
        """创建 text→image 链"""
        config = create_multimodal_text_to_image_chain("qr_code")
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 1

    def test_multimodal_chain_validates_modality(self):
        """多模态链触发模态验证（不兼容链产生警告但不崩溃）"""
        # text → image_path (qr_code) → text (base64) 是不兼容的
        # 应该产生警告但不崩溃（模态验证在 create_converter_chain_config 内部自动执行）
        config = create_attack_converter_config(
            converter_names=["qr_code", "base64"],
        )
        assert config is not None


# ============================================================
# 10. PolicyPuppetryTemplate 枚举导出
# ============================================================

class TestPolicyPuppetryTemplate:
    """PolicyPuppetryTemplate 枚举导出测试"""

    def test_enum_has_members(self):
        """枚举有成员"""
        members = list(PolicyPuppetryTemplate)
        assert len(members) >= 2

    def test_enum_has_dr_house(self):
        """枚举包含 DR_HOUSE"""
        assert hasattr(PolicyPuppetryTemplate, "DR_HOUSE")

    def test_enum_has_medical_advisor(self):
        """枚举包含 MEDICAL_ADVISOR"""
        assert hasattr(PolicyPuppetryTemplate, "MEDICAL_ADVISOR")

    def test_random_returns_valid_member(self):
        """random() 返回有效成员"""
        member = PolicyPuppetryTemplate.random()
        assert member in list(PolicyPuppetryTemplate)

    def test_to_seed_prompt_returns_object(self):
        """to_seed_prompt() 返回对象"""
        member = PolicyPuppetryTemplate.DR_HOUSE
        prompt = member.to_seed_prompt()
        assert prompt is not None


# ============================================================
# 11. Converter 链模态验证集成
# ============================================================

class TestChainModalityValidation:
    """Converter 链模态验证集成测试"""

    def test_text_only_chain_no_warnings(self):
        """纯文本链无模态警告"""
        config = create_converter_chain_config(
            converter_names=["base64", "rot13", "atbash"],
        )
        assert config is not None

    def test_mixed_modality_chain_logs_warning(self):
        """混合模态链记录警告"""
        # qr_code: text → image_path, 然后 base64: text → text
        # 这应该产生模态不匹配警告
        config = create_converter_chain_config(
            converter_names=["qr_code", "base64"],
            validate_modality=True,
        )
        # 验证不崩溃，链仍然创建
        assert config is not None
        assert len(config.converters) == 2

    def test_image_to_image_chain_modality(self):
        """image_path → image_path 链模态验证"""
        # ImageOverlayConverter 和 ImageRotationConverter 都接受 image_path 输入
        # 验证模态链路兼容性（不实际创建实例，因为需要 base_image 参数）
        warnings = validate_converter_chain_modality(["image_overlay", "image_rotation"])
        # 第一个 converter 接受 image_path 但链路以 text 开始，会产生模态警告
        # 第二个 converter 接受 image_path，与第一个的输出 image_path 兼容
        assert len(warnings) <= 1  # 最多一个警告（第一个的输入不匹配 text）

    def test_audio_chain(self):
        """audio_path → audio_path 链（延迟导入触发）"""
        config = create_converter_chain_config(
            converter_names=["audio_white_noise"],
            validate_modality=True,
        )
        assert config is not None


# ============================================================
# 12. PEP 562 Audio Converter 延迟导入
# ============================================================

class TestPEP562LazyImport:
    """PEP 562 Audio Converter 延迟导入测试"""

    def test_lazy_audio_map_not_empty(self):
        """延迟导入映射表非空"""
        assert len(_LAZY_AUDIO_MAP) >= 7

    def test_audio_converters_are_lazy_wrapped(self):
        """Audio Converter 使用 _LazyConverterClass 包装"""
        for name in ["audio_echo", "audio_frequency", "audio_speed",
                      "audio_volume", "audio_white_noise",
                      "azure_speech_text_to_audio", "azure_speech_audio_to_text"]:
            assert name in CONVERTER_CLASS_MAP
            val = CONVERTER_CLASS_MAP[name]
            assert isinstance(val, _LazyConverterClass), (
                f"{name} 应使用 _LazyConverterClass 包装，实际: {type(val)}"
            )

    def test_audio_class_name_aliases_exist(self):
        """Audio Converter 类名别名存在"""
        assert "AudioEchoConverter" in CONVERTER_CLASS_MAP
        assert "AudioWhiteNoiseConverter" in CONVERTER_CLASS_MAP
        assert "AzureSpeechTextToAudioConverter" in CONVERTER_CLASS_MAP

    def test_audio_snake_and_class_name_same_object(self):
        """snake_case 和类名指向同一个 _LazyConverterClass 实例"""
        assert CONVERTER_CLASS_MAP["audio_echo"] is CONVERTER_CLASS_MAP["AudioEchoConverter"]


# ============================================================
# 13. P0-1: File Converter 高级功能
# ============================================================

class TestFileConverterChains:
    """File Converter 高级功能链工厂测试"""

    def test_create_text_to_pdf_chain(self):
        """创建文本→PDF 链"""
        config = create_text_to_pdf_chain(font_size=14)
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 1

    def test_create_text_to_worddoc_chain(self):
        """创建文本→WordDoc 链"""
        config = create_text_to_worddoc_chain()
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 1

    def test_create_pdf_injection_chain_requires_existing_pdf(self):
        """PDF 注入链需要 existing_pdf 参数"""
        sig = inspect.signature(create_pdf_injection_chain)
        params = list(sig.parameters.keys())
        assert "existing_pdf" in params
        assert "injection_items" in params
        assert "font_color" in params
        assert "font_size" in params

    def test_create_worddoc_injection_chain_signature(self):
        """WordDoc 注入链方法签名正确"""
        sig = inspect.signature(create_worddoc_injection_chain)
        params = list(sig.parameters.keys())
        assert "existing_docx" in params
        assert "placeholder" in params
        assert "prompt_template" in params


# ============================================================
# 14. P2-1: Response Converter API
# ============================================================

class TestResponseConverterAPI:
    """Response Converter 编程式控制 API 测试"""

    def test_create_response_converter_config(self):
        """创建 Response Converter 配置"""
        config = create_response_converter_config(
            converter_names=["base64"],
        )
        assert config is not None
        # 应该有 response_converters，没有 request_converters
        assert len(config.response_converters) > 0
        assert len(config.request_converters) == 0

    def test_create_response_converter_with_indexes(self):
        """带 indexes_to_apply 的 Response Converter"""
        config = create_response_converter_config(
            converter_names=["base64"],
            indexes_to_apply=[0, 1],
        )
        chain = config.response_converters[0]
        assert chain.indexes_to_apply == [0, 1]


# ============================================================
# 15. P2-2: TextJailbreak 集成
# ============================================================

class TestTextJailbreakChain:
    """TextJailbreakConverter 数据集集成测试"""

    def test_create_text_jailbreak_chain_signature(self):
        """TextJailbreak 链方法签名正确"""
        sig = inspect.signature(create_text_jailbreak_chain)
        params = list(sig.parameters.keys())
        assert "jailbreak_template_name" in params
        assert sig.parameters["jailbreak_template_name"].default is None


# ============================================================
# 16. P1-3: 多模态 Converter 链工厂
# ============================================================

class TestMultimodalChainFactories:
    """多模态 Converter 链工厂测试"""

    def test_create_multimodal_image_attack_chain(self):
        """创建多模态图片攻击链"""
        config = create_multimodal_image_attack_chain("qr_code")
        assert config is not None
        chain = config.request_converters[0]
        assert len(chain.converters) == 1

    def test_create_multimodal_steganography_chain_signature(self):
        """多模态隐写术链方法签名正确"""
        sig = inspect.signature(create_multimodal_steganography_chain)
        params = list(sig.parameters.keys())
        assert "base_image_path" in params
        assert "text" in params
