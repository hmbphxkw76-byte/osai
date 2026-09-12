# -*- coding: utf-8 -*-
"""recon/model - LLM Model 侦察模块

对 LLM 模型 API 执行侦察:
- API 分类 (API Classification)
- 系统提示提取 (System Prompt Extraction)
- 模型种子映射 (Model Seed Mapping)
- Prompt 占位符注入与 Chat ID 处理 (Prompt Injector Utilities)

模块清单:
    - api_classifier        : API 分类器
    - system_prompt_extract : 系统提示提取器
    - model_seed_mapper     : 模型种子映射器
    - prompt_injector       : Prompt/Chat-ID 注入与提取工具函数

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect Prompt Injection
    - Perez et al. (arXiv:2212.09251) — Prompt Injection Attacks

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from recon.model.api_classifier import APICategory, detect_api_category
from recon.model.prompt_injector import (
    build_full_url,
    detect_and_inject_chat_id_placeholder,
    extract_chat_id_from_response,
    extract_model_info_from_response,
    extract_original_prompt_value,
    infer_tls,
    inject_prompt_placeholder,
)
from recon.model.seed_mapper import (
    ModelSeedMapper,
    detect_model_family,
    get_mapper,
    get_seeds_for_model,
)
from recon.model.system_prompt_extract import (
    SystemPromptExtractor,
    extract_system_prompt,
)

__all__ = [
    # api_classifier
    "APICategory",
    "detect_api_category",
    # prompt_injector utilities
    "infer_tls",
    "build_full_url",
    "inject_prompt_placeholder",
    "detect_and_inject_chat_id_placeholder",
    "extract_chat_id_from_response",
    "extract_original_prompt_value",
    "extract_model_info_from_response",
    # seed_mapper
    "ModelSeedMapper",
    "detect_model_family",
    "get_mapper",
    "get_seeds_for_model",
    # system_prompt_extract
    "SystemPromptExtractor",
    "extract_system_prompt",
]
