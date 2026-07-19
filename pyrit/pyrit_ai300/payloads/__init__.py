# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payloads Module
载荷模块：管理攻击载荷、多维分析

子模块：
- models: 数据模型（ThreatModel, PayloadProfile）
- patterns: 检测模式定义
- normalizer: 归一化预处理
- payload_classifier: 核心分析函数
- payload_manager: 载荷管理器
- template_renderer: 三级占位符渲染器（v3.1 新增）
- payload_generator: CVE/论文自动生成载荷草稿（v3.2 新增）
- payload_mutator: 基于成功载荷的智能变异器（v3.3 新增）
- payload_dedup: 载荷去重器（v3.3 新增）
- payload_filter: 侦察→载荷过滤闭环（v3.4 REV-1 新增）
- asr_ranker: ASR 感知载荷排序器（v3.4 REV-2 新增）
"""

from .payload_manager import PayloadManager
from .models import (
    ThreatModel,
    PayloadProfile,
)
from .payload_classifier import (
    classify_payload,
    classify_payloads,
    get_category_description,
    analyze_payload,
    analyze_payloads,
    MODEL_CONTEXT_WINDOWS,
)
from .normalizer import normalize_payload
from .template_renderer import TemplateRenderer, render_payload
from .payload_generator import PayloadGenerator, GeneratedPayload, GenerationResult
from .payload_mutator import PayloadMutator, MutatedPayload, MutationResult, MUTATION_STRATEGIES
from .payload_dedup import deduplicate_payloads, deduplicate_with_profiles
from .payload_filter import PayloadFilter, OWASP_SURFACE_MAP, normalize_surfaces
from .asr_ranker import ASRRanker
from .model_specific_selector import ModelSpecificSelector

__all__ = [
    # PayloadManager
    "PayloadManager",
    # Models
    "ThreatModel",
    "PayloadProfile",
    "MODEL_CONTEXT_WINDOWS",
    # Classifier functions
    "classify_payload",
    "classify_payloads",
    "get_category_description",
    "analyze_payload",
    "analyze_payloads",
    "normalize_payload",
    # Template Renderer (v3.1)
    "TemplateRenderer",
    "render_payload",
    # Payload Generator (v3.2)
    "PayloadGenerator",
    "GeneratedPayload",
    "GenerationResult",
    # Payload Mutator (v3.3)
    "PayloadMutator",
    "MutatedPayload",
    "MutationResult",
    "MUTATION_STRATEGIES",
    "deduplicate_payloads",
    "deduplicate_with_profiles",
    # Payload Filter (v3.4 REV-1)
    "PayloadFilter",
    "OWASP_SURFACE_MAP",
    "normalize_surfaces",
    # ASR Ranker (v3.4 REV-2)
    "ASRRanker",
    # Model Specific Selector (REV-3)
    "ModelSpecificSelector",
]
