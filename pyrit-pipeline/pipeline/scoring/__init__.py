# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""评分模块 — AI-VSS 漏洞评分系统 + PyRIT 原生 Scorer 桥接。.

本包提供 AI 漏洞评分标准 (AI-VSS) 实现, 扩展标准 CVSS
以覆盖 AI 特有风险维度。同时提供桥接器将 PyRIT 原生
Scorer 结果增强为 AI-VSS 漏洞评分。

**R-022 PyRIT 原生优先**: AI-VSS 为纯数据层增强, 不修改
原生 Scorer 的 score_async 生命周期, 仅消费 Score 公开字段。

> **日期**: 2026-8-4
"""

from __future__ import annotations

from pipeline.scoring.adaptive_rules import learn_adaptive_patterns
from pipeline.scoring.ai_vss_bridge import AIVSSAugmentedScore, AIVSSBridge
from pipeline.scoring.ai_vss_scorer import (
    AIVSSModifier,
    AIVSSScore,
    AIVSSScorer,
    AIVSSSeverity,
)
from pipeline.scoring.cascade_scorer import (
    CascadeScore,
    CascadeScoreResult,
    CascadeScorerWrapper,
    create_cascade_scorer,
    create_concise_t2_scorer,
    detect_model_family,
    inject_adaptive_rules,
    set_current_model_family,
    validate_scoring_accuracy,
)
from pipeline.scoring.dual_judge_scorer import (
    DualJudgeScorerWrapper,
    create_dual_judge_scorer,
    dual_judge_score_async,
    set_judge_f1_history,
)
from pipeline.scoring.scorer_distillation import (
    DistillationConfig,
    DistilledScore,
    DistilledScorerWrapper,
    export_training_data,
    load_distilled_scorer,
    prepare_distillation_config,
)

__all__ = [
    "AIVSSAugmentedScore",
    "AIVSSBridge",
    "AIVSSModifier",
    "AIVSSScore",
    "AIVSSScorer",
    "AIVSSSeverity",
    "CascadeScore",
    "CascadeScoreResult",
    "CascadeScorerWrapper",
    "DistillationConfig",
    "DistilledScore",
    "DistilledScorerWrapper",
    "DualJudgeScorerWrapper",
    "create_cascade_scorer",
    "create_concise_t2_scorer",
    "create_dual_judge_scorer",
    "detect_model_family",
    "dual_judge_score_async",
    "export_training_data",
    "inject_adaptive_rules",
    "learn_adaptive_patterns",
    "load_distilled_scorer",
    "prepare_distillation_config",
    "set_current_model_family",
    "set_judge_f1_history",
    "validate_scoring_accuracy",
]
