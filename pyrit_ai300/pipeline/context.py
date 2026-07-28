"""
PipelineContext — 阶段间共享状态容器
====================================

替代旧版 pipeline.py 中 1000 行函数内的几十个局部变量。
每个阶段函数接收 PipelineContext 并按需读取/写入字段。

设计原则:
  - 单一数据流：所有阶段间传递的数据都通过 ctx 流转
  - 类型安全：每个字段有明确类型标注
  - 可追溯：每个字段标注来源阶段（# src: Stage N）
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PipelineContext:
    """Pipeline 全局上下文 — 阶段间共享状态"""

    # ── 元数据 (src: Pre-stage) ──
    config_loader: Any = None
    start_time: datetime = None
    exam_id: str = ""
    log_path: Optional[Path] = None
    verbose: bool = False
    owasp_ids: Optional[List[str]] = None  # CLI 参数

    # ── 环境配置 (src: Pre-stage) ──
    target_url: str = ""
    target_endpoint: str = ""
    target_model: str = ""
    target_api_key: str = ""
    judge_endpoint: str = ""
    judge_model: str = ""
    judge_api_key: str = ""

    # ── 重试/停止配置 (src: Pre-stage) ──
    scenario_max_retries: int = 0
    owasp_success_threshold: float = 0.5
    stop_on_first_success: bool = False

    # ── Stage 1: Recon ──
    recon_result: Any = None
    model_tier: str = "unknown"
    target_type: str = ""  # recon 检测的 target_type (如 "openai_responses")

    # ── Stage 2: Analysis ──
    strategy_selection: Any = None
    strategy_info: Dict[str, Any] = field(default_factory=dict)
    priority_score: int = 0
    auth_result: Any = None
    recommended_mode: str = ""

    # ── Stage 3: Targets ──
    objective_target: Any = None
    # target_type 在 Stage 3 被 create_prompt_target 覆盖为更精确的值
    target_group: str = ""
    bypass_mechanism: str = "unknown"
    judge_target: Any = None
    converter_target: Any = None
    converter_model: str = ""
    converter_target_display: str = ""
    api_max_concurrent: int = 10
    target_rpm: Optional[int] = None
    judge_rpm: Optional[int] = None

    # ── Stage 4: Datasets ──
    manager: Any = None
    total_seeds: int = 0
    total_groups: int = 0
    all_seed_groups: List[Any] = field(default_factory=list)
    selected_groups: List[Any] = field(default_factory=list)
    planning_groups: List[Any] = field(default_factory=list)
    attack_groups: List[Any] = field(default_factory=list)
    attack_plans: List[Any] = field(default_factory=list)
    prompt_batches: List[Any] = field(default_factory=list)
    total_prompts: int = 0
    multi_turn_count: int = 0
    fallback_strategy: Any = None
    fallback_chain: List[Any] = field(default_factory=list)
    config_owasp_ids: List[str] = field(default_factory=list)
    owasp_counts: Dict[str, int] = field(default_factory=dict)
    technique_counts: Dict[str, int] = field(default_factory=dict)
    asr_high_count: int = 0

    # ── Stage 5: Matching ──
    converter_chains: List[str] = field(default_factory=list)

    # ── Stage 6: Execute ──
    adaptive_result: Any = None
    batch_result: Any = None
    max_concurrency: int = 1
    per_attack_timeout: int = 180
    timeout_overrides: Dict[str, int] = field(default_factory=dict)
    adaptive_max_concurrency: int = 4

    # ── Stage 8: Report ──
    report_result: Any = None
    end_time: Optional[datetime] = None
