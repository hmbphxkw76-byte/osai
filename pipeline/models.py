"""
===============================================================================
RedTeam_AI Pipeline — 数据模型 & 常量
===============================================================================
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from rich.console import Console

# Fix Windows console encoding for emoji support
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()

# ── 路径常量 ──
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════════════════════════════
# 枚举 & 常量
# ═══════════════════════════════════════════════════════════════════════

class PipelineStage(str, Enum):
    RECON = "recon"          # L0: 前置侦察
    GARAK = "garak"          # L1: AI 模型侦查
    BRIDGE = "bridge"        # L2: 桥接映射
    PROMPTFOO = "promptfoo"  # L3: 提示词模板
    PYRIT = "pyrit"          # L4: 深度攻击
    REPORT = "report"        # L5: 统一报告
    AUTO = "auto"            # 全流程

STAGE_ORDER = [
    PipelineStage.RECON,
    PipelineStage.GARAK,
    PipelineStage.BRIDGE,
    PipelineStage.PROMPTFOO,
    PipelineStage.PYRIT,
    PipelineStage.REPORT,
]

STAGE_LABELS = {
    PipelineStage.RECON: "L0: 前置侦察 — URL枚举/端口扫描/资产发现/服务指纹",
    PipelineStage.GARAK: "L1: AI模型侦查 — Garak基线扫描(6类探针)",
    PipelineStage.BRIDGE: "L2: 桥接映射 — Garak JSONL→Seeds JSON 解析+过滤+风险分类",
    PipelineStage.PROMPTFOO: "L3: 提示词模板 — YAML模板/断言规则/变量插值/多场景配置",
    PipelineStage.PYRIT: "L4: 深度攻击 — Crescendo多轮/编码绕过/自适应LLM攻击/ASR量化",
    PipelineStage.REPORT: "L5: 统一报告 — Garak ASR + PyRIT证据 + promptfoo断言 → OffSec",
}

GARAK_PROBES_INFO = {
    "promptinject":   {"desc": "提示注入探测", "severity": "critical"},
    "jailbreak":      {"desc": "越狱攻击探测 (DAN/GCG/PAST)", "severity": "critical"},
    "encoding":       {"desc": "编码绕过探测 (Base64/ROT13/Morse)", "severity": "medium"},
    "leakage":        {"desc": "数据泄露探测", "severity": "high"},
    "toxicity":       {"desc": "毒性内容探测", "severity": "medium"},
    "hallucination":  {"desc": "幻觉生成探测", "severity": "low"},
}


# ═══════════════════════════════════════════════════════════════════════
# 管道状态
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PipelineState:
    """全流程管道状态 — 支持断点续执行。"""
    target_url: str = ""
    target_id: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    errors: list[str] = field(default_factory=list)

    # L0: 前置侦察
    recon_done: bool = False
    profile_path: str = ""
    profile_data: dict = field(default_factory=dict)

    # L1: Garak 侦查
    garak_done: bool = False
    garak_profile: dict = field(default_factory=dict)
    garak_output_dir: str = ""

    # L2: 桥接映射
    bridge_done: bool = False
    seeds_path: str = ""
    seeds_data: dict = field(default_factory=dict)

    # L3: promptfoo
    promptfoo_done: bool = False
    promptfoo_config_path: str = ""

    # L4: PyRIT 攻击
    pyrit_done: bool = False
    attack_results: dict = field(default_factory=dict)

    # L5: 报告
    report_done: bool = False
    report_path: str = ""

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if isinstance(v, (str, int, float, bool, list, dict, type(None))):
                d[k] = v
        return d

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False, default=str)

    @classmethod
    def load(cls, path: str) -> PipelineState:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        state = cls()
        for k, v in data.items():
            if hasattr(state, k):
                setattr(state, k, v)
        return state
