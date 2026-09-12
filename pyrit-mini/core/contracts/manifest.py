"""core/contracts/manifest.py — 评分运行清单（ScoreRunManifest）。

ASR 可复现的前提是「同输入 + 同 seed → 同结果」。Manifest 记录影响评分的全部
环境变量：随机种子、Judge 模型、rubric 哈希、temperature。

消费 `config/defaults.yaml:82 adaptive_random_seed`（当前无人读取 —— C7 断链）。

Academic basis:
    - Zheng et al. (arXiv:2306.05685) LLM-as-a-Judge: 裁判模型与温度显著影响裁决
    - Wilson (1927): 置信区间口径唯一化
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


def _file_hash(path: str | Path) -> str | None:
    """文件内容哈希；文件不存在返回 None（IA-6：不崩溃）。"""
    try:
        p = Path(path)
        if not p.is_file():
            return None
        return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    except OSError:
        return None


class ScoreRunManifest(BaseModel):
    """一次评分运行的完整可复现清单。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: str = ""
    random_seed: int | None = None
    judge_models: list[str] = Field(default_factory=list)
    t0_enabled: bool = True
    rubric_paths: list[str] = Field(default_factory=list)
    rubric_hashes: dict[str, str] = Field(default_factory=dict)
    temperature: float | None = None
    aggregation: Literal["or", "and"] = "or"
    adaptive_threshold: float | None = None
    target_model: str = ""
    component_keys: list[str] = Field(default_factory=list)

    def add_rubric(self, path: str | Path) -> None:
        """登记 rubric 并记录其哈希（C7：rubric 变化必须可观测）。"""
        p = str(path)
        if p not in self.rubric_paths:
            self.rubric_paths.append(p)
        digest = _file_hash(p)
        if digest:
            self.rubric_hashes[p] = digest

    def fingerprint(self) -> str:
        """整次运行的指纹，用于跨运行一致性比对（ASR 重跑差异 ≤±2% 的判据）。"""
        payload = "|".join(
            [
                self.run_id,
                str(self.random_seed),
                ",".join(self.judge_models),
                ",".join(f"{k}:{v}" for k, v in sorted(self.rubric_hashes.items())),
                str(self.temperature),
                self.aggregation,
                ",".join(sorted(self.component_keys)),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
