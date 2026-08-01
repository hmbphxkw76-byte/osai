# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Prompt 生成器集成 — GCG 对抗后缀 + Fuzzer 载荷变异。.

使用 PyRIT 原生 ``pyrit.executor.promptgen`` 模块:
  - GCG: 白盒梯度优化对抗后缀 (arXiv:2307.15043)
  - Fuzzer: MCTS 引导的载荷变异 (arXiv:2309.11453)

两者均为 ``PromptGeneratorStrategy``，生成种子后注入
``DatasetAttackConfiguration(inline seed_groups)`` 进入原生执行流水线。

学术依据 (R-007 规则):
  - Zou et al. (arXiv:2307.15043): GCG 对抗后缀在 GPT-4 上 ASR 66%
  - Yu et al. (arXiv:2309.11453): GPTFUZZER 自动变异越狱提示
  - PyRIT 官方 promptgen 模块文档

> **日期**: 2026-8-1
"""

from __future__ import annotations

from pipeline.promptgen.fuzzer_integration import FuzzerPayloadGenerator
from pipeline.promptgen.gcg_integration import GCGSuffixGenerator

__all__ = [
    "GCGSuffixGenerator",
    "FuzzerPayloadGenerator",
]
