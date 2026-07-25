"""
Prompt Generator Module — 对齐 pyrit.executor.promptgen
=========================================================

Layer 1: 种子生成层
"把 1 个 objective 扩展成 N 个攻击变体"

子模块：
- anecdoctor_wrapper.py  AnecDoctor 封装：文档→攻击种子
- fuzzer_wrapper.py      Fuzzer 封装：变异模糊测试
- gcg_wrapper.py         GCG 封装：白盒梯度优化（stub，待 PyRIT 官方实现）
"""

from src.executor.promptgen.anecdoctor_wrapper import AnecdoctorWrapper
from src.executor.promptgen.fuzzer_wrapper import FuzzerWrapper
from src.executor.promptgen.gcg_wrapper import GCGWrapper, GCGConfig

__all__ = [
    "AnecdoctorWrapper",
    "FuzzerWrapper",
    "GCGWrapper",
    "GCGConfig",
]
