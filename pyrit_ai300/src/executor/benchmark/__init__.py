"""
Benchmark Module — 对齐 pyrit.executor.benchmark
==================================================

Layer 5: 标准测试层
"预定义测试集 + 预定义评分 → 一键出成绩单"

子模块：
- fairness_bias.py       公平性偏差基准测试
- question_answering.py  问答准确性基准测试
"""

from src.executor.benchmark.fairness_bias import FairnessBiasWrapper
from src.executor.benchmark.question_answering import QuestionAnsweringWrapper

__all__ = [
    "FairnessBiasWrapper",
    "QuestionAnsweringWrapper",
]
