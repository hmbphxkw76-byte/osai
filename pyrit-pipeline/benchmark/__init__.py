# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""benchmark — 性能基准测试目录。

记录大规模运行性能数据, 包括:
  - ASR 查询延迟
  - EvidenceCollector 收集延迟
  - Converter 路由构建延迟
  - 报告生成延迟
  - 端到端流水线吞吐量

使用方式:
  python -m benchmark.run_benchmarks
"""
