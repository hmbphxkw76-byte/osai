"""
===============================================================================
Bridge Layer — Garak JSONL → Seeds JSON 桥接映射层
===============================================================================

职责:
  - 解析 Garak 扫描输出的 JSONL 结果
  - 过滤无效/重复探测结果
  - 映射风险类别到 attack_seeds JSON (供 promptfoo 模板 + PyRIT 消费)
  - 标注严重度分级、攻击向量分类

数据流:
  garak/outputs/*.jsonl → Bridge 解析+过滤+映射 → seeds_attack.json
                                              ↓
                              promptfoo/ → YAML 模板 (变量插值)
                              pyrit/     → 攻击载荷
===============================================================================
"""
from bridge.seeds_mapper import SeedsMapper, SeedEntry, SeedsManifest

__all__ = [
    "SeedsMapper",
    "SeedEntry",
    "SeedsManifest",
]
