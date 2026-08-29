"""arm — 种子选取 + Converter 转换阶段。

攻击链路第 2-3 步:
    种子选取: 从 YAML 种子文件加载攻击种子, 按历史 ASR 排序
    Converter 转换: 构建 L5 最优 Converter 链 (编码/说服/分解/混淆)

核心模块:
    - seed_ranker: 种子加载 + ASR 排序 + 语言自适应
    - converter_chains: L5 专家级 Converter 链定义
    - converter_presets: l5_optimal 预设 + build_converter_map
    - technique_picker: 攻击技术选择 (单轮/多轮/自适应)
    - converter_selector: Converter 候选选择 + OWASP 优先级 + ASR 裁剪
"""

from arm.converter_presets import build_converter_map
from arm.seed_ranker import load_seeds
from arm.technique_picker import filter_by_adversarial, select_techniques

__all__ = [
    "load_seeds",
    "build_converter_map",
    "select_techniques",
    "filter_by_adversarial",
]
