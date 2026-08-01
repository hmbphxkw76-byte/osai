"""garak 全功能红队流水线

基于 garak 原生框架，驱动完整攻击生命周期：
    Stage 1: Recon      — 连通性 + 活跃 Probe 枚举 + 模态侦察 + 目标画像
    Stage 2: Configure  — Tier 排序 + Buff 攻击链 + run.spec 生成
    Stage 3: Execute    — 真正调用 garak harness 发起攻击 + Detector 评估
    Stage 4: Analyze    — garak 报告解析 + DEFCON/ASR/置信区间 + 双框架聚合
    Stage 5: Report     — 卡片化展示 + PyRIT AIR 导出

用法:
    python main.py --stage all
"""

import sys

# Windows GBK 终端下 emoji 打印会触发 UnicodeEncodeError，模块级强制 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

__version__ = "2.0.0"
__author__ = "garak-scanner"
__description__ = "garak-driven full-lifecycle LLM red-team pipeline (recon → execute → analyze → export)"
