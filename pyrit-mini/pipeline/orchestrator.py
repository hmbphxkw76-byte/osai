"""攻击链路编排器 — 6 阶段完整链路 (recon→arm→strike→escalate→assess→report)。

v58 重构: 薄包装器模式, 委托给 main.py 的完整实现, 避免代码重复。

阶段对应模块包:
    ① recon     (recon/burp_parser.py + recon/target_router.py)
    ② arm       (arm/seed_ranker.py + arm/converter_presets.py + arm/technique_picker.py)
    ③ strike    (strike/executor.py)
    ④ escalate  (strike/escalation.py + strike/escalation_chain.py)
    ⑤ assess    (assess/scorer.py + assess/asr_tracker.py + assess/asr_stats.py)
    ⑥ report    (report/evidence.py + report/generator.py)
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def run(argv: list[str] | None = None) -> None:
    """主流程入口 — 委托给 main.py 的完整 6 阶段攻击链路。

    阶段对应模块包 (--stage 控制退出点):
        ① recon     (recon/burp_parser.py + recon/target_router.py)
        ② arm       (arm/seed_ranker.py + arm/converter_presets.py + arm/technique_picker.py)
        ③ strike    (strike/executor.py)
        ④ escalate  (strike/escalation.py + strike/escalation_chain.py)
        ⑤ assess    (assess/scorer.py + assess/asr_tracker.py + assess/asr_stats.py)
        ⑥ report    (report/evidence.py + report/generator.py)

    多 endpoint 支持:
        不指定 --burp → 自动扫描 data/burp/*.txt 全部文件 (默认多端点模式)
        --burp MM_05 → 指定单个 endpoint
        → 优先级排序: 按能力指纹排序 (MCP > function_calling > RAG > workflow > chat)
        → 对每个 endpoint 执行完整 6 阶段深度攻击链路
        → 最终汇总联合 ASR (arXiv:2310.08419 — 1 - ∏(1 - ASRᵢ))
    """
    # 延迟导入避免循环依赖
    from main import run as _main_run
    await _main_run(argv)
