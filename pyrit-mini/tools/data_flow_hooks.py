"""
流水线 Phase 数据流快照钩子

用法: 在每个 phase 模块中导入并调用

    from tools.data_flow_hooks import snapshot_hook
    
    # 在 phase 执行完时调用
    snapshot_hook(ctx, "post_recon")
    
    # 在流水线结束时验证
    from tools.data_flow_hooks import validate_and_report
    report = validate_and_report(ctx)
"""

from __future__ import annotations

import logging
from typing import Any

from tools.data_flow_validator import DataFlowValidator, format_report

logger = logging.getLogger(__name__)

# 模块级全局验证器实例
_validator: DataFlowValidator | None = None


def _get_validator() -> DataFlowValidator:
    """获取全局验证器实例"""
    global _validator
    if _validator is None:
        _validator = DataFlowValidator()
    return _validator


def reset_validator() -> None:
    """重置全局验证器（用于测试）"""
    global _validator
    _validator = None


def snapshot_hook(ctx: Any, phase: str, metadata: dict | None = None) -> None:
    """
    阶段快照钩子 — 在 phase 执行结束时调用
    
    集成到流水线的推荐方式:
    
    # 在 core/phases/recon.py 的 _run_recon_phase 末尾:
    from tools.data_flow_hooks import snapshot_hook
    snapshot_hook(ctx, "post_recon")
    
    Args:
        ctx: PipelineContext 实例
        phase: 阶段标识，如 "post_recon", "post_arm", "post_strike", "post_assess"
        metadata: 可选额外元数据
    """
    validator = _get_validator()
    validator.set_context(ctx)
    snap = validator.snapshot(phase, metadata=metadata)
    logger.debug("[Hook] %s 快照完成: %d fields", phase, len(snap.fields))


def validate_and_report(ctx: Any) -> str:
    """
    执行完整数据流验证并返回格式化报告
    
    在流水线结束时调用，返回可读报告字符串。
    
    Args:
        ctx: PipelineContext 实例
        
    Returns:
        格式化验证报告文本
    """
    validator = _get_validator()
    validator.set_context(ctx)

    # 如果还有最后阶段未快照，补齐
    if "post_assess" not in validator.snapshots:
        validator.snapshot("post_assess")

    report = validator.validate_all()
    formatted = format_report(report)

    # 输出到日志
    logger.info("[DataFlow] 数据流验证完成: %d passed, %d failed, %d warnings",
                report.passed, report.failed, report.warnings)

    if not report.is_valid:
        logger.error("[DataFlow] 发现数据流断点！详见报告。")

    return formatted


def validate_quick(ctx: Any) -> bool:
    """
    快速数据流验证 — 仅检查关键字段
    
    使用独立验证器，避免全局状态污染。
    
    Returns:
        是否通过
    """
    # 创建独立验证器，避免干扰全局状态
    local_validator = DataFlowValidator(ctx)

    # 自动生成各阶段快照
    for phase in ["recon", "arm", "strike", "assess"]:
        snap_key = f"post_{phase}"
        local_validator.snapshot(snap_key)

    report = local_validator.validate_all()
    return report.is_valid


# =============================================================================
# 集成适配器: 自动在 phases 中注入快照钩子
# =============================================================================

def integrate_with_phases() -> None:
    """
    自动集成到 phases 模块的代码钩子
    
    在 main.py 或 orchestrator.py 中调用一次，
    自动在每个 phase 结束时插入 snapshot_hook 调用。
    
    使用猴子补丁(monkey-patch)方式，无需修改原始 phase 文件。
    
    注意: 仅在开发/调试环境使用，生产环境建议显式调用
    """
    import importlib
    import sys

    phase_modules = [
        ("core.phases.recon", "recon", "post_recon"),
        ("core.phases.arm", "arm", "post_arm"),
        ("core.phases.strike", "strike", "post_strike"),
        ("core.phases.assess", "assess", "post_assess"),
    ]

    for module_name, phase_name, snapshot_name in phase_modules:
        try:
            mod = importlib.import_module(module_name)
            _patch_phase_module(mod, phase_name, snapshot_name)
            logger.info("[DataFlow] 已集成钩子到 %s (%s)", module_name, snapshot_name)
        except (ImportError, AttributeError) as e:
            logger.warning("[DataFlow] 无法集成 %s: %s", module_name, e)


def _patch_phase_module(mod: Any, phase_name: str, snapshot_name: str) -> None:
    """
    猴子补丁: 在 phase 模块的执行函数末尾注入 snapshot_hook
    """
    # 查找 phase 的执行函数
    run_func_name = f"_run_{phase_name}_phase"
    run_func = getattr(mod, run_func_name, None)

    if run_func is None:
        logger.debug("[DataFlow] %s 不存在，跳过", run_func_name)
        return

    # 创建包装器
    original_func = run_func

    async def wrapped_func(*args, **kwargs):
        result = await original_func(*args, **kwargs)
        # 尝试获取 ctx (第一个参数或 kwargs)
        ctx = kwargs.get("ctx") or (args[0] if args else None)
        if ctx:
            snapshot_hook(ctx, snapshot_name)
        return result

    # 替换
    setattr(mod, run_func_name, wrapped_func)
    logger.debug("[DataFlow] 已修补 %s.%s", mod.__name__, run_func_name)
