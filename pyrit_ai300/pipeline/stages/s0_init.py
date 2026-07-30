"""
Stage 0: 初始化 PyRIT (Pre-stage, 无阶段编号)
================================================

执行 PyRIT 原生初始化（AI300SetupManager + 初始化器），
设置数据库路径和重试配置。

性能优化 (v8.3):
  调整 print/import 顺序 — 所有不依赖 import 的 [OK] 信息在
  重导入链（pyrit.setup ~3.7s）触发之前打印，用户 0.2s 即看到
  完整初始化进度，import 期间显示 "正在加载..." 提示。
"""

from pathlib import Path

from pipeline.context import PipelineContext


async def run(ctx: PipelineContext) -> None:
    """初始化 PyRIT 环境"""
    print("\n初始化 PyRIT...")

    # ── 先打印所有不依赖 import 的 [OK] 信息（用户立即获得反馈）──
    ctx.scenario_max_retries = ctx.config_loader.get_scenario_max_retries()
    print(f"  [OK] Scenario 重试: max_retries={ctx.scenario_max_retries} "
          f"(total={1 + ctx.scenario_max_retries})")

    ctx.owasp_success_threshold = ctx.config_loader.get_owasp_success_threshold()
    ctx.stop_on_first_success = ctx.config_loader.get_stop_on_first_success()
    print(f"  [OK] 停止策略: L2 OWASP阈值={ctx.owasp_success_threshold:.0%}, "
          f"L3 全局首停={ctx.stop_on_first_success}")

    db_base_path = Path(ctx.config_loader.get_memory_db_path())
    db_path = db_base_path.parent / f"{ctx.exam_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"  [OK] Memory 后端: {ctx.config_loader.get_memory_db_type()}")
    print(f"  [OK] 数据库路径: {db_path}")

    # ── 触发重导入链（pyrit.setup → TargetInitializer → pyrit.prompt_target）──
    # 此处约 3.7s，用户已看到上方所有 [OK] 信息
    print("  [..] 正在加载 PyRIT 核心模块...")

    from src.setup import initialize_ai300_async

    # silent=True 静默 PyRIT 原生初始化输出（"Skipping scorer" 等噪音）
    # s0_init 自身的 [OK] 信息仍正常输出，不受 silent 影响
    setup_manager = await initialize_ai300_async(
        memory_db_type=ctx.config_loader.get_memory_db_type(),
        project_root=Path(__file__).parent.parent.parent,  # 项目根目录
        db_path=str(db_path),
        silent=True,
    )
    retry_config = setup_manager.retry_config
    if retry_config:
        # P3-A: retry_config 格式化展示
        _max_attempts = getattr(retry_config, "max_num_attempts", None)
        _backoff = getattr(retry_config, "backoff_factor", None)
        _status = getattr(retry_config, "retry_on_status_codes", None)
        _retry_lines = []
        if _max_attempts is not None:
            _retry_lines.append(f"max_attempts={_max_attempts}")
        if _backoff is not None:
            _retry_lines.append(f"backoff={_backoff}")
        if _status:
            _retry_lines.append(f"retry_status={list(_status)[:5]}")
        if _retry_lines:
            print(f"  [OK] 重试配置: {' | '.join(_retry_lines)}")
        else:
            print("  [OK] 重试配置: 已加载")

    # P2-A: 阶段间衔接行
    from pipeline.display import handoff_line
    handoff_line(0, 1, f"PyRIT 初始化完成 | Memory={ctx.config_loader.get_memory_db_type()} | retries={ctx.scenario_max_retries}")
