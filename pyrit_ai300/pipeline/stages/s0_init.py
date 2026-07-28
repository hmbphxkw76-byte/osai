"""
Stage 0: 初始化 PyRIT (Pre-stage, 无阶段编号)
================================================

执行 PyRIT 原生初始化（AI300SetupManager + 6 个初始化器），
设置数据库路径和重试配置。
"""

from pathlib import Path

from pipeline.context import PipelineContext


async def run(ctx: PipelineContext) -> None:
    """初始化 PyRIT 环境"""
    print("\n初始化 PyRIT...")

    db_base_path = Path(ctx.config_loader.get_memory_db_path())
    db_path = db_base_path.parent / f"{ctx.exam_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    from src.setup import initialize_ai300_async

    ctx.scenario_max_retries = ctx.config_loader.get_scenario_max_retries()
    print(f"  [OK] Scenario 重试: max_retries={ctx.scenario_max_retries} "
          f"(total={1 + ctx.scenario_max_retries})")

    ctx.owasp_success_threshold = ctx.config_loader.get_owasp_success_threshold()
    ctx.stop_on_first_success = ctx.config_loader.get_stop_on_first_success()
    print(f"  [OK] 停止策略: L2 OWASP阈值={ctx.owasp_success_threshold:.0%}, "
          f"L3 全局首停={ctx.stop_on_first_success}")

    setup_manager = await initialize_ai300_async(
        memory_db_type=ctx.config_loader.get_memory_db_type(),
        project_root=Path(__file__).parent.parent.parent,  # 项目根目录
        db_path=str(db_path),
        silent=False,
    )
    retry_config = setup_manager.retry_config
    if retry_config:
        print(f"  [OK] 重试配置: {retry_config}")
    print(f"  [OK] Memory 后端: {ctx.config_loader.get_memory_db_type()}")
    print(f"  [OK] 数据库路径: {db_path}")
