"""Pytest 全局 fixtures — 初始化 PyRIT 环境 (内存 + 注册表)."""

from __future__ import annotations

import asyncio
import gc
import logging
from pathlib import Path

import pytest

# test_full_integration.py 已重构为标准 pytest 测试类, 不再需要跳过收集

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session", autouse=True)
def _init_pyrit_memory():
    """初始化 PyRIT CentralMemory (SQLite, 临时文件)。

    HTTPTarget.__init__ 会调用 CentralMemory.get_memory_instance()，
    如果没有初始化会抛出 ValueError。

    Windows 兼容: SQLite 连接在 TemporaryDirectory 清理前必须关闭,
    否则 WinError 32 (文件被占用) 会阻止临时目录删除。
    """
    import os
    import tempfile

    import dotenv

    # 加载 .env (如果存在)
    env_path = _PROJECT_ROOT / ".env"
    if env_path.exists():
        dotenv.load_dotenv(env_path, override=False)

    # 使用临时数据库路径
    tmp_dir = tempfile.mkdtemp()
    db_path = Path(tmp_dir) / "test.db"
    os.environ["PYRIT_MEMORY_DB_URL"] = f"sqlite:///{db_path}"

    from pyrit.setup.initialization import initialize_pyrit_async

    # 异步初始化需要在事件循环中运行
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            initialize_pyrit_async(
                memory_db_type="SQLite",
                load_defaults=True,
                silent=True,
                db_path=str(db_path),
            )
        )
        yield
    finally:
        # 关闭事件循环
        loop.close()

        # Windows 兼容: 强制关闭 SQLite 连接, 释放文件句柄
        # 学术依据: Windows 文件锁定机制要求所有句柄释放后才能删除
        try:
            from pyrit.memory import CentralMemory

            memory = CentralMemory.get_memory_instance()
            # 尝试关闭数据库引擎
            engine = getattr(memory, "_engine", None)
            if engine is not None:
                engine.dispose()
                logging.getLogger(__name__).info("SQLite engine disposed")
        except Exception:
            pass

        # 强制垃圾回收, 释放所有引用 SQLite 的对象
        gc.collect()

        # 清理临时目录 (ignore_errors=True 保证不会因文件锁定失败)
        import shutil

        shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def _reset_global_state():
    """每个测试前重置全局可变状态, 防止测试间状态污染。

    L5 v45: 修复 test_pipeline_dataflow.py 中 6 个测试间状态污染。
    原因: pipeline.assess.dual_judge 的全局变量
    (_cached_truefalse_judge, _judge_init_attempted 等) 在测试间
    不重置, 导致后续测试读取到前一个测试的 Judge 状态。

    也重置 seed_ranker 的全局路径 (其他测试可能 monkey-patch 了它)。
    """
    # 重置 dual_judge 全局状态
    try:
        from pipeline.assess import dual_judge
        dual_judge._cached_truefalse_judge = None
        dual_judge._cached_harmbench_judge = None
        dual_judge._cached_arbiter_judge = None
        dual_judge._judge_init_attempted = False
        dual_judge._dual_judge_agreements = 0
        dual_judge._dual_judge_disagreements = 0
        dual_judge._dual_judge_third_arbitrated_success = 0
    except ImportError:
        pass

    # 重置 asr_tracker 全局统计
    try:
        from pipeline.assess import asr_tracker
        asr_tracker._cached_truefalse_judge = None
        asr_tracker._cached_harmbench_judge = None
    except (ImportError, AttributeError):
        pass

    yield
