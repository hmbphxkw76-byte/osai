# -*- coding: utf-8 -*-
"""
AI-300 Framework - PyRIT Initializer
PyRIT 0.14.0 内存初始化模块

职责：
- 初始化 PyRIT CentralMemory（SQLite 或内存模式）
- 提供组件初始化状态查询
- P2-9: 支持 SQLite 持久化数据库 + 自定义 DB 路径

从 AttackOrchestrator 拆分，遵循单一职责原则。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from pyrit.memory import CentralMemory, SQLiteMemory

logger = logging.getLogger(__name__)


class PyRITInitializer:
    """
    PyRIT 0.14.0 内存初始化器

    支持三种模式：
    - in_memory: SQLite 内存数据库（测试/临时使用）
    - persistent: SQLite 持久化数据库（默认路径 results/ai300_memory.db）
    - custom: 自定义 DB 路径（P2-9 新增）

    使用方式：
        initializer = PyRITInitializer(memory_type="in_memory")
        initializer.initialize()

        # P2-9: 持久化模式
        initializer = PyRITInitializer(memory_type="persistent")
        initializer.initialize()  # → results/ai300_memory.db

        # P2-9: 自定义路径
        initializer = PyRITInitializer(memory_type="persistent", db_path="/data/attacks.db")
        initializer.initialize()
    """

    # 默认持久化数据库路径
    DEFAULT_DB_PATH = "results/ai300_memory.db"

    def __init__(
        self,
        memory_type: str = "in_memory",
        db_path: str = "",
    ):
        """
        Args:
            memory_type: 内存类型 ("in_memory" / "persistent")
            db_path: 自定义数据库路径（P2-9 新增，仅 persistent 模式有效）
        """
        self.memory_type = memory_type
        self.db_path = db_path
        self._initialized = False

    def initialize(self) -> None:
        """初始化 PyRIT 内存"""
        logger.info("\n######## 初始化 PyRIT ########")
        if self.memory_type == "in_memory":
            memory = SQLiteMemory(db_path=":memory:")
        else:
            # P2-9: 持久化模式
            db_path = self.db_path or self.DEFAULT_DB_PATH
            # 确保目录存在
            db_dir = Path(db_path).parent
            if str(db_dir) and not db_dir.exists():
                db_dir.mkdir(parents=True, exist_ok=True)
                logger.info("Created memory DB directory: %s", db_dir)
            memory = SQLiteMemory(db_path=db_path)
            logger.info("P2-9: Persistent memory at %s", db_path)
        CentralMemory.set_memory_instance(memory)
        self._initialized = True
        logger.info("PyRIT 0.14.0 initialized with %s memory", self.memory_type)

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized

    @staticmethod
    def get_memory_instance():
        """获取当前 Memory 实例"""
        return CentralMemory.get_memory_instance()
