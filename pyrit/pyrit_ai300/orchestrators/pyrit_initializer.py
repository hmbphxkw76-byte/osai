# -*- coding: utf-8 -*-
"""
AI-300 Framework - PyRIT Initializer
PyRIT 0.14.0 内存初始化模块

职责：
- 初始化 PyRIT CentralMemory（SQLite 或内存模式）
- 提供组件初始化状态查询

从 AttackOrchestrator 拆分，遵循单一职责原则。
"""

from __future__ import annotations

import logging

from pyrit.memory import CentralMemory, SQLiteMemory

logger = logging.getLogger(__name__)


class PyRITInitializer:
    """
    PyRIT 0.14.0 内存初始化器

    支持两种模式：
    - in_memory: SQLite 内存数据库（测试/临时使用）
    - persistent: SQLite 持久化数据库（生产使用）

    使用方式：
        initializer = PyRITInitializer(memory_type="in_memory")
        initializer.initialize()
    """

    def __init__(self, memory_type: str = "in_memory"):
        """
        Args:
            memory_type: 内存类型 ("in_memory" 或 "persistent")
        """
        self.memory_type = memory_type
        self._initialized = False

    def initialize(self) -> None:
        """初始化 PyRIT 内存"""
        logger.info("\n######## 初始化 PyRIT ########")
        if self.memory_type == "in_memory":
            memory = SQLiteMemory(db_path=":memory:")
        else:
            memory = SQLiteMemory()
        CentralMemory.set_memory_instance(memory)
        self._initialized = True
        logger.info("PyRIT 0.14.0 initialized with %s memory", self.memory_type)

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized
