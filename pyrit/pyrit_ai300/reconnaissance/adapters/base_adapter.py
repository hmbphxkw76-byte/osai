# -*- coding: utf-8 -*-
"""
AI-300 Framework - Base Adapter
适配器抽象基类：定义所有侦察适配器的统一接口

设计原则：
- 薄壳模式：仅做格式转换，不做业务逻辑
- 统一返回格式：AdapterResult
- 超时控制：所有适配器必须支持超时
"""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


@dataclass
class AdapterResult:
    """适配器统一返回格式"""
    tool: str = ""                          # 工具名称
    success: bool = False                   # 是否成功
    data: Dict[str, Any] = field(default_factory=dict)  # 原始结果
    findings: List[Dict[str, Any]] = field(default_factory=list)  # 标准化发现
    errors: List[str] = field(default_factory=list)  # 错误信息
    duration: float = 0.0                   # 执行耗时（秒）
    raw_output: str = ""                    # 原始输出（调试用）

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "success": self.success,
            "data": self.data,
            "findings": self.findings,
            "errors": self.errors,
            "duration": self.duration,
        }


class BaseAdapter(ABC):
    """
    侦察适配器抽象基类

    所有适配器必须实现：
    - name 属性：工具名称
    - run() 方法：执行侦察并返回 AdapterResult
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """工具名称标识"""
        ...

    @abstractmethod
    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行侦察

        Args:
            target: 目标 URL/endpoint
            config: 工具配置字典

        Returns:
            AdapterResult 统一格式结果
        """
        ...

    def check_available(self) -> bool:
        """
        检查工具是否可用（可覆盖）

        Returns:
            True 表示工具可用
        """
        return True

    def _make_error_result(self, error_msg: str) -> AdapterResult:
        """创建错误结果"""
        return AdapterResult(
            tool=self.name,
            success=False,
            errors=[error_msg],
        )
