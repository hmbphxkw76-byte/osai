# -*- coding: utf-8 -*-
"""
评估适配器基类
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ai300_schemas import PyRITTargetConfig, UnifiedFinding


@dataclass
class EvalStrategy:
    """评估策略描述"""

    # 策略唯一名称
    name: str = ""
    # 人类可读说明
    description: str = ""
    # 目标 OWASP LLM 风险编号
    owasp_llm_id: str = ""
    # 工具特定参数（如测试输入、扫描类别）
    tool_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalResult:
    """单次评估执行结果"""

    # 执行该策略的适配器名称
    adapter: str = ""
    # 对应的策略名称
    strategy: str = ""
    # 是否成功完成扫描
    success: bool = False
    # 扫描得到的统一发现列表
    findings: List[UnifiedFinding] = field(default_factory=list)
    # 原始输出（供调试）
    raw_output: Dict[str, Any] = field(default_factory=dict)
    # 错误信息
    error: str = ""


class EvalAdapter(ABC):
    """评估适配器抽象基类"""

    # 适配器名称，子类必须覆盖
    name: str = ""

    def __init__(self, config: Dict[str, Any]):
        """传入配置字典，子类按需读取"""
        self.config = config

    @abstractmethod
    def is_available(self) -> bool:
        """检查当前环境是否可用该适配器"""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        target: PyRITTargetConfig,
        strategy: EvalStrategy,
    ) -> EvalResult:
        """执行评估策略"""
        raise NotImplementedError

    @abstractmethod
    def supported_strategies(self) -> List[str]:
        """返回支持的策略名称列表"""
        raise NotImplementedError
