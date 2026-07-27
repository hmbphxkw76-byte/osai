# -*- coding: utf-8 -*-
"""
攻击适配器基类
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ai300_schemas import PyRITTargetConfig, UnifiedFinding


@dataclass
class AttackStrategy:
    """攻击策略描述"""

    name: str = ""
    description: str = ""
    # 目标 OWASP LLM 风险编号
    owasp_llm_id: str = ""
    # 工具特定参数
    tool_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """单次攻击执行结果"""

    adapter: str = ""
    strategy: str = ""
    success: bool = False
    findings: List[UnifiedFinding] = field(default_factory=list)
    raw_output: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


class AttackAdapter(ABC):
    """攻击适配器抽象基类"""

    name: str = ""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    def is_available(self) -> bool:
        """检查当前环境是否可用该适配器"""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        target: PyRITTargetConfig,
        strategy: AttackStrategy,
    ) -> AttackResult:
        """执行攻击策略"""
        raise NotImplementedError

    @abstractmethod
    def supported_strategies(self) -> List[str]:
        """返回支持的策略名称列表"""
        raise NotImplementedError
