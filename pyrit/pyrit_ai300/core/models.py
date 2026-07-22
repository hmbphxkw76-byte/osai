# -*- coding: utf-8 -*-
"""
AI-300 Framework - Core Data Models
共享数据模型：跨模块通用的数据结构基类和接口定义

设计原则：
- 仅依赖 Python 标准库
- 定义数据契约（非具体实现），业务模块继承/实现
- ProfileContract: 侦察画像的标准化接口契约
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class EndpointInfo:
    """
    端点信息：标准化的 API 端点描述

    Attributes:
        url: 端点 URL
        method: HTTP 方法
        auth_type: 认证类型
        protocols: 支持的协议列表
    """
    url: str = ""
    method: str = "POST"
    auth_type: str = ""
    protocols: List[str] = field(default_factory=list)


@dataclass
class FingerprintContract:
    """
    指纹契约：标准化的目标模型指纹

    被侦察模块填充，被攻击模块消费。

    Attributes:
        model_name: 模型名称
        model_family: 模型族系
        endpoint: API 端点
        capabilities: 能力列表
        context_window: 上下文窗口大小
    """
    model_name: str = ""
    model_family: str = ""
    endpoint: str = ""
    capabilities: List[str] = field(default_factory=list)
    context_window: int = 0


@runtime_checkable
class ProfileContract(Protocol):
    """
    侦察画像契约：定义侦察画像必须实现的接口

    侦察模块产出的 TargetProfile 必须实现此契约，
    攻击模块通过此契约消费侦察结果，实现解耦。
    """

    @property
    def target_url(self) -> str:
        """目标 URL"""
        ...

    @property
    def vulnerability_count(self) -> int:
        """漏洞数量"""
        ...

    @property
    def risk_level(self) -> str:
        """风险等级"""
        ...

    @property
    def surfaces(self) -> List[str]:
        """攻击面列表"""
        ...

    @property
    def entry_points(self) -> List[Dict[str, Any]]:
        """入口点列表"""
        ...

    @property
    def fingerprint(self) -> Optional[FingerprintContract]:
        """目标指纹"""
        ...

    def save(self, path: str) -> None:
        """保存画像到文件"""
        ...

    def get_owasp_mappings(self) -> List[str]:
        """获取 OWASP 映射"""
        ...
