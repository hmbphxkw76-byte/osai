# -*- coding: utf-8 -*-
"""
Pipeline Context
================

Pipeline 执行上下文，贯穿整个侦察流程，承载阶段间共享数据。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StageResult:
    """单个阶段执行结果"""

    stage_name: str = ""
    success: bool = False
    skipped: bool = False
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "success": self.success,
            "skipped": self.skipped,
            "message": self.message,
            "data": self.data,
            "duration_ms": self.duration_ms,
        }


@dataclass
class PipelineContext:
    """Pipeline 全局上下文"""

    # 输入参数
    target_url: str = ""
    target_type: str = "auto"
    headless: bool = False
    config: Dict[str, Any] = field(default_factory=dict)

    # 中间产物
    credential_resolution: Optional[Any] = None
    auth_profile: Optional[Any] = None
    browser_manager: Optional[Any] = None
    page: Optional[Any] = None
    dom_detector: Optional[Any] = None
    interceptor: Optional[Any] = None
    chat_entry: Optional[Dict[str, Any]] = None
    detection: Optional[Dict[str, Any]] = None
    send_result: Optional[Dict[str, Any]] = None

    # 最终结果
    profile: Optional[Any] = None

    # 阶段执行记录
    stage_results: List[StageResult] = field(default_factory=list)

    def add_result(self, result: StageResult) -> None:
        """添加阶段结果"""
        self.stage_results.append(result)

    def get_result(self, stage_name: str) -> Optional[StageResult]:
        """按阶段名获取结果"""
        for r in self.stage_results:
            if r.stage_name == stage_name:
                return r
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_type": self.target_type,
            "headless": self.headless,
            "stage_results": [r.to_dict() for r in self.stage_results],
        }
