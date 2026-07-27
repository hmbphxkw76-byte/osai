# -*- coding: utf-8 -*-
"""
PyRIT Target Config
===================

ai300-recon 导出、ai300-attack 消费的 PyRIT PromptTarget 配置契约。

保持字段与 PyRIT 0.14+ 的 PromptTarget 构造参数对齐，但不直接依赖 PyRIT。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class PyRITTargetConfig:
    """PyRIT PromptTarget 配置"""

    # PromptTarget 类型名
    target_type: str = "HTTPTarget"
    # 目标 endpoint（API URL 或页面 URL）
    endpoint: str = ""
    # 模型名称
    model_name: str = ""
    # API 类型：openai_compatible / azure / anthropic 等
    api_type: str = "openai_compatible"
    # API key / token
    api_key: Optional[str] = None
    # 额外请求头
    headers: Dict[str, str] = field(default_factory=dict)
    # HTTP 方法（HTTPTarget 用）
    http_method: str = "POST"
    # 请求体模板（HTTPTarget 用，可选）
    body_template: Optional[str] = None
    # 超时秒数
    timeout: int = 60
    # 浏览器选择器（PlaywrightTarget 用）
    input_selector: str = ""
    send_selector: str = ""
    response_selector: str = ""
    # 浏览器状态文件路径
    storage_state_path: Optional[str] = None
    # 任意附加配置
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PyRITTargetConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "PyRITTargetConfig":
        return cls.from_dict(json.loads(text))
