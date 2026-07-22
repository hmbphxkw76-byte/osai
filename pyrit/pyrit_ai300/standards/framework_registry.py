# -*- coding: utf-8 -*-
"""
AI-300 Framework - 框架注册表

灵感来源：DeepTeam 的框架选择机制

提供统一入口，根据框架 ID 获取框架实例。
支持 YAML 配置 → 框架实例的动态加载。
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .framework_base import AISafetyFramework
from .owasp_llm_framework import OWASPLinearFramework2025
from .owasp_asi_framework import OWASPAgenticFramework2026


# ── 框架注册表 ──
_FRAMEWORK_REGISTRY: Dict[str, type] = {
    "owasp_llm_2025": OWASPLinearFramework2025,
    "owasp_asi_2026": OWASPAgenticFramework2026,
}

# ── 框架实例缓存 ──
_FRAMEWORK_INSTANCES: Dict[str, AISafetyFramework] = {}


def register_framework(framework_id: str, framework_class: type) -> None:
    """注册新框架"""
    if not issubclass(framework_class, AISafetyFramework):
        raise TypeError(f"{framework_class} must inherit from AISafetyFramework")
    _FRAMEWORK_REGISTRY[framework_id] = framework_class
    # 清除缓存
    _FRAMEWORK_INSTANCES.pop(framework_id, None)


def get_framework(framework_id: str) -> Optional[AISafetyFramework]:
    """
    根据框架 ID 获取框架实例

    Args:
        framework_id: 框架标识（如 "owasp_llm_2025"）

    Returns:
        框架实例，未找到返回 None
    """
    # 检查缓存
    if framework_id in _FRAMEWORK_INSTANCES:
        return _FRAMEWORK_INSTANCES[framework_id]

    # 查找注册表
    cls = _FRAMEWORK_REGISTRY.get(framework_id)
    if cls is None:
        return None

    # 创建实例并缓存
    instance = cls()
    _FRAMEWORK_INSTANCES[framework_id] = instance
    return instance


def list_frameworks() -> List[str]:
    """获取所有已注册的框架 ID"""
    return sorted(_FRAMEWORK_REGISTRY.keys())


def get_framework_info(framework_id: str) -> Optional[Dict]:
    """
    获取框架元信息（不创建实例）

    Returns:
        {framework_id, framework_name, framework_version}
    """
    cls = _FRAMEWORK_REGISTRY.get(framework_id)
    if cls is None:
        return None
    # 使用类属性获取信息（不实例化）
    return {
        "framework_id": cls.framework_id.fget(cls),
        "framework_name": cls.framework_name.fget(cls),
        "framework_version": cls.framework_version.fget(cls),
    }


def get_all_frameworks_info() -> List[Dict]:
    """获取所有框架的元信息"""
    return [info for info in (get_framework_info(fid) for fid in list_frameworks()) if info]


def framework_to_yaml(framework_id: str) -> str:
    """
    将框架定义序列化为 YAML 格式字符串

    Args:
        framework_id: 框架 ID

    Returns:
        YAML 格式的框架定义
    """
    framework = get_framework(framework_id)
    if framework is None:
        return f"# Framework '{framework_id}' not found"

    data = framework.to_dict()
    # 简单的 YAML 序列化（不依赖 PyYAML）
    lines = [
        f"framework_id: {data['framework_id']}",
        f"framework_name: {data['framework_name']}",
        f"framework_version: {data['framework_version']}",
        "",
        "vulnerabilities:",
    ]
    for v in data["vulnerabilities"]:
        lines.append(f"  - vuln_id: {v['vuln_id']}")
        lines.append(f"    title: \"{v['title']}\"")
        lines.append(f"    severity: {v['severity']}")
        lines.append(f"    risk_category: \"{v['risk_category']}\"")
        lines.append(f"    attacks: [{', '.join(v['attacks'])}]")
        lines.append("")

    lines.append("risk_categories:")
    for cat in data["risk_categories"]:
        lines.append(f"  - {cat}")

    return "\n".join(lines)


def framework_to_json(framework_id: str, indent: int = 2) -> str:
    """将框架定义序列化为 JSON 格式字符串"""
    framework = get_framework(framework_id)
    if framework is None:
        return json.dumps({"error": f"Framework '{framework_id}' not found"})
    return json.dumps(framework.to_dict(), indent=indent, ensure_ascii=False)


def select_framework_from_config(config: dict) -> Optional[AISafetyFramework]:
    """
    从配置字典中选择框架

    支持的配置格式：
        framework: "owasp_llm_2025"
        # 或
        framework:
          id: "owasp_llm_2025"
          version: "2025.1"

    Args:
        config: 配置字典

    Returns:
        框架实例，未找到返回 None
    """
    fw_config = config.get("framework")
    if not fw_config:
        return None

    if isinstance(fw_config, str):
        return get_framework(fw_config)
    elif isinstance(fw_config, dict):
        fw_id = fw_config.get("id", "")
        return get_framework(fw_id)

    return None
