"""载荷加载器（AI-300 Ch3-Ch9 攻击载荷管理）。

基于 OWASP LLM Top 10 分类的 YAML 载荷库加载器：
  - 从 config/payloads/ 目录按 OWASP 分类加载 YAML 文件
  - 支持 payload（直接载荷）和 payload_template（模板载荷）两种格式
  - 提供 goal 占位符替换功能，生成可执行的攻击载荷

Library-First: 载荷与执行解耦，支持 PyRIT 和 Native 双通道消费
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


class PayloadLoader:
    """YAML 载荷库加载器 — AI-300 攻击载荷统一管理接口。

    使用方式：
        loader = PayloadLoader()
        
        # 按 OWASP 类别加载
        payloads = loader.load_by_category("llm01")
        
        # 按文件路径加载
        payloads = loader.load("config/payloads/llm01/direct_injection.yaml")
        
        # 转换为 Runner 输入格式（替换 {goal} 占位符）
        inputs = loader.to_runner_inputs(payloads, goal="leak system prompt")
    """

    def __init__(
        self,
        payload_dir: str = "config/payloads",
    ):
        self.payload_dir = Path(payload_dir)

    def load(self, yaml_path: str) -> list[dict[str, Any]]:
        """从指定 YAML 文件加载载荷列表。

        Args:
            yaml_path: YAML 文件路径（相对或绝对）

        Returns:
            载荷列表，每个载荷为 dict，包含 technique/name/payload 字段
        """
        path = Path(yaml_path)
        if not path.exists():
            logger.debug("载荷文件不存在: %s（使用内置回退载荷）", yaml_path)
            return []

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict) or "payloads" not in data:
                logger.warning("载荷文件格式错误，缺少 payloads 字段: %s", yaml_path)
                return []

            return data["payloads"]

        except yaml.YAMLError as exc:
            logger.error("YAML 解析失败: %s, 错误: %s", yaml_path, exc)
            return []
        except Exception as exc:
            logger.error("加载载荷文件失败: %s, 错误: %s", yaml_path, exc)
            return []

    def load_by_category(self, category: str) -> list[dict[str, Any]]:
        """按 OWASP 类别加载该类别下所有载荷文件。

        Args:
            category: OWASP 类别名（如 llm01, llm02）

        Returns:
            该类别下所有载荷合并后的列表
        """
        category_dir = self.payload_dir / category
        if not category_dir.exists() or not category_dir.is_dir():
            logger.warning("类别目录不存在: %s", category_dir)
            return []

        all_payloads: list[dict[str, Any]] = []
        for yaml_file in sorted(category_dir.glob("*.yaml")):
            payloads = self.load(str(yaml_file))
            all_payloads.extend(payloads)

        logger.info("从类别 %s 加载了 %d 条载荷", category, len(all_payloads))
        return all_payloads

    def to_runner_inputs(
        self,
        payloads: list[dict[str, Any]],
        goal: str = "",
        **kwargs: str,
    ) -> list[str]:
        """将载荷列表转换为 AttackRunner 可消费的字符串列表。

        支持两种载荷格式：
          - payload: 直接使用字符串值
          - payload_template: 使用 str.format() 替换占位符

        Args:
            payloads: 载荷列表
            goal: 攻击目标，用于替换 {goal} 占位符
            **kwargs: 额外的占位符键值对

        Returns:
            可直接传给 AttackRunner.run() 的字符串列表
        """
        inputs = []
        for payload in payloads:
            content = payload.get("payload", "") or payload.get("payload_template", "")
            if not content:
                continue

            if "{goal}" in content:
                content = content.replace("{goal}", goal)

            if kwargs:
                content = content.format(**kwargs)

            inputs.append(content)

        return inputs

    def get_payloads_by_technique(
        self,
        payloads: list[dict[str, Any]],
        technique: str,
    ) -> list[dict[str, Any]]:
        """按技术类型筛选载荷。

        Args:
            payloads: 原始载荷列表
            technique: 技术类型（如 instruction_override, roleplay）

        Returns:
            匹配的载荷列表
        """
        return [p for p in payloads if p.get("technique") == technique]
