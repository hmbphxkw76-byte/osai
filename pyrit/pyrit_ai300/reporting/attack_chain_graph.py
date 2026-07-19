# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Chain Graph Generator (REV-8 / GAP-7)
攻击链 Mermaid 图形化生成器：生成可视化攻击路径图表

核心功能：
1. 基于攻击结果生成 Mermaid 流程图
2. 支持多层级的攻击路径展示
3. 自动化载荷 → 转换器 → 攻击策略 → 评分结果 完整路径
4. 兼容 Markdown 报告格式

Mermaid 参考：
- https://mermaid.js.org/
- 节点类型: rect, circle, diamond, stadium
- 连接线: -->, -.->

对齐文档：docs/architecture_review.md §5.2 GAP-7
预期收益：报告可视化，攻击路径清晰呈现
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackChainGenerator:
    """
    攻击链 Mermaid 图形化生成器 (REV-8)

    基于攻击执行结果生成 Mermaid 格式的攻击路径图表。

    使用方式：
        generator = AttackChainGenerator()
        mermaid_code = generator.generate_chain(attack_results)
        # 输出可嵌入 Markdown: ```mermaid\n{mermaid_code}\n```
    """

    def generate_chain(
        self,
        attack_results: List[Dict[str, Any]],
        max_nodes: int = 20,
    ) -> str:
        """
        生成攻击链 Mermaid 图表

        Args:
            attack_results: 攻击结果列表（来自 AttackOrchestrator）
            max_nodes: 最大节点数（避免图表过大）

        Returns:
            Mermaid 格式的图表代码
        """
        if not attack_results:
            return self._generate_empty_graph()

        # 收集所有攻击节点
        nodes = []
        edges = []
        node_id = 0

        for attack in attack_results:
            attack_name = attack.get("attack_name", "Unknown")
            mode = attack.get("mode", "unknown")
            results = attack.get("results", [])
            success_count = attack.get("success_count", 0)
            total = success_count + attack.get("failure_count", 0)
            success_rate = (success_count / total * 100) if total > 0 else 0

            # 攻击节点
            attack_id = f"attack{node_id}"
            attack_label = self._escape_label(
                f"{attack_name}\\nmode={mode}\\nsuccess={success_rate:.0f}%"
            )
            nodes.append(f"{attack_id}[{attack_label}]")
            node_id += 1

            # 子节点：成功载荷
            if success_count > 0 and node_id < max_nodes:
                success_id = f"success{node_id}"
                success_label = self._escape_label(f"✓ {success_count} payloads passed")
                nodes.append(f"{success_id}({success_label})")
                edges.append(f"{attack_id} -->|bypass| {success_id}")
                node_id += 1

            # 子节点：失败载荷
            failure_count = attack.get("failure_count", 0)
            if failure_count > 0 and node_id < max_nodes:
                fail_id = f"fail{node_id}"
                fail_label = self._escape_label(f"✗ {failure_count} payloads blocked")
                nodes.append(f"{fail_id}[{fail_label}]")
                edges.append(f"{attack_id} -->|blocked| {fail_id}")
                node_id += 1

            # 连接到下一个攻击
            if node_id < max_nodes:
                next_attack_id = f"attack{node_id}"
                edges.append(f"{attack_id} --> {next_attack_id}")

        # 构建 Mermaid 代码
        mermaid = "graph TD\n"
        mermaid += "\n".join(nodes) + "\n"
        mermaid += "\n".join(edges) + "\n"

        # 添加样式
        mermaid += "\n".join(self._get_styles())

        return mermaid

    def generate_detailed_chain(
        self,
        results: Dict[str, Any],
    ) -> str:
        """
        生成详细攻击链（包含载荷、转换器、策略）

        Args:
            results: Smart Match 执行结果

        Returns:
            Mermaid 格式的详细图表
        """
        plan = results.get("plan", [])
        if not plan:
            return self._generate_empty_graph()

        mermaid = "graph TD\n"

        for i, item in enumerate(plan):
            payload = str(item.get("payload", ""))[:40]
            category = item.get("payload_category", "")
            attack_family = item.get("attack_family", "")
            converters = item.get("selected_converters", [])

            # Payload 节点
            payload_id = f"payload{i}"
            payload_label = self._escape_label(
                f"Payload {i+1}: {payload}\\ncat={category}"
            )
            mermaid += f"{payload_id}[{payload_label}]\n"

            # Converter 节点
            if converters:
                conv_id = f"conv{i}"
                conv_label = self._escape_label(f"Converters: {', '.join(converters)}")
                mermaid += f"{conv_id}[{conv_label}]\n"
                mermaid += f"{payload_id} --> {conv_id}\n"

                # Attack Strategy 节点
                strat_id = f"strat{i}"
                strat_label = self._escape_label(f"Strategy: {attack_family}")
                mermaid += f"{strat_id}[{strat_label}]\n"
                mermaid += f"{conv_id} --> {strat_id}\n"

                # 连接到下一个 payload
                if i < len(plan) - 1:
                    mermaid += f"{strat_id} --> payload{i+1}\n"
            else:
                if i < len(plan) - 1:
                    mermaid += f"{payload_id} --> payload{i+1}\n"

        return mermaid

    def generate_kill_chain(self, owasp_ids: List[str]) -> str:
        """
        生成 Kill Chain 流程图（NVIDIA AI Kill Chain 对齐）

        Args:
            owasp_ids: 执行的 OWASP ID 列表

        Returns:
            Mermaid 格式的 Kill Chain 图表
        """
        mermaid = """graph LR
    A[Reconnaissance] --> B[Poisoning]
    B --> C[Hijacking]
    C --> D[Persistence]
    D --> E[Impact]
"""

        # 添加 OWASP 标签
        if owasp_ids:
            mermaid += "\nsubgraph OWASP Classes\n"
            for i, owasp_id in enumerate(owasp_ids):
                mermaid += f"    C{i}[{owasp_id}]\n"
            mermaid += "end\n"

        return mermaid

    def _generate_empty_graph(self) -> str:
        """生成空图表"""
        return """graph TD
    A[No attack data available]
"""

    def _escape_label(self, text: str) -> str:
        """转义 Mermaid 标签中的特殊字符"""
        return (
            text.replace("&", "&amp;")
                .replace("[", "&#91;")
                .replace("]", "&#93;")
                .replace("(", "&#40;")
                .replace(")", "&#41;")
        )

    def _get_styles(self) -> List[str]:
        """获取 Mermaid 样式定义"""
        return [
            "classDef attackNode fill:#f96,stroke:#333,stroke-width:2px",
            "classDef successNode fill:#9f9,stroke:#333,stroke-width:2px",
            "classDef failNode fill:#f99,stroke:#333,stroke-width:2px",
            "classDef payloadNode fill:#bbf,stroke:#333,stroke-width:1px",
            "classDef converterNode fill:#ffb,stroke:#333,stroke-width:1px",
            "classDef strategyNode fill:#bfb,stroke:#333,stroke-width:1px",
        ]


def generate_mermaid_chain(
    attack_results: List[Dict[str, Any]],
    max_nodes: int = 20,
) -> str:
    """便捷函数：生成攻击链 Mermaid 图表"""
    generator = AttackChainGenerator()
    return generator.generate_chain(attack_results, max_nodes)