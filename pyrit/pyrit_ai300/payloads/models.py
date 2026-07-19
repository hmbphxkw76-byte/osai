# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payload Models
数据模型：ThreatModel + PayloadProfile

PyRIT 0.14.0 兼容
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


@dataclass
class ThreatModel:
    """
    威胁模型：描述攻击者的能力和约束

    借鉴 SoK Taxonomy（arXiv:2510.15476）五维评估框架：
    (model, attack, defense, dataset, judger)
    """
    access_level: str = "black_box"      # black_box / white_box / gray_box
    cost_budget: float = 1.0             # 攻击成本预算 (0.0-1.0)
    knowledge_level: str = "public"      # public / internal / full
    execution_constraints: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_level": self.access_level,
            "cost_budget": self.cost_budget,
            "knowledge_level": self.knowledge_level,
            "execution_constraints": self.execution_constraints,
        }


@dataclass
class PayloadProfile:
    """
    载荷多维分析结果

    五个独立维度 + 置信度 + 目标模型感知 + 威胁模型：
    - length_class:   short / medium / long / context_overflow
    - encoding_state: plain / encoded / obfuscated / multi_encoded
    - language:       en / zh / ja / ko / ar / cyrillic / mixed / other
    - technique:      14 种技术类别
    - complexity:     simple / moderate / complex

    附加信息：
    - token_count:    估算 token 数
    - char_count:     字符数
    - tags:           标签集合（自由扩展）
    - confidence:     各维度置信度 {dimension: 0.0-1.0}
    - context_window: 目标模型上下文窗口大小
    - asi_category:   关联的 ASI 类别（可选）
    - normalized_text: 归一化后的文本
    - threat_model:   威胁模型
    """
    length_class: str = "short"
    encoding_state: str = "plain"
    language: str = "en"
    technique: str = "direct"
    complexity: str = "simple"
    token_count: int = 0
    char_count: int = 0
    tags: Set[str] = field(default_factory=set)
    confidence: Dict[str, float] = field(default_factory=dict)
    context_window: int = 8192
    asi_category: str = ""
    normalized_text: str = ""
    threat_model: Optional[ThreatModel] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "length_class": self.length_class,
            "encoding_state": self.encoding_state,
            "language": self.language,
            "technique": self.technique,
            "complexity": self.complexity,
            "token_count": self.token_count,
            "char_count": self.char_count,
            "tags": sorted(self.tags),
            "confidence": dict(self.confidence),
            "context_window": self.context_window,
            "asi_category": self.asi_category,
            "normalized_text": self.normalized_text,
            "attack_surface_score": self.attack_surface_score,
            "avg_confidence": self.avg_confidence,
            "needs_multi_strategy": self.needs_multi_strategy,
        }
        if self.threat_model:
            result["threat_model"] = self.threat_model.to_dict()
        return result

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PayloadProfile":
        """
        从字典重建 PayloadProfile（与 to_dict 互补）

        用于编排器从攻击计划中恢复完整的 PayloadProfile 实例，
        避免手动逐字段构造导致的信息丢失。
        """
        threat_model = None
        tm_dict = d.get("threat_model")
        if tm_dict and isinstance(tm_dict, dict):
            threat_model = ThreatModel(
                access_level=tm_dict.get("access_level", "black_box"),
                cost_budget=tm_dict.get("cost_budget", 1.0),
                knowledge_level=tm_dict.get("knowledge_level", "public"),
                execution_constraints=tm_dict.get("execution_constraints", {}),
            )
        tags_val = d.get("tags", [])
        if isinstance(tags_val, list):
            tags_val = set(tags_val)
        elif not isinstance(tags_val, set):
            tags_val = set()
        conf_val = d.get("confidence", {})
        if not isinstance(conf_val, dict):
            conf_val = {}
        return cls(
            length_class=d.get("length_class", "short"),
            encoding_state=d.get("encoding_state", "plain"),
            language=d.get("language", "en"),
            technique=d.get("technique", "direct"),
            complexity=d.get("complexity", "simple"),
            token_count=d.get("token_count", 0),
            char_count=d.get("char_count", 0),
            tags=tags_val,
            confidence=conf_val,
            context_window=d.get("context_window", 8192),
            asi_category=d.get("asi_category", ""),
            normalized_text=d.get("normalized_text", ""),
            threat_model=threat_model,
        )

    @property
    def primary_category(self) -> str:
        """
        向后兼容：返回单一主类别（用于旧接口）
        优先级：encoding_state > technique > length_class
        （编码状态优先：已编码载荷应直接投递，不需要根据解码内容选择策略）
        """
        if self.encoding_state in ("encoded", "multi_encoded"):
            return "encoded"
        if self.technique in ("role_play", "prompt_leaking", "adversarial",
                              "markdown_injection", "indirect_injection",
                              "context_splitting", "instruction_override",
                              "payload_splitting", "data_exfiltration",
                              "cross_context_contamination", "context_manipulation"):
            return self.technique
        if self.length_class == "context_overflow":
            return "long_context"
        if self.length_class == "long":
            return "long_context"
        if self.language != "en":
            return "multilingual"
        return "direct_short"

    @property
    def attack_surface_score(self) -> float:
        """
        攻击面评分：综合评估可利用性

        借鉴 SoK Taxonomy（arXiv:2510.15476）五维评估框架，
        结合威胁模型信息计算攻击面评分。
        """
        score = 0.0
        if self.threat_model:
            if self.threat_model.access_level == "black_box":
                score += 0.3
            elif self.threat_model.access_level == "gray_box":
                score += 0.6
            else:
                score += 1.0
            # 成本预算影响
            score += self.threat_model.cost_budget * 0.2
        else:
            score += 0.5  # 默认中等
        # 编码状态影响攻击面
        if self.encoding_state == "encoded":
            score += 0.1
        elif self.encoding_state == "multi_encoded":
            score += 0.15
        return min(1.0, score)

    @property
    def avg_confidence(self) -> float:
        """平均置信度"""
        if not self.confidence:
            return 1.0
        return sum(self.confidence.values()) / len(self.confidence)

    @property
    def needs_multi_strategy(self) -> bool:
        """是否需要多策略尝试（低置信度时）"""
        return self.avg_confidence < 0.6
