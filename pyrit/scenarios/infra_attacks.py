"""
===============================================================================
OffSec AI-300 — 基础设施与供应链攻击模块 (Module 11-16)
===============================================================================
覆盖 AI-300 Syllabus：
  Module 11 — Model Extraction (模型提取)
  Module 12 — Data Poisoning (训练数据投毒)
  Module 13 — AI Supply Chain Attacks (AI 供应链攻击)
  Module 14 — AI Infra Recon (AI 基础设施侦查)
  Module 15 — API & Endpoint Attacks (API 与端点攻击)
  Module 16 — Model Serving Exploits (模型服务利用)

设计原则：
  ✅ 纯 YAML 驱动 — 多文件加载，每个模块对应独立的 payload YAML 文件
  ✅ 零硬编码回退 — YAML 为唯一真相源
  ✅ 复用 scenarios/payloads.py 统一 Provider

YAML 文件映射：
  - model_extraction_payloads.yaml  → Module 11 (模型提取)
  - data_poison_payloads.yaml       → Module 12 (数据投毒)
  - supply_chain_payloads.yaml      → Module 13 (供应链)
  - infra_payloads.yaml             → Modules 14-16 (基础设施)
===============================================================================
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# 1. 枚举
# ═══════════════════════════════════════════════════════════════════

class InfraAttackType(str, Enum):
    API_FUZZ = "api_fuzz"
    MODEL_SERVING = "model_serving"
    SUPPLY_CHAIN = "supply_chain"
    MODEL_EXTRACT = "model_extract"
    DATA_POISON = "data_poison"
    CLOUD_RECON = "cloud_recon"
    AUTH_BYPASS = "auth_bypass"


# ═══════════════════════════════════════════════════════════════════
# 2. 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class InfraPayload:
    text: str
    attack_type: InfraAttackType
    target_endpoint: str = "/v1/chat/completions"
    http_method: str = "POST"
    requires_file: bool = False
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "attack_type": self.attack_type.value,
            "target_endpoint": self.target_endpoint,
            "http_method": self.http_method,
            "requires_file": self.requires_file,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 统一 Payload 获取 — 通过 ModulePayloadProvider（纯 YAML）
# ═══════════════════════════════════════════════════════════════════

def _get_infra_provider():
    """延迟获取 ModulePayloadProvider（避免循环导入）。"""
    from scenarios.payloads import get_provider
    return get_provider()


# 子模块 key → (module_key, section_key) 映射
# module_key 用于查找 YAML 文件名，section_key 用于提取 YAML payloads 节
_INFRA_SECTION_MAP: dict[str, tuple[str, str]] = {
    # Modules 14-16: infra_payloads.yaml 内的 section
    "api_fuzz":       ("infra",          "api_fuzz"),
    "model_serving":  ("infra",          "model_serving"),
    "cloud_recon":    ("infra",          "cloud_recon"),
    "auth_bypass":    ("infra",          "auth_bypass"),
    # Module 13: 独立文件 supply_chain_payloads.yaml
    "supply_chain":   ("supply_chain",   "supply_chain"),
    # Module 11: 独立文件 model_extraction_payloads.yaml
    "model_extract":  ("model_extract",  "model_extract"),
    # Module 12: 独立文件 data_poison_payloads.yaml
    "data_poison":    ("data_poison",    "data_poison"),
}


def _get_infra_texts(sub_key: str) -> list[str]:
    """从 YAML 获取 Infra payload 文本 — 纯 YAML，零硬编码回退。

    支持多文件加载：infra_payloads / supply_chain / model_extraction / data_poison。
    """
    if sub_key not in _INFRA_SECTION_MAP:
        logger.warning("InfraPayloadGenerator: 未知 sub_key=%s", sub_key)
        return []
    module_key, section_key = _INFRA_SECTION_MAP[sub_key]
    return _get_infra_provider().get(module_key, section_key)


# ═══════════════════════════════════════════════════════════════════
# 4. 生成器
# ═══════════════════════════════════════════════════════════════════

class InfraPayloadGenerator:
    """基础设施与供应链攻击 Payload 生成器 — 纯 YAML 驱动。

    使用方式：
        >>> gen = InfraPayloadGenerator()
        >>> payloads = gen.generate("infra_attack")
    """

    def generate(
        self, category: str, objective: str = "", *, max_payloads: int = 10,
    ) -> list[InfraPayload]:
        payloads: list[InfraPayload] = []

        if category == "infra_attack":
            for text in _get_infra_texts("api_fuzz")[:4]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.API_FUZZ,
                    description="API 模糊探测",
                ))
            for text in _get_infra_texts("model_serving")[:3]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.MODEL_SERVING,
                    description="模型服务利用",
                ))
            for text in _get_infra_texts("cloud_recon")[:4]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.CLOUD_RECON,
                    description="AI 云基础设施侦查",
                ))
            for text in _get_infra_texts("auth_bypass")[:4]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.AUTH_BYPASS,
                    description="API 认证绕过",
                ))

        elif category == "supply_chain":
            for text in _get_infra_texts("supply_chain")[:8]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.SUPPLY_CHAIN,
                    description="供应链安全检测",
                ))

        elif category == "model_extract":
            for text in _get_infra_texts("model_extract")[:8]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.MODEL_EXTRACT,
                    description="模型提取",
                ))

        elif category == "data_poison":
            for text in _get_infra_texts("data_poison")[:8]:
                payloads.append(InfraPayload(
                    text=text, attack_type=InfraAttackType.DATA_POISON,
                    description="训练数据投毒",
                ))

        if objective and len(payloads) < max_payloads:
            for seed in payloads[:3]:
                text = seed.text.replace("deployment_name", f"deployment_name-{objective[:15]}")
                payloads.append(InfraPayload(
                    text=text, attack_type=seed.attack_type,
                    target_endpoint=seed.target_endpoint,
                    description=f"定制化: {objective[:30]}",
                ))
        return payloads[:max_payloads]

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        strategy_map: dict[str, str] = {
            "api_fuzz":             "api_fuzz",
            "model_serving_exploit": "model_serving",
            "supply_chain_scan":    "supply_chain",
        }
        section_key = strategy_map.get(strategy_name, "")
        if section_key:
            return _get_infra_texts(section_key)
        return []
