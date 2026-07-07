"""
===============================================================================
OffSec AI-300 — 统一 Payload 提供层 (PyRIT-aligned)
===============================================================================
PyRIT 对齐: 本模块 = SeedPromptDataset.from_yaml_file() + converter selection。

设计原则:
  ✅ 纯 YAML 驱动 — datasets/payloads/*.yaml 为唯一真相源 (Single Source of Truth)
  ✅ 零硬编码回退 — 所有 payload 从 YAML 加载，YAML 缺失则报错而非静默回退
  ✅ 全模块覆盖 — 12 个 payload 文件 → 统一 Provider → 各 Generator
  ✅ 单管道入口   — scenarios/orchestrator.py 仅通过本模块获取 payload

架构:
  datasets/payloads/*.yaml
       ↓
  datasets/payload_loader.py (UnifiedPayloadLoader)
       ↓
  scenarios/payloads.py (ModulePayloadProvider)  ← 本模块
       ↓
  scenarios/orchestrator.py (ExamAutoOrchestrator)

使用:
  from scenarios.payloads import ModulePayloadProvider, get_payloads
  provider = ModulePayloadProvider("zh")
  texts = provider.get("rag", "data_leakage")          # → list[str]
  texts = provider.get("prompt_injection", "direct_extract")
  gen = provider.generator_for("prompt_injection")
  payloads = gen.generate("prompt_injection", max_payloads=6)
===============================================================================
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# 1. 统一 Payload 提供器 — 单点 YAML 加载入口
# ═══════════════════════════════════════════════════════════════════

class ModulePayloadProvider:
    """统一 Payload 提供器 — 所有模块的 payload 加载入口。

    PyRIT 对齐: 等价于 SeedPromptDataset.from_yaml_file() 工厂方法。

    用法:
        provider = ModulePayloadProvider("zh")
        texts = provider.get("rag", "data_leakage")
        texts = provider.get("prompt_injection", "direct_extract")
        sections = provider.list_sections("jailbreak")
        gen = provider.generator_for("prompt_injection")
    """

    # 模块 key → YAML 文件名映射（与 data/payload_loader.py 的 MODULE_FILE_MAP 对齐）
    MODULE_FILE_MAP: dict[str, str] = {
        "prompt_injection": "prompt_injection_payloads.yaml",
        "jailbreak":          "jailbreak_payloads.yaml",
        "exfiltration":        "exfiltration_payloads.yaml",
        "output_handling":    "output_handling_payloads.yaml",
        "rag":                "rag_payloads.yaml",
        "agent":              "agent_payloads.yaml",
        "infra":              "infra_payloads.yaml",
        # infra_attacks 下属子模块
        "api_fuzz":           "infra_payloads.yaml",
        "model_serving":      "infra_payloads.yaml",
        "cloud_recon":        "infra_payloads.yaml",
        "auth_bypass":        "infra_payloads.yaml",
        "supply_chain":       "supply_chain_payloads.yaml",
        "model_extract":      "model_extraction_payloads.yaml",
        "data_poison":        "data_poison_payloads.yaml",
    }

    def __init__(self, lang: str = "zh"):
        self.lang = lang
        self._loader = None     # 延迟初始化 UnifiedPayloadLoader
        self._cache: dict[str, dict[str, list[str]]] = {}

    @property
    def loader(self):
        if self._loader is None:
            from datasets.payload_loader import UnifiedPayloadLoader
            self._loader = UnifiedPayloadLoader(self.lang)
        return self._loader

    def _load_yaml(self, module_key: str) -> dict[str, list[str]]:
        """加载模块对应的 YAML 文件，返回 {section_key: [payload_texts]}。

        YAML 缺失或为空时返回空 dict（调用方负责处理）。
        """
        filename = self.MODULE_FILE_MAP.get(module_key)
        if not filename:
            logger.warning("ModulePayloadProvider: 未知模块 key=%s", module_key)
            return {}

        if filename in self._cache:
            return self._cache[filename]

        sections = self.loader.get_module_sections(filename)
        if sections is None:
            logger.warning("ModulePayloadProvider: YAML 加载失败 key=%s file=%s", module_key, filename)
            sections = {}

        self._cache[filename] = sections
        return sections

    def get(self, module_key: str, section_key: str) -> list[str]:
        """获取指定模块 + section 的 payload 文本列表。

        Args:
            module_key: 模块标识符 (如 "prompt_injection", "rag", "api_fuzz")
            section_key: YAML section 名称 (如 "direct_extract", "data_leakage")

        Returns:
            payload 文本列表，YAML 中无对应 section 时返回空列表
        """
        sections = self._load_yaml(module_key)
        result = sections.get(section_key, [])
        if not result:
            logger.warning(
                "ModulePayloadProvider: section 为空 key=%s section=%s (YAML 可能缺少此节)",
                module_key, section_key,
            )
        return result

    def list_sections(self, module_key: str) -> list[str]:
        """列出指定模块 YAML 中的所有 section 名称。"""
        sections = self._load_yaml(module_key)
        return list(sections.keys())

    def module_available(self, module_key: str) -> bool:
        """检查模块是否有可用的 payload（YAML 文件存在且非空）。"""
        sections = self._load_yaml(module_key)
        return len(sections) > 0

    def generator_for(self, module_key: str):
        """根据模块 key 返回对应的 PayloadGenerator。

        返回的 generator 实现 generate(category, objective, max_payloads) 接口。
        """
        generators = {
            "prompt_injection": PromptInjectionPayloadGenerator,
            "jailbreak":        JailbreakPayloadGenerator,
            "exfiltration":     ExfiltrationPayloadGenerator,
            "output_handling":  OutputHandlingPayloadGenerator,
            "rag":              lambda: RAGPayloadGenerator(self),
            "agent":            lambda: AgentPayloadGenerator(self),
            "infra":            lambda: InfraPayloadGenerator(self),
        }
        gen = generators.get(module_key)
        if gen is None:
            logger.warning("ModulePayloadProvider: 无 generator for key=%s", module_key)
            return None
        return gen() if callable(gen) else gen


# ── 全局单例（延迟初始化，避免 PyRIT 循环导入）──
_provider: Optional[ModulePayloadProvider] = None


def get_payloads(module_key: str, section_key: str) -> list[str]:
    """快捷函数：获取指定 section 的 payload 文本列表。"""
    global _provider
    if _provider is None:
        _provider = ModulePayloadProvider()
    return _provider.get(module_key, section_key)


def get_provider() -> ModulePayloadProvider:
    """获取全局 ModulePayloadProvider 单例。"""
    global _provider
    if _provider is None:
        _provider = ModulePayloadProvider()
    return _provider


# ═══════════════════════════════════════════════════════════════════
# 2. 通用 Payload 数据类（所有模块共用）
# ═══════════════════════════════════════════════════════════════════

@dataclass
class GenericPayload:
    """通用 payload 数据类 — 所有新模块统一使用此结构。

    已有特定数据类（RAGPayload, AgentPayload, InfraPayload）保持向后兼容，
    新增的 prompt_injection / jailbreak / exfiltration / output_handling 模块
    使用此通用类。
    """
    text: str
    section_key: str
    module_key: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "section_key": self.section_key,
            "module_key": self.module_key,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 🆕 之前孤立的 Payload Generator（覆盖 Module 04-07）
# ═══════════════════════════════════════════════════════════════════

class PromptInjectionPayloadGenerator:
    """Prompt 注入攻击 Payload 生成器 (Module 04)。

    覆盖: 直接注入、角色覆盖、分隔符注入、间接注入、隐藏文本、
           跨上下文注入、指令层级绕过、多轮注入

    数据源: datasets/payloads/prompt_injection_payloads.yaml (纯 YAML)
    """

    SECTION_MAP: dict[str, list[str]] = {
        "prompt_injection": [
            "direct_extract", "role_override", "delimiter_inject",
            "indirect_content", "hidden_text",
            "cross_context", "hierarchy_bypass", "multi_turn",
        ],
    }

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self._provider = provider or get_provider()

    def generate(
        self, category: str = "", objective: str = "",
        *, max_payloads: int = 8,
    ) -> list[GenericPayload]:
        """生成 Prompt 注入攻击 payload 列表。"""
        payloads: list[GenericPayload] = []
        section_keys = self.SECTION_MAP.get(category, self.SECTION_MAP.get("prompt_injection", []))

        for sk in section_keys:
            texts = self._provider.get("prompt_injection", sk)
            for text in texts[:2]:  # 每 section 最多取 2 条
                payloads.append(GenericPayload(
                    text=text, section_key=sk,
                    module_key="prompt_injection",
                    description=f"Prompt注入-{sk}",
                ))
                if len(payloads) >= max_payloads:
                    return payloads
        return payloads


class JailbreakPayloadGenerator:
    """越狱攻击 Payload 生成器 (Module 05)。

    覆盖: 角色扮演、开发者模式、学术框架、编码混淆、多语言、
           情感操控、假设场景、渐进越狱、Token操作

    数据源: datasets/payloads/jailbreak_payloads.yaml (纯 YAML)
    """

    SECTION_MAP: dict[str, list[str]] = {
        "jailbreak": [
            "roleplay", "developer_mode", "academic", "encoding",
            "multilingual", "emotional", "hypothetical", "gradual", "token_manip",
        ],
    }

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self._provider = provider or get_provider()

    def generate(
        self, category: str = "", objective: str = "",
        *, max_payloads: int = 10,
    ) -> list[GenericPayload]:
        """生成越狱攻击 payload 列表。"""
        payloads: list[GenericPayload] = []
        section_keys = self.SECTION_MAP.get(category, self.SECTION_MAP.get("jailbreak", []))

        for sk in section_keys:
            texts = self._provider.get("jailbreak", sk)
            for text in texts[:2]:
                payloads.append(GenericPayload(
                    text=text, section_key=sk,
                    module_key="jailbreak",
                    description=f"越狱-{sk}",
                ))
                if len(payloads) >= max_payloads:
                    return payloads
        return payloads


class ExfiltrationPayloadGenerator:
    """数据外泄攻击 Payload 生成器 (Module 06)。

    覆盖: PII提取、训练数据重建、系统提示词提取、凭证窃取、知识库泄露

    数据源: datasets/payloads/exfiltration_payloads.yaml (纯 YAML)
    """

    SECTION_MAP: dict[str, list[str]] = {
        "exfiltration": [
            "pii_extract", "training_reconstruct", "system_prompt_extract",
        ],
    }

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self._provider = provider or get_provider()

    def generate(
        self, category: str = "", objective: str = "",
        *, max_payloads: int = 6,
    ) -> list[GenericPayload]:
        """生成数据外泄攻击 payload 列表。"""
        payloads: list[GenericPayload] = []
        section_keys = self.SECTION_MAP.get(category, self.SECTION_MAP.get("exfiltration", []))

        for sk in section_keys:
            texts = self._provider.get("exfiltration", sk)
            for text in texts[:3]:
                payloads.append(GenericPayload(
                    text=text, section_key=sk,
                    module_key="exfiltration",
                    description=f"数据外泄-{sk}",
                ))
                if len(payloads) >= max_payloads:
                    return payloads
        return payloads


class OutputHandlingPayloadGenerator:
    """不安全输出处理攻击 Payload 生成器 (Module 07)。

    覆盖: XSS via LLM、SQL注入 via 输出、命令注入 via 输出

    数据源: datasets/payloads/output_handling_payloads.yaml (纯 YAML)
    """

    SECTION_MAP: dict[str, list[str]] = {
        "output_handling": [
            "xss_output", "sql_output",
        ],
    }

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self._provider = provider or get_provider()

    def generate(
        self, category: str = "", objective: str = "",
        *, max_payloads: int = 6,
    ) -> list[GenericPayload]:
        """生成不安全输出处理攻击 payload 列表。"""
        payloads: list[GenericPayload] = []
        section_keys = self.SECTION_MAP.get(category, self.SECTION_MAP.get("output_handling", []))

        for sk in section_keys:
            texts = self._provider.get("output_handling", sk)
            for text in texts[:3]:
                payloads.append(GenericPayload(
                    text=text, section_key=sk,
                    module_key="output_handling",
                    description=f"输出处理-{sk}",
                ))
                if len(payloads) >= max_payloads:
                    return payloads
        return payloads


# ═══════════════════════════════════════════════════════════════════
# 4. 已有模块 Generator 包装（rag/agent/infra — 委托给原模块，避免循环导入）
# ═══════════════════════════════════════════════════════════════════


class RAGPayloadGenerator:
    """RAG 管道攻击 Payload 生成器 (Module 8) — 延迟委托。

    实际生成逻辑在 scenarios/rag_attacks.py (已移除硬编码回退，纯 YAML)。
    本类作为统一入口，通过 ModulePayloadProvider 初始化上下文。
    """

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self.provider = provider or get_provider()
        self._gen = None

    def _ensure_gen(self):
        if self._gen is None:
            # 延迟导入避免与 scenarios/rag_attacks.py 循环导入
            from scenarios.rag_attacks import RAGPayloadGenerator as _RAGGen
            self._gen = _RAGGen()
        return self._gen

    def generate(self, category: str, objective: str = "", *, max_payloads: int = 8):
        return self._ensure_gen().generate(category, objective, max_payloads=max_payloads)

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        from scenarios.rag_attacks import RAGPayloadGenerator as _RAGGen
        return _RAGGen.get_strategy_payloads(strategy_name)


class AgentPayloadGenerator:
    """多智能体攻击 Payload 生成器 (Module 9-10) — 延迟委托。"""

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self.provider = provider or get_provider()
        self._gen = None

    def _ensure_gen(self):
        if self._gen is None:
            from scenarios.agent_attacks import AgentPayloadGenerator as _AgentGen
            self._gen = _AgentGen()
        return self._gen

    def generate(self, category: str, objective: str = "", *, max_payloads: int = 10):
        return self._ensure_gen().generate(category, objective, max_payloads=max_payloads)

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        from scenarios.agent_attacks import AgentPayloadGenerator as _AgentGen
        return _AgentGen.get_strategy_payloads(strategy_name)


class InfraPayloadGenerator:
    """基础设施攻击 Payload 生成器 (Module 11-16) — 延迟委托。"""

    def __init__(self, provider: ModulePayloadProvider | None = None):
        self.provider = provider or get_provider()
        self._gen = None

    def _ensure_gen(self):
        if self._gen is None:
            from scenarios.infra_attacks import InfraPayloadGenerator as _InfraGen
            self._gen = _InfraGen()
        return self._gen

    def generate(self, category: str, objective: str = "", *, max_payloads: int = 10):
        return self._ensure_gen().generate(category, objective, max_payloads=max_payloads)

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        from scenarios.infra_attacks import InfraPayloadGenerator as _InfraGen
        return _InfraGen.get_strategy_payloads(strategy_name)


# ═══════════════════════════════════════════════════════════════════
# 5. 生成器工厂 — 按 category 字符串路由
# ═══════════════════════════════════════════════════════════════════

GENERATOR_MAP: dict[str, type] = {
    # Module 04-07: 🆕 孤立的模块（从 YAML 直接加载）
    "prompt_injection":  PromptInjectionPayloadGenerator,
    "jailbreak":         JailbreakPayloadGenerator,
    "exfiltration":      ExfiltrationPayloadGenerator,
    "output_handling":   OutputHandlingPayloadGenerator,
    # Module 08: RAG
    "rag":               RAGPayloadGenerator,
    "rag_poison":        RAGPayloadGenerator,
    "rag_exploit":       RAGPayloadGenerator,
    # Module 09-10: Agent
    "agent_hijack":      AgentPayloadGenerator,
    "multi_agent":       AgentPayloadGenerator,
    "agent":             AgentPayloadGenerator,
    # Module 11-16: Infra
    "infra_attack":      InfraPayloadGenerator,
    "supply_chain":      InfraPayloadGenerator,
    "model_extract":     InfraPayloadGenerator,
    "data_poison":       InfraPayloadGenerator,
}


def create_generator(category: str) -> object | None:
    """根据 category 字符串创建对应的 PayloadGenerator 实例。

    Args:
        category: YAML 模板中的 category 字段值

    Returns:
        PayloadGenerator 实例（实现 generate(category, objective, max_payloads)），
        或 None（无匹配时）

    用法:
        gen = create_generator("prompt_injection")
        payloads = gen.generate("prompt_injection", max_payloads=6)

        gen = create_generator("rag_poison")
        payloads = gen.generate("rag_poison", objective)
    """
    gen_cls = GENERATOR_MAP.get(category)
    if gen_cls is None:
        logger.warning("create_generator: 无匹配的 generator for category=%s", category)
        return None
    return gen_cls()


# ═══════════════════════════════════════════════════════════════════
# 6. 12 模块全覆盖摘要
# ═══════════════════════════════════════════════════════════════════

# 全部 12 个 YAML payload 文件 → Generator 映射关系:
#
# Module 04  prompt_injection_payloads.yaml   → PromptInjectionPayloadGenerator  🆕
# Module 05  jailbreak_payloads.yaml          → JailbreakPayloadGenerator         🆕
# Module 06  exfiltration_payloads.yaml       → ExfiltrationPayloadGenerator      🆕
# Module 07  output_handling_payloads.yaml    → OutputHandlingPayloadGenerator    🆕
# Module 08  rag_payloads.yaml                → RAGPayloadGenerator               ♻️ 委托
# Module 09-10 agent_payloads.yaml            → AgentPayloadGenerator             ♻️ 委托
# Module 11  model_extraction_payloads.yaml   → InfraPayloadGenerator             ♻️ 委托
# Module 12  data_poison_payloads.yaml        → InfraPayloadGenerator             ♻️ 委托
# Module 13  supply_chain_payloads.yaml       → InfraPayloadGenerator             ♻️ 委托
# Module 14-16 infra_payloads.yaml            → InfraPayloadGenerator             ♻️ 委托
# + core/    classic_payloads_{zh,en}.yaml    → UnifiedPayloadLoader.get_classic()
#
# 所有 payload 文件的统一入口: ModulePayloadProvider → 纯 YAML，零硬编码回退
