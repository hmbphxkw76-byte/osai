"""
===============================================================================
Promptfoo 模块 — 统一提示词管理 + 评估判定 + 报告生成 (整合 datasets/)
===============================================================================
本包提供:
  - PromptfooManager: 提示词管理中心（加载、筛选、导出、评估）
  - EvalEngine: 统一评估引擎（ASR 评分 + OWASP/MITRE 映射）
  - ReportGenerator: OffSec 风格渗透测试报告生成器
  - loader: Payload 加载器（测试用例 + 攻击载荷，原 datasets/）
  - vendor_payloads: 厂商差异化 Payload 模块
  - schema: 数据模型（PromptEntry + Pydantic 用例/Payload Schema）

架构位置: L5 (统一评估判定) + L6 (标准化报告生成) + 统一提示词源
===============================================================================
"""
from promptfoo.schema import (
    PromptEntry, PromptSet, PromptfooEvalResult,
    # Pydantic 用例模型 (原 datasets/models.py)
    SyllabusMapping, AttackCombo, TestCase, TestCaseSet,
    PayloadRegistry, PayloadRow, PayloadBatch, CaseBatch,
    register_payload, register_preset, inject_payload, register_test_case,
)
from promptfoo.manager import PromptfooManager
from promptfoo.eval.engine import EvalEngine
from promptfoo.reporting.generator import ReportGenerator

# 延迟导入 loader（避免循环）
def _get_loader():
    from promptfoo.loader import (
        load_test_cases, load_payloads_module, apply_preset,
        load_classic_payloads, load_module_payloads, get_module_payloads,
        PayloadLoader, UnifiedPayloadLoader,
        PRESET_NAMES, MODULE_FILE_MAP, MODULE_SECTION_MAP,
    )
    return locals()

# 延迟导入 vendor_payloads
def _get_vendor():
    from promptfoo.vendor_payloads import (
        get_vendor_payloads, get_vendor_specific_vars,
        get_recommended_converters, get_vendor_jailbreak_hook,
        detect_vendor_from_model_name,
    )
    return locals()

def __getattr__(name):
    if name in _LAZY_MAP:
        mod_name, func = _LAZY_MAP[name]
        import importlib
        m = importlib.import_module(mod_name)
        return getattr(m, func)
    raise AttributeError(f"module 'promptfoo' has no attribute '{name}'")

_LAZY_MAP = {
    "load_test_cases": ("promptfoo.loader", "load_test_cases"),
    "load_payloads_module": ("promptfoo.loader", "load_payloads_module"),
    "apply_preset": ("promptfoo.loader", "apply_preset"),
    "load_classic_payloads": ("promptfoo.loader", "load_classic_payloads"),
    "load_module_payloads": ("promptfoo.loader", "load_module_payloads"),
    "get_module_payloads": ("promptfoo.loader", "get_module_payloads"),
    "PayloadLoader": ("promptfoo.loader", "PayloadLoader"),
    "UnifiedPayloadLoader": ("promptfoo.loader", "UnifiedPayloadLoader"),
    "PRESET_NAMES": ("promptfoo.loader", "PRESET_NAMES"),
    "MODULE_FILE_MAP": ("promptfoo.loader", "MODULE_FILE_MAP"),
    "MODULE_SECTION_MAP": ("promptfoo.loader", "MODULE_SECTION_MAP"),
    "get_vendor_payloads": ("promptfoo.vendor_payloads", "get_vendor_payloads"),
    "get_vendor_specific_vars": ("promptfoo.vendor_payloads", "get_vendor_specific_vars"),
    "get_recommended_converters": ("promptfoo.vendor_payloads", "get_recommended_converters"),
    "get_vendor_jailbreak_hook": ("promptfoo.vendor_payloads", "get_vendor_jailbreak_hook"),
    "detect_vendor_from_model_name": ("promptfoo.vendor_payloads", "detect_vendor_from_model_name"),
}

__all__ = [
    "PromptEntry", "PromptSet", "PromptfooEvalResult",
    "SyllabusMapping", "AttackCombo", "TestCase", "TestCaseSet",
    "PayloadRegistry", "PayloadRow", "PayloadBatch", "CaseBatch",
    "register_payload", "register_preset", "inject_payload", "register_test_case",
    "PromptfooManager", "EvalEngine", "ReportGenerator",
    "load_test_cases", "load_payloads_module", "apply_preset",
    "load_classic_payloads", "load_module_payloads", "get_module_payloads",
    "PayloadLoader", "UnifiedPayloadLoader",
    "PRESET_NAMES", "MODULE_FILE_MAP", "MODULE_SECTION_MAP",
    "get_vendor_payloads", "get_vendor_specific_vars",
    "get_recommended_converters", "get_vendor_jailbreak_hook",
    "detect_vendor_from_model_name",
]
