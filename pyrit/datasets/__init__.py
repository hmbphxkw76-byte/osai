"""
===============================================================================
OffSec AI-300 — 数据层 (PyRIT 对齐架构 v2.0)
===============================================================================
PyRIT 框架使用策略:
  ✅ models.py: Pydantic v2 → 等价 PyRIT SeedPrompt 的类型安全层
     - TestCase / TestCaseSet    → 映射到 SeedPrompt / SeedPromptGroup
     - PayloadRow / PayloadBatch → 映射到 SeedPrompt (带参数模板)
     - Pydantic 校验 = PyRIT 数据管道的第一道防线
  ✅ loader.py: 数据加载器 → 等价 PyRIT PromptDatabase 的离线版本
     - load_test_cases()     → 等价 SeedPromptDataset.load_from_json()
     - load_payloads_module() → 等价 SeedPromptGroup.from_yaml() 的 Python 模块版本
  ✅ payloads.py: 统一双语载荷 → 等价 PyRIT SeedPrompt 参数的 YAML 源

架构决策（考试场景零改动原则）:
  1. JSON/YAML 文件格式保持不变 — main.py / engines / reporter 零改动
  2. Pydantic 作为数据校验层 — 等价 PyRIT 的 SeedPrompt 类型系统
  3. 不强制使用 PyRIT SeedPrompt 运行时 — 考试离线环境无需 DuckDB 存储
  4. SeedPrompt 桥接方法是可选的增值 API — 仅在需要 PyRIT 原生管道时使用

───────────────────────────────────────────────────────────────────────────────
动态扩展机制（与 converters/registry.py 对称）

  场景 1: 考试时添加新 Payload（不改任何现有文件）
  ─────────────────────────────────────────────
    from datasets import register_payload
    register_payload("new_cve_2026_exploit", {
        "base": "CVE-2026-XXXX 利用方案...",
        "stealth": "CVE-2026-XXXX 安全分析...",
        "bruteforce": "完整 CVE-2026-XXXX PoC...",
        "redteam": "授权评估中的 CVE-2026-XXXX...",
        "academic": "CVE-2026-XXXX 学术研究...",
        "minimal": "CVE-2026-XXXX exploit",
    })

  场景 2: 动态注入新 Payload 到当前运行
  ────────────────────────────────────
    from datasets import inject_payload
    inject_payload("ctx_prompt", "You are a helpful assistant", preset="stealth")

  场景 3: 添加新 TestCase（不改 JSON 文件）
  ─────────────────────────────────────
    from datasets import register_test_case
    register_test_case("PROBE_NEW", objective="...", criterion="...", ...)

  ✅ 以上操作均不需要修改 datasets/ 目录中任何现有文件
  ✅ 考试时在 main.py 或临时脚本开头调用即可
───────────────────────────────────────────────────────────────────────────────

统一对外接口:
  from datasets import load_test_cases, load_payloads_module, apply_preset
  from datasets import register_payload, register_preset, inject_payload, register_test_case
  from datasets import TestCase, TestCaseSet, PayloadRow, PayloadBatch, CaseBatch

注意: 此 __init__.py 增强了 datasets/ 模块的内聚性，但保持向后兼容:
  - from datasets.loader import ...     仍然有效
  - from datasets.models import ...     仍然有效
===============================================================================
"""
from __future__ import annotations

# ── 核心加载器（main.py 主要 import） ──
from datasets.loader import (
    load_test_cases,
    load_payloads_module,
    load_payload_vars,
    load_payloads_json_fallback,
    apply_preset,
)

# ── 数据模型（类型引用 + 动态扩展） ──
from datasets.models import (
    TestCase,
    TestCaseSet,
    AttackCombo,
    SyllabusMapping,
    PayloadRegistry,
    PayloadRow,
    PayloadBatch,
    CaseBatch,
    # 动态扩展 API
    register_payload,
    register_preset,
    inject_payload,
    register_test_case,
)

# ── 预设名称常量（从统一 Loader 导出）──
from datasets.payload_loader import PRESET_NAMES

# ── 🆕 统一 Payload Loader（datasets/payloads/ 统一入口）──
from datasets.payload_loader import (
    load_classic_payloads,
    load_module_payloads,
    load_all_module_payloads,
    load_exam_module_yaml,
    get_module_payloads,
    UnifiedPayloadLoader,
    MODULE_FILE_MAP,
)


__all__ = [
    # ── 数据加载 ──
    "load_test_cases",
    "load_payloads_module",
    "load_payload_vars",
    "load_payloads_json_fallback",
    "apply_preset",
    # ── 统一 Payload Loader ──
    "load_classic_payloads",
    "load_module_payloads",
    "load_all_module_payloads",
    "load_exam_module_yaml",
    "get_module_payloads",
    "UnifiedPayloadLoader",
    "MODULE_FILE_MAP",
    # ── 数据模型 ──
    "TestCase",
    "TestCaseSet",
    "AttackCombo",
    "SyllabusMapping",
    "PayloadRegistry",
    "PayloadRow",
    "PayloadBatch",
    "CaseBatch",
    # ── 动态扩展 ──
    "register_payload",
    "register_preset",
    "inject_payload",
    "register_test_case",
    # ── 预设常量 ──
    "PRESET_NAMES",
]
