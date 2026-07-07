"""
===============================================================================
OffSec AI-300 — 统一 Payload Loader v2.0
===============================================================================
datasets/payloads/ 目录作为唯一真相源 (Single Source of Truth) 的统一加载入口。

设计原则（考试者视角）:
  ✅ 考试期间仅需编辑 datasets/payloads/ 下的 YAML 文件
  ✅ 无需触碰任何 Python 代码
  ✅ 支持两种 Payload 格式:
     - 经典载荷 (core/): 双语预设变体格式，用于 {key} 模板替换
     - AI 模块载荷 (根目录): 扁平列表格式，用于 exam_mode 攻击模块
  ✅ 纯 YAML 驱动 — 所有 payload 以 YAML 为唯一源，无 Python 模块依赖
  ✅ exam_mode 模块统一通过此 Loader 获取 payload（消除重复代码）

目录结构:
  datasets/payloads/
  ├── core/
  │   ├── classic_payloads_zh.yaml     ← 经典攻击载荷 (中文, 5 预设)
  │   └── classic_payloads_en.yaml     ← 经典攻击载荷 (英文, 5 预设)
  ├── prompt_injection_payloads.yaml   ← Module 04: Prompt 注入
  ├── jailbreak_payloads.yaml          ← Module 05: 越狱技术
  ├── exfiltration_payloads.yaml       ← Module 06: 数据外泄
  ├── output_handling_payloads.yaml    ← Module 07: 不安全输出处理
  ├── rag_payloads.yaml                ← Module 08: RAG 管道攻击
  ├── agent_payloads.yaml              ← Module 09-10: Agent/多Agent
  ├── model_extraction_payloads.yaml   ← Module 11: 模型提取
  ├── data_poison_payloads.yaml        ← Module 12: 数据投毒
  ├── supply_chain_payloads.yaml       ← Module 13: 供应链攻击
  ├── infra_payloads.yaml              ← Module 14-16: 基础设施攻击
  └── manifest.yaml                    ← 模块→文件映射索引

API:
  # 经典载荷: {key} 模板替换
  from datasets.payload_loader import load_classic_payloads
  vars_dict, presets = load_classic_payloads("cn")

  # AI 模块载荷: exam_mode 模块使用
  from datasets.payload_loader import load_module_payloads
  payloads = load_module_payloads("prompt_injection")
  # → {"direct_extract": ["text1", ...], "role_override": ["text2", ...]}

  # 统一访问
  from datasets.payload_loader import UnifiedPayloadLoader
  loader = UnifiedPayloadLoader("cn")
  all_vars = loader.get_all_vars()        # 全部 {key} 可用变量 (经典 + AI)
  module_data = loader.get_module("rag")  # 指定模块的 AI payloads
===============================================================================
"""
from __future__ import annotations

import os
import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

# ── 预设名称常量 ──
PRESET_NAMES = ["stealth", "bruteforce", "redteam", "academic", "minimal"]

# ── 模块→YAML 文件映射（考试期间唯一需要修改的元数据）──
MODULE_FILE_MAP: dict[str, str] = {
    # Modules 04-07: 独立文件
    "prompt_injection": "prompt_injection_payloads.yaml",
    "jailbreak": "jailbreak_payloads.yaml",
    "exfiltration": "exfiltration_payloads.yaml",
    "output_handling": "output_handling_payloads.yaml",
    # Module 08
    "rag": "rag_payloads.yaml",
    "rag_poison": "rag_payloads.yaml",
    "indirect_inject": "rag_payloads.yaml",  # 间接注入也在 RAG 文件中
    # Modules 09-10
    "agent": "agent_payloads.yaml",
    "agent_attack": "agent_payloads.yaml",
    "multi_agent": "agent_payloads.yaml",
    # Modules 11-13: 独立文件
    "model_extract": "model_extraction_payloads.yaml",
    "model_extraction": "model_extraction_payloads.yaml",
    "data_poison": "data_poison_payloads.yaml",
    "data_poisoning": "data_poison_payloads.yaml",
    "supply_chain": "supply_chain_payloads.yaml",
    # Modules 14-16: 合并在 infra_payloads.yaml
    "infra": "infra_payloads.yaml",
    "infra_attack": "infra_payloads.yaml",
    "api_fuzz": "infra_payloads.yaml",
    "model_serving": "infra_payloads.yaml",
    "cloud_recon": "infra_payloads.yaml",
    "auth_bypass": "infra_payloads.yaml",
}

# ── 批量加载时每个 YAML 文件中的 section 映射（AI 模块）──
# 用于 exam_mode 模块的 payload_key → YAML section 查找
MODULE_SECTION_MAP: dict[str, dict[str, str]] = {
    "infra_attack": {
        "infra_attack": "infra_payloads.yaml",
        "api_fuzz": "infra_payloads.yaml",
        "model_serving": "infra_payloads.yaml",
        "cloud_recon": "infra_payloads.yaml",
        "auth_bypass": "infra_payloads.yaml",
        "supply_chain": "supply_chain_payloads.yaml",
        "model_extract": "model_extraction_payloads.yaml",
        "data_poison": "data_poison_payloads.yaml",
    },
    # 其他模块直接使用 MODULE_FILE_MAP
}


# ═══════════════════════════════════════════════════════════════════
# 1. 项目路径解析
# ═══════════════════════════════════════════════════════════════════

def _get_payloads_dir() -> str:
    """返回 datasets/payloads/ 目录的绝对路径。"""
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "payloads")


def _get_core_dir() -> str:
    """返回 datasets/payloads/core/ 目录的绝对路径。"""
    return os.path.join(_get_payloads_dir(), "core")


# ═══════════════════════════════════════════════════════════════════
# 2. YAML 加载工具
# ═══════════════════════════════════════════════════════════════════

def _load_yaml_safe(filepath: str) -> dict | None:
    """安全加载 YAML 文件，返回 dict 或 None。"""
    try:
        import yaml
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logger.debug("YAML 加载失败 [%s]: %s", filepath, e)
    return None


# ═══════════════════════════════════════════════════════════════════
# 3. 经典载荷加载器 (core/ — 双语预设格式)
# ═══════════════════════════════════════════════════════════════════

def load_classic_payloads(
    lang: str = "cn",
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """从 datasets/payloads/core/classic_payloads_{lang}.yaml 加载经典载荷。

    Args:
        lang: 语言代码 — "cn"/"zh" (中文) 或 "en" (英文)

    Returns:
        (vars_dict, presets_dict)
        - vars_dict: {"keylogger_code": "base_value", ...}
        - presets_dict: {"stealth": {"keylogger_code": "stealth_value", ...}, ...}

    优先级: YAML 文件唯源
    """
    lang_file = "classic_payloads_zh.yaml" if lang.startswith(("cn", "zh")) else "classic_payloads_en.yaml"
    filepath = os.path.join(_get_core_dir(), lang_file)

    # ── 尝试从 YAML 加载 ──
    data = _load_yaml_safe(filepath)
    if data:
        payloads = data.get("payloads", {})
        if payloads:
            vars_dict: dict[str, str] = {}
            presets_dict: dict[str, dict[str, str]] = {pn: {} for pn in PRESET_NAMES}

            for name, row in payloads.items():
                if not isinstance(row, dict):
                    continue
                base = row.get("base", "")
                vars_dict[name] = base
                for pn in PRESET_NAMES:
                    presets_dict[pn][name] = row.get(pn, base)

            logger.info(
                "Classic payloads 从 YAML 加载 [%s]: %d 变量, %d 预设",
                lang_file, len(vars_dict), len(presets_dict),
            )
            return vars_dict, presets_dict

    # ── YAML 文件不存在或加载失败 ──
    logger.error("经典载荷 YAML 加载失败: %s", lang_file)
    return {}, {pn: {} for pn in PRESET_NAMES}


# ═══════════════════════════════════════════════════════════════════
# 4. AI 模块载荷加载器 (根目录 — 扁平列表格式)
# ═══════════════════════════════════════════════════════════════════

@lru_cache(maxsize=32)
def load_module_payloads(module_key: str) -> dict[str, list[str]]:
    """从 datasets/payloads/{filename}.yaml 加载指定 AI 模块的 payload。

    格式识别:
      - YAML 顶层 payloads 节为 {section_key: [text1, text2, ...]} → 直接返回
      - 若 YAML 结构非预期 → 返回空 dict

    Args:
        module_key: 模块标识符（如 "prompt_injection", "rag", "jailbreak" 等）

    Returns:
        {"section_name": ["payload1", "payload2", ...], ...}
        或空 dict（文件不存在/格式错误时）
    """
    filename = MODULE_FILE_MAP.get(module_key)
    if not filename:
        logger.debug("未知模块 key: %s (不在 MODULE_FILE_MAP 中)", module_key)
        return {}

    filepath = os.path.join(_get_payloads_dir(), filename)
    data = _load_yaml_safe(filepath)
    if not data:
        return {}

    payloads = data.get("payloads", {})
    if not isinstance(payloads, dict):
        return {}

    # 校验每个 value 是 list[str]
    result: dict[str, list[str]] = {}
    for section_key, section_value in payloads.items():
        if isinstance(section_value, list):
            result[section_key] = [str(x) for x in section_value if x]
        elif isinstance(section_value, dict):
            # 兼容嵌套字典格式（某些 YAML 可能有子结构）
            result[section_key] = [str(v) for v in section_value.values() if v]

    logger.debug("模块载荷 [%s] → %s: %d sections, %d 总条目",
                 module_key, filename, len(result),
                 sum(len(v) for v in result.values()))
    return result


def load_all_module_payloads() -> dict[str, dict[str, list[str]]]:
    """批量加载所有 AI 模块的 payload。

    Returns:
        {"prompt_injection": {"direct_extract": [...], ...}, "jailbreak": {...}, ...}
    """
    result: dict[str, dict[str, list[str]]] = {}
    seen_files: set = set()

    for module_key, filename in MODULE_FILE_MAP.items():
        if filename in seen_files:
            continue
        seen_files.add(filename)

        filepath = os.path.join(_get_payloads_dir(), filename)
        data = _load_yaml_safe(filepath)
        if not data or "payloads" not in data:
            continue

        payloads = data["payloads"]
        if isinstance(payloads, dict):
            parsed: dict[str, list[str]] = {}
            for sk, sv in payloads.items():
                if isinstance(sv, list):
                    parsed[sk] = [str(x) for x in sv if x]
                elif isinstance(sv, dict):
                    parsed[sk] = [str(v) for v in sv.values() if v]
            if parsed:
                # 使用文件名作为顶层 key（去后缀）
                base_name = os.path.splitext(filename)[0]
                result[base_name] = parsed

    return result


# ═══════════════════════════════════════════════════════════════════
# 5. 跨模块统一 YAML 加载 — 供 exam_mode 模块复用
# ═══════════════════════════════════════════════════════════════════

def _resolve_yaml_path(filename: str) -> str | None:
    """解析 YAML 文件名到完整路径。
    搜索顺序: datasets/payloads/ → 当前目录
    """
    payloads_dir = _get_payloads_dir()
    candidate = os.path.join(payloads_dir, filename)
    if os.path.exists(candidate):
        return candidate

    alt = os.path.join(os.getcwd(), "datasets", "payloads", filename)
    if os.path.exists(alt):
        return alt

    return None


def load_exam_module_yaml(filename: str, module_key: str) -> dict[str, list[str]] | None:
    """供 exam_mode 模块调用的统一接口。

    替换 exam_mode/infra_attacks.py、rag_attacks.py、agent_attacks.py 中
    各自独立的 YAML 加载函数。

    Args:
        filename: YAML 文件名（如 "rag_payloads.yaml"）
        module_key: 模块标识符（用于缓存和日志）

    Returns:
        {"section_key": ["text1", ...], ...} 或 None（加载失败时）
    """
    filepath = _resolve_yaml_path(filename)
    if not filepath:
        logger.debug("YAML 文件未找到 [%s]: %s", module_key, filename)
        return None

    data = _load_yaml_safe(filepath)
    if not data:
        return None

    payloads = data.get("payloads", {})
    if not isinstance(payloads, dict):
        return None

    result: dict[str, list[str]] = {}
    for sk, sv in payloads.items():
        if isinstance(sv, list):
            result[sk] = [str(x) for x in sv if x]
        elif isinstance(sv, dict):
            result[sk] = [str(v) for v in sv.values() if v]

    if result:
        logger.info("exam_mode 模块载荷已加载 [%s]: %d sections", module_key, len(result))
        return result
    return None


# ═══════════════════════════════════════════════════════════════════
# 6. 统一访问类 — 一站式payload入口
# ═══════════════════════════════════════════════════════════════════

class UnifiedPayloadLoader:
    """统一 Payload 访问入口。

    考试期间唯一需要操作的类。自动从 datasets/payloads/ 加载全部载荷。

    用法:
        loader = UnifiedPayloadLoader("cn")
        vars_dict, presets = loader.get_classic()  # 经典载荷（{key} 替换用）
        jailbreak = loader.get_module("jailbreak")  # AI 模块载荷
        all_vars = loader.get_all_vars()            # 所有 {key} 可用变量
    """

    def __init__(self, lang: str = "cn"):
        self.lang = "en" if lang.startswith("en") else "zh"
        self._classic_vars: dict[str, str] | None = None
        self._classic_presets: dict[str, dict[str, str]] | None = None
        self._module_cache: dict[str, dict[str, list[str]]] = {}

    def get_classic(self) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        """获取经典载荷（支持 {key} 模板替换）。"""
        if self._classic_vars is None:
            self._classic_vars, self._classic_presets = load_classic_payloads(self.lang)
        return self._classic_vars, self._classic_presets or {}

    def get_module(self, module_key: str) -> dict[str, list[str]]:
        """获取指定 AI 模块的 payload。"""
        if module_key not in self._module_cache:
            self._module_cache[module_key] = load_module_payloads(module_key)
        return self._module_cache[module_key]

    def get_all_vars(self) -> dict[str, str]:
        """获取所有可用的 {key} 模板变量（经典 + AI 模块 flattened）。"""
        vars_dict, _ = self.get_classic()
        # 添加 AI 模块 payload 作为命名空间变量
        # 格式: {module}_{section} → 第一个 payload
        all_module = load_all_module_payloads()
        for module_name, sections in all_module.items():
            for section_key, texts in sections.items():
                if texts:
                    var_key = f"{module_name}_{section_key}"
                    # 避免覆盖经典载荷的同名 key
                    if var_key not in vars_dict:
                        vars_dict[var_key] = texts[0]
        return vars_dict

    def get_module_sections(self, yaml_filename: str) -> dict[str, list[str]] | None:
        """按文件名加载 YAML（供 exam_mode 模块使用）。

        这是 exam_mode 三个模块的统一入口，替代各自独立的 YAML 解析。
        """
        module_key = os.path.splitext(yaml_filename)[0]
        return load_exam_module_yaml(yaml_filename, module_key)

    @property
    def loader_info(self) -> dict:
        """返回 loader 摘要信息。"""
        vars_dict, presets = self.get_classic()
        all_modules = load_all_module_payloads()
        return {
            "lang": self.lang,
            "classic_vars": len(vars_dict),
            "classic_presets": list(presets.keys()) if presets else [],
            "ai_modules": list(all_modules.keys()),
            "total_ai_sections": sum(len(s) for s in all_modules.values()),
            "yaml_dir": _get_payloads_dir(),
            "core_dir": _get_core_dir(),
        }


# ═══════════════════════════════════════════════════════════════════
# 7. 便捷函数（向后兼容）
# ═══════════════════════════════════════════════════════════════════

def get_module_payloads(module_key: str) -> dict[str, list[str]]:
    """获取指定模块的 payload（便捷函数，等价于 load_module_payloads）。

    exam_mode 模块推荐使用此函数替代独立的 YAML 加载代码。
    """
    return load_module_payloads(module_key)
