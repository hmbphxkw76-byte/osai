"""
===============================================================================
PyRIT Red Team — 统一 Payload 加载器
===============================================================================
从 YAML 源文件加载攻击载荷，支持经典载荷（预设系统）和模块载荷。

加载源:
  1. core/classic_payloads_{zh,en}.yaml  — 经典攻击载荷（含5预设系统）
  2. payloads/*.yaml                       — 按模块组织的专项载荷

使用方式:
  from datasets.payload_loader import (
      load_classic_payloads, load_all_module_payloads, get_module_payloads,
      UnifiedPayloadLoader, MODULE_FILE_MAP, PRESET_NAMES,
  )
===============================================================================
"""
from __future__ import annotations

import os
import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

# ── 常量 ──

PRESET_NAMES: list[str] = ["stealth", "bruteforce", "redteam", "academic", "minimal"]

MODULE_FILE_MAP: dict[str, str] = {
    "prompt_injection": "prompt_injection_payloads.yaml",
    "jailbreak":         "jailbreak_payloads.yaml",
    "exfiltration":      "exfiltration_payloads.yaml",
    "output_handling":   "output_handling_payloads.yaml",
    "rag":               "rag_payloads.yaml",
    "agent":             "agent_payloads.yaml",
    "infra":             "infra_payloads.yaml",
    "api_fuzz":          "infra_payloads.yaml",
    "model_serving":     "infra_payloads.yaml",
    "cloud_recon":       "infra_payloads.yaml",
    "auth_bypass":       "infra_payloads.yaml",
    "supply_chain":      "supply_chain_payloads.yaml",
    "model_extract":     "model_extraction_payloads.yaml",
    "data_poison":       "data_poison_payloads.yaml",
    "frontier":          "frontier_payloads_placeholder.yaml",
}

MODULE_SECTION_MAP: dict[str, list[str]] = {
    "prompt_injection": ["direct_extract", "role_override", "delimiter_inject",
                         "indirect_content", "hidden_text", "cross_context",
                         "hierarchy_bypass", "multi_turn"],
    "jailbreak": ["roleplay", "developer_mode", "academic", "encoding",
                  "multilingual", "emotional", "hypothetical", "gradual", "token_manip"],
    "exfiltration": ["pii_extract", "training_reconstruct", "system_prompt_extract"],
    "output_handling": ["xss_output", "sql_output"],
    "rag": ["query_manipulation", "source_poison", "retrieval_abuse"],
    "agent": ["tool_abuse", "orchestrator_bypass", "memory_poison"],
    "infra": ["api_fuzz", "model_serving", "cloud_recon", "auth_bypass"],
    "supply_chain": ["package_confusion", "dependency_hijack", "plugin_inject"],
    "model_extract": ["architecture_probe", "parameter_extract", "membership_infer"],
    "data_poison": ["label_flip", "trigger_inject", "backdoor_embed"],
    "frontier": ["placeholder"],
}


# ── 路径工具 ──

def _get_payloads_dir() -> str:
    """获取 payloads 目录路径。"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")


def _get_core_dir() -> str:
    """获取 core YAML 文件目录。"""
    return os.path.join(_get_payloads_dir(), "core")


def _load_yaml_safe(filepath: str) -> dict | None:
    """安全加载 YAML 文件，返回 dict 或 None。"""
    import yaml
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Failed to load YAML {filepath}: {e}")
        return None


# ── 经典载荷加载 ──

def load_classic_payloads(lang: str) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """从 core/classic_payloads_{zh,en}.yaml 加载经典攻击载荷。

    Args:
        lang: "cn" → classic_payloads_zh.yaml, "en" → classic_payloads_en.yaml

    Returns:
        (vars_dict, presets_dict)
          - vars_dict:  {payload_name: base_value}
          - presets_dict: {preset_name: {payload_name: preset_value}}
    """
    lang_map = {"cn": "zh", "en": "en"}
    lang_suffix = lang_map.get(lang, "zh")
    filename = f"classic_payloads_{lang_suffix}.yaml"
    filepath = os.path.join(_get_core_dir(), filename)

    data = _load_yaml_safe(filepath)
    if not data:
        return {}, {}

    payloads_data = data.get("payloads", {})
    vars_dict: dict[str, str] = {}
    presets_dict: dict[str, dict[str, str]] = {pn: {} for pn in PRESET_NAMES}

    for payload_name, variants in payloads_data.items():
        if not isinstance(variants, dict):
            continue
        base = variants.get("base", "")
        vars_dict[payload_name] = base
        for pn in PRESET_NAMES:
            if pn in variants:
                presets_dict[pn][payload_name] = variants[pn]

    return vars_dict, presets_dict


# ── 模块载荷加载 ──

def load_module_payloads(module_key: str) -> dict[str, list[str]] | None:
    """加载单个模块的 YAML 载荷文件。

    Args:
        module_key: 模块名（如 "prompt_injection", "jailbreak"）

    Returns:
        {section_key: [payload_texts]} 或 None（加载失败）
    """
    filename = MODULE_FILE_MAP.get(module_key)
    if not filename:
        return None

    filepath = os.path.join(_get_payloads_dir(), filename)
    data = _load_yaml_safe(filepath)
    if not data:
        return None

    return data.get("payloads", {})


def load_all_module_payloads() -> dict[str, dict[str, list[str]]]:
    """加载所有模块 YAML 载荷文件。

    Returns:
        {base_filename_without_ext: {section_key: [payload_texts]}}
    """
    result: dict[str, dict[str, list[str]]] = {}
    seen_files: set[str] = set()

    for module_key, filename in MODULE_FILE_MAP.items():
        if filename in seen_files:
            continue
        seen_files.add(filename)

        base_name = os.path.splitext(filename)[0]
        sections = load_module_payloads(module_key)
        if sections:
            result[base_name] = sections

    return result


def _resolve_yaml_path(filename: str) -> str | None:
    """解析 YAML 文件完整路径。"""
    filepath = os.path.join(_get_payloads_dir(), filename)
    if os.path.exists(filepath):
        return filepath
    return None


def load_exam_module_yaml(filename: str, module_key: str) -> dict[str, list[str]] | None:
    """加载指定 YAML 文件并返回载荷 sections。

    Args:
        filename: YAML 文件名
        module_key: 模块标识（用于日志）

    Returns:
        {section_key: [payload_texts]} 或 None
    """
    filepath = os.path.join(_get_payloads_dir(), filename)
    if not os.path.exists(filepath):
        logger.warning(f"Module YAML not found: {filename}")
        return None

    data = _load_yaml_safe(filepath)
    if not data:
        return None

    return data.get("payloads", {})


def get_module_payloads(module_key: str, section_key: str) -> list[str]:
    """快捷获取指定模块指定 section 的 payload 文本列表。

    Args:
        module_key: 模块名
        section_key: section 名

    Returns:
        payload 文本列表
    """
    sections = load_module_payloads(module_key)
    if not sections:
        return []
    return sections.get(section_key, [])


# ── 统一加载器类 ──

class UnifiedPayloadLoader:
    """统一载荷加载器 — 为 scenarios/ 模块提供的便捷接口。

    封装了经典载荷和模块载荷的加载逻辑，支持按语言自动选择。
    """

    def __init__(self, lang: str):
        """初始化加载器。

        Args:
            lang: "zh" 或 "en"（内部统一转换为 "cn"/"en" 用于经典载荷）
        """
        self.lang = "cn" if lang == "zh" else lang

    def get_module_sections(self, filename: str) -> dict[str, list[str]] | None:
        """获取指定 YAML 文件的模块载荷 sections。

        Args:
            filename: YAML 文件名（如 "prompt_injection_payloads.yaml"）

        Returns:
            {section_key: [payload_texts]} 或 None
        """
        filepath = os.path.join(_get_payloads_dir(), filename)
        data = _load_yaml_safe(filepath)
        if not data:
            return None
        return data.get("payloads", {})

    def get_classic(self) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        """获取经典载荷数据。

        Returns:
            (vars_dict, presets_dict) 同 load_classic_payloads()
        """
        return load_classic_payloads(self.lang)
