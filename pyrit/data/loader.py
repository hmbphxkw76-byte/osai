"""
===============================================================================
OffSec AI-300 — 数据加载器（Pydantic 验证 + 向后兼容）
===============================================================================
职责:
- load_test_cases(): 加载 JSON → Pydantic 校验 → 返回向后兼容的 dict 列表
- load_payloads_module(): 从 data/payloads.py 加载变量 + 预设（主加载方式）
                          自动合并 results/ 下的 Pending JSON 载荷
- load_payloads_json_fallback(): 从 results/ 加载待入库的 PayloadBatch JSON
- load_payload_vars(): YAML 兼容加载（降级方案）
- apply_preset(): 应用预设到 payload 字典
- validate_existing_data(): 启动时快速校验所有数据文件

加载优先级（由高到低）:
  1. data/payloads_{lang}.py  →  已入库的稳定载荷（主数据源）
  2. results/ 下的 Pending JSON  →  生成后尚未入库的载荷（兜底合并）
  3. YAML 文件                  →  旧格式兼容（load_payload_vars）

使用方式（在 main.py 中）:
    from data.loader import load_test_cases, load_payloads_module, apply_preset
    cases, _ = load_test_cases(json_file)
    vars_dict, presets = load_payloads_module("cn")
===============================================================================
"""
from __future__ import annotations

import glob as _glob
import json
import os
import sys
from typing import Optional

from rich.console import Console

# 确保 data/ 目录在 Python path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.models import TestCaseSet, PayloadRegistry, PayloadBatch

console = Console()

# ═══════════════════════════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════════════════════════

# 预设名称列表（与 payloads_cn.py/payloads_en.py 的 PRESET_NAMES 保持同步）
_PRESET_NAMES = ['stealth', 'bruteforce', 'redteam', 'academic', 'minimal']

# 缓存已加载的验证结果，避免重复校验
_VALIDATION_CACHE: dict[str, TestCaseSet] = {}


# ═══════════════════════════════════════════════════════════════════
# 1. 测试用例加载（核心入口）
# ═══════════════════════════════════════════════════════════════════

def load_test_cases(
    filepath: str,
    validate: bool = True,
    use_cache: bool = True,
) -> tuple[list[dict], Optional[TestCaseSet]]:
    """加载测试用例 JSON 文件 → Pydantic 校验 → 返回 (dict列表, Pydantic模型)。

    Args:
        filepath: JSON 文件路径
        validate: 是否启用 Pydantic 校验（默认 True）
        use_cache: 是否使用缓存（同一文件只校验一次）

    Returns:
        (cases_dict_list, validated_model_or_None)

    向后兼容: 返回的 list[dict] 可直接用于 engines.py / reporter.py，无需任何代码改动。
    """
    if use_cache and filepath in _VALIDATION_CACHE:
        tc_set = _VALIDATION_CACHE[filepath]
        return tc_set.to_legacy_list(), tc_set

    # Step 1: 原始 JSON 加载
    if not os.path.exists(filepath):
        console.print(f"[red][ERR] 用例文件不存在: {filepath}[/red]")
        return [], None

    if not validate:
        # 跳过 Pydantic 校验（快速模式）
        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        return raw_data.get("test_cases", []), None

    # Step 2: Pydantic 校验
    try:
        tc_set = TestCaseSet.from_json_file(filepath)
        if use_cache:
            _VALIDATION_CACHE[filepath] = tc_set

        # 统计用例分布
        probes = sum(1 for tc in tc_set.test_cases if tc.is_probe)
        singles = sum(1 for tc in tc_set.test_cases if not tc.is_probe and not tc.is_multi_turn)
        crescendos = sum(1 for tc in tc_set.test_cases if tc.is_multi_turn)

        console.print(
            f"[green][OK] 用例校验通过: {filepath}[/green]\n"
            f"   [dim]共 {len(tc_set.test_cases)} 个用例 "
            f"(PROBE: {probes} | 单轮: {singles} | 多轮: {crescendos})[/dim]"
        )

        return tc_set.to_legacy_list(), tc_set

    except Exception as e:
        console.print(f"[bold red][FAIL] 用例校验失败 ({filepath}):[/bold red]\n   {e}")

        # 优雅降级：校验失败时仍加载原始数据（但打印警告帮助定位）
        console.print("[yellow][WARN] 校验失败，降级为原始 JSON 加载（部分字段可能异常）[/yellow]")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            return raw_data.get("test_cases", []), None
        except Exception:
            return [], None


# ═══════════════════════════════════════════════════════════════════
# 2. Payload 变量加载（Python 模块 → Pydantic 校验；YAML 降级）
# ═══════════════════════════════════════════════════════════════════

def load_payloads_module(
    lang: str = "cn",
    include_pending: bool = True,
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """从 data/payloads_{lang}.py 加载变量和预设，自动合并 Pending JSON。

    加载优先级:
      1. data/payloads_{lang}.py  →  已入库的稳定载荷
      2. results/generated_payloads_{lang}_*.json  →  待入库的 Pending 载荷（兜底）
         Pending 载荷的键名不会覆盖已入库同名键（已入库优先）

    Args:
        lang: 语言代码 'cn' / 'en'
        include_pending: 是否自动合并 results/ 下的待入库 JSON（默认 True）

    Returns:
        (base_vars_dict, presets_dict)
        - presets_dict: {'stealth': {...}, 'bruteforce': {...}, ...}
    """
    if lang == "en":
        from data.payloads_en import get_payloads
    else:
        from data.payloads_cn import get_payloads

    vars_dict, presets = get_payloads()

    # Pydantic 校验：确保数据完整性
    try:
        PayloadRegistry.model_validate(vars_dict)
        console.print(
            f"[green][OK] Payload 模块校验通过: data/payloads_{lang}.py[/green]\n"
            f"   [dim]{len(vars_dict)} 个变量 + {len(presets)} 个预设 "
            f"({', '.join(presets.keys())})[/dim]"
        )
    except Exception as e:
        console.print(f"[yellow][WARN] Payload 模块校验警告 ({lang}): {e}[/yellow]")

    # ── 兜底: 合并 results/ 下的 Pending JSON 载荷 ──
    if include_pending:
        pending = load_payloads_json_fallback(lang)
        if pending is not None:
            pending_vars, pending_presets = pending
            # 已入库优先：JSON 中的同名键不覆盖 Python 模块中的值
            for k, v in pending_vars.items():
                if k not in vars_dict:
                    vars_dict[k] = v
            for pn in _PRESET_NAMES:
                if pn in pending_presets:
                    for k, v in pending_presets[pn].items():
                        if k not in presets[pn]:
                            presets[pn][k] = v
            console.print(
                f"   [dim][>] Pending 载荷已合并: "
                f"总计 {len(vars_dict)} 变量 (Python 模块 + Pending JSON)[/dim]"
            )

    return vars_dict, presets

def load_payload_vars(
    filepath: str,
    validate: bool = True,
) -> tuple[dict[str, str], Optional[PayloadRegistry]]:
    """加载 Payload YAML 文件 → Pydantic 校验 → 返回 (payload_dict, model)。

    自动过滤 _ 开头的元数据键（_description, _presets, _variants 等）。

    Args:
        filepath: YAML 文件路径
        validate: 是否启用 Pydantic 校验

    Returns:
        (payload_dict, registry_or_None)
    """
    if not os.path.exists(filepath):
        console.print(f"[red][ERR] Payload 文件不存在: {filepath}[/red]")
        return {}, None

    if not validate:
        import yaml
        with open(filepath, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return {k: v for k, v in raw.items() if not k.startswith("_")}, None

    try:
        registry = PayloadRegistry.from_yaml_file(filepath)
        vars_dict = registry.extract_payload_vars()
        presets_dict = registry.extract_presets()

        num_presets = len(presets_dict)
        console.print(
            f"[green][OK] Payload 校验通过: {filepath}[/green]\n"
            f"   [dim]{len(vars_dict)} 个变量 + {num_presets} 个预设 (stealth/bruteforce/redteam/academic/minimal)[/dim]"
        )

        return vars_dict, registry

    except Exception as e:
        console.print(f"[bold red][FAIL] Payload 校验失败 ({filepath}):[/bold red]\n   {e}")
        console.print("[yellow][WARN] 校验失败，降级为原始 YAML 加载[/yellow]")
        try:
            import yaml
            with open(filepath, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            return {k: v for k, v in raw.items() if not k.startswith("_")}, None
        except Exception:
            return {}, None


# ═══════════════════════════════════════════════════════════════════
# 2.5. JSON 兜底加载（results/ 下的 PayloadBatch JSON → 在入库前即可验证）
# ═══════════════════════════════════════════════════════════════════

def _resolve_project_root() -> str:
    """返回项目根目录的绝对路径。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_payloads_json_fallback(
    lang: str = "cn",
    results_dir: str = "",
) -> "tuple[dict[str, str], dict[str, dict[str, str]]] | None":
    """从 results/ 目录加载最近生成的 PayloadBatch JSON 作为兜底。

    用于 payload_generator.py 生成的载荷尚未合并到 payloads_{lang}.py 时，
    也能先用 JSON 跑一轮 PROBE 验证。

    查找规则:
      1. results/generated_payloads_{lang}_*.json 中取最新（按文件名倒序）
      2. Pydantic 校验 → PayloadBatch
      3. 转置为 (vars_dict, presets_dict) 格式 ← 与 load_payloads_module() 返回值一致

    Args:
        lang: 语言代码 'cn' / 'en'
        results_dir: results/ 目录路径（默认自动检测项目根目录下的 results/）

    Returns:
        (pending_vars_dict, pending_presets_dict) 或 None（无待入库 JSON 时）
        - vars_dict: {'pending_payload_name': 'base值', ...}
        - presets_dict: {'stealth': {'pending_payload_name': '...'}, ...}
    """
    if not results_dir:
        results_dir = os.path.join(_resolve_project_root(), "results")
    if not os.path.isdir(results_dir):
        return None

    # 查找符合命名规则的 PayloadBatch JSON 文件（按文件名字典序倒排 = 最新在前）
    pattern = os.path.join(results_dir, f"generated_payloads_{lang}_*.json")
    candidates = sorted(_glob.glob(pattern), reverse=True)
    if not candidates:
        return None

    latest = candidates[0]
    console.print(
        f"[dim][>] 检测到待入库 Payload JSON: {os.path.basename(latest)}[/dim]"
    )

    # 解析 + 校验
    try:
        with open(latest, "r", encoding="utf-8") as f:
            raw = f.read()
        batch = PayloadBatch.model_validate_json(raw)
    except Exception as e:
        console.print(f"[yellow][WARN] Pending JSON 校验失败: {e}[/yellow]")
        return None

    # 转置 PayloadBatch → (vars_dict, presets_dict)
    # 行式 PayloadRow → 列式输出，与 get_payloads() 格式完全一致
    pending_vars: dict[str, str] = {}
    pending_presets: dict[str, dict[str, str]] = {pn: {} for pn in _PRESET_NAMES}

    for p in batch.payloads:
        pending_vars[p.name] = p.base
        for pn in _PRESET_NAMES:
            pending_presets[pn][p.name] = getattr(p, pn, p.base)

    added = len(pending_vars)
    if added:
        console.print(
            f"   [dim]已合并 {added} 个 Pending Payload "
            f"({' '.join(pending_vars.keys())})[/dim]"
        )
    return pending_vars, pending_presets


def apply_preset(
    payload_vars: dict,
    preset_name: str,
    presets_from_file: dict,
) -> dict:
    """将预设覆盖到 payload 变量字典上。

    Args:
        payload_vars: 基础 payload 变量字典（会被原地修改并返回）
        preset_name: 预设名（stealth/bruteforce/redteam/academic/minimal）
        presets_from_file: 从 YAML 文件提取的 _presets 字典

    Returns:
        原地修改后的 payload_vars（也返回值方便链式调用）
    """
    if not preset_name or not presets_from_file:
        return payload_vars

    if preset_name not in presets_from_file:
        available = list(presets_from_file.keys())
        console.print(f"[yellow][WARN] 未知预设 '{preset_name}'，可用: {available}[/yellow]")
        return payload_vars

    preset = presets_from_file[preset_name]
    if not isinstance(preset, dict):
        return payload_vars

    applied = 0
    for k, v in preset.items():
        if not k.startswith("_"):
            payload_vars[k] = v
            applied += 1

    preset_desc = preset.get("_desc", preset_name)
    console.print(
        f"[dim][>] 预设已应用: {preset_name} ({preset_desc}) — 覆盖 {applied} 个变量[/dim]"
    )
    return payload_vars


# ═══════════════════════════════════════════════════════════════════
# 3. 批量数据文件健康检查（启动时执行一次）
# ═══════════════════════════════════════════════════════════════════

def validate_all_data_files(data_dir: str = "data") -> bool:
    """启动时快速校验所有数据文件，提前暴露格式问题。

    Returns:
        True 表示全部通过，False 表示有文件校验失败（但不阻塞启动）
    """
    all_ok = True

    # 校验 JSON 用例文件
    for lang_tag, fname in [("cn", "multi_stage_capstone_cases_cn.json"),
                             ("en", "multi_stage_capstone_cases_en.json")]:
        filepath = os.path.join(data_dir, fname)
        if os.path.exists(filepath):
            _, model = load_test_cases(filepath, validate=True, use_cache=False)
            if model is None:
                all_ok = False

    # 校验 Payload Python 模块（替代 YAML 文件）
    for lang_tag in ["cn", "en"]:
        try:
            vars_dict, presets = load_payloads_module(lang_tag)
            if not vars_dict:
                all_ok = False
        except Exception:
            all_ok = False

    if all_ok:
        console.print("[bold green][OK] 所有数据文件校验通过[/bold green]")
    else:
        console.print("[bold yellow][WARN] 部分数据文件校验未通过，已降级加载（不影响运行）[/bold yellow]")

    return all_ok
