# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""扩展 PyRIT 内容过滤器标记 — 兼容第三方 OpenAI 兼容 API 的安全审查错误格式。

PyRIT 原生 ``CONTENT_FILTER_MARKERS`` 仅覆盖 OpenAI/Azure MAI 的标记::

    content_filter, content_safety_violation, policy_violation, moderation_blocked

第三方 OpenAI 兼容 API (如 LongCat, DeepSeek, 通义千问等) 使用不同的错误码和类型,
导致 PyRIT 无法识别其内容过滤响应,将 400 错误视为普通 ``BadRequestError`` 重新抛出,
引发整个场景崩溃。

本模块在运行时扩展标记集 (monkey-patch),**不修改 PyRIT 源码**:

  1. 读取 ``data/config/content_filter_markers.yaml`` 配置 (静态扩展)
  2. 合并原生标记 + 扩展标记
  3. 替换 ``pyrit.exceptions.exception_classes.CONTENT_FILTER_MARKERS``
  4. 替换 ``pyrit.prompt_target.openai.openai_error_handling.CONTENT_FILTER_MARKERS``
  5. 包装 ``_is_content_filter_error()`` 增加 heuristic 自动发现 (P3 动态探测)

**三层防御机制**:

  - **L1 静态标记** — YAML 配置的已知标记 (子串匹配)
  - **L2 默认扩展** — 硬编码的常见第三方 API 标记 (YAML 缺失时兜底)
  - **L3 动态发现** — heuristic 关键词检测,自动注册新标记并持久化

原理:
  - PyRIT 的 ``_is_content_filter_error()`` 和 ``handle_bad_request_exception()``
    均通过子串匹配方式检测内容过滤标记
  - 标记在两个模块各自有引用 (``from ... import CONTENT_FILTER_MARKERS``)
  - 因此需要同时替换两个模块的引用,否则只补丁一个不生效
  - 动态发现通过包装 ``_is_content_filter_error()`` 实现,
    在静态标记不匹配时做 heuristic 降级检测

学术依据:
  - PyRIT (arXiv:2407.01232): ``response_error="blocked"`` 语义化错误响应设计,
    明确将内容过滤器拦截视为攻击结果而非异常
  - JailbreakBench (arXiv:2402.01135): 内容过滤拦截计为攻击失败 (ASR=0),
    不中断评估流程

> **日期**: 2026-8-1
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# ============================================================
# 原生标记 (PyRIT 1.1.0.dev0) — 不可删除
# ============================================================

_NATIVE_MARKERS = frozenset(
    {
        "content_filter",
        "content_safety_violation",
        "policy_violation",
        "moderation_blocked",
    }
)

# ============================================================
# 默认扩展标记 — 覆盖已知第三方 OpenAI 兼容 API (L2 兜底)
# ============================================================

_DEFAULT_EXTRA_MARKERS = frozenset(
    {
        # LongCat-2.0 API — 服务器端 security_audit 安全审查
        "security_audit_fail",
        "security_error",
        # 通义千问 / 阿里云 — 内容安全审查
        "sensitive_content",
        # 百度文心 — 风险内容检测
        "risk_content_detected",
        # DeepSeek (部分版本) — 审查拦截
        "review_blocked",
        # 通用中文安全审查关键词 (子串匹配)
        "违规信息",
    }
)

# ============================================================
# L3: heuristic 关键词 — 用于动态发现未知 API 的内容过滤错误
# ============================================================
# 当静态标记 (L1+L2) 不匹配时,检查错误负载中是否包含这些关键词。
# 如果包含,则判定为内容过滤并自动注册 error.code 作为新标记。
# 选取的关键词在安全审查语境中具有高区分度,不易出现在正常 400 错误中。

_SECURITY_KEYWORDS = frozenset(
    {
        # 英文关键词
        "security",
        "audit",
        "safety",
        "violation",
        "blocked",
        "moderation",
        "sensitive",
        "review",
        "prohibited",
        "inappropriate",
        "harmful",
        # 中文关键词
        "违规",
        "审查",
        "敏感",
        "拦截",
        "不当",
        "有害",
    }
)

# ============================================================
# 运行时状态
# ============================================================

# 当前合并后的完整标记集 (静态)
_current_markers: frozenset[str] = _NATIVE_MARKERS | _DEFAULT_EXTRA_MARKERS

# 运行时动态发现的标记 (L3)
_discovered_markers: set[str] = set()

# 持久化路径
_DISCOVERED_CACHE_PATH = Path("data/config/content_filter_discovered.json")


# ============================================================
# L3: heuristic 自动发现
# ============================================================


def _heuristic_is_content_filter_error(data: dict[str, object] | str) -> tuple[bool, set[str]]:
    """Heuristic 检测: 错误负载是否看起来像内容过滤拦截。

    在静态标记 (L1+L2) 不匹配时调用。检查错误负载中是否包含
    安全审查相关关键词。如果匹配,返回 True 并给出建议注册的新标记。

    Args:
        data: 错误负载 (dict 或 str)

    Returns:
        (is_content_filter, suggested_markers) 元组:
        - is_content_filter: 是否判定为内容过滤
        - suggested_markers: 建议注册的新标记集合 (error.code, error.type)
    """
    suggested: set[str] = set()

    if isinstance(data, dict):
        error_obj = data.get("error")
        if isinstance(error_obj, dict):
            code = str(error_obj.get("code", "")).lower()
            error_type = str(error_obj.get("type", "")).lower()
            message = str(error_obj.get("message", "")).lower()

            # 合并所有文本字段做关键词扫描
            combined = f"{code} {error_type} {message}"

            matched = any(kw in combined for kw in _SECURITY_KEYWORDS)
            if matched:
                # 建议注册 code 和 type 作为新标记
                if code and code not in _current_markers:
                    suggested.add(code)
                if error_type and error_type not in _current_markers:
                    suggested.add(error_type)
                return True, suggested

    elif isinstance(data, str):
        data_lower = data.lower()
        if any(kw in data_lower for kw in _SECURITY_KEYWORDS):
            return True, suggested

    return False, suggested


def _register_discovered_markers(new_markers: set[str]) -> None:
    """注册动态发现的新标记并同步到 PyRIT 模块。

    Args:
        new_markers: 新发现的标记集合
    """
    if not new_markers:
        return

    # 过滤掉已经在当前标记集中的
    truly_new = new_markers - _current_markers - _discovered_markers
    if not truly_new:
        return

    _discovered_markers.update(truly_new)
    logger.info("Auto-discovered %d new content filter markers: %s", len(truly_new), truly_new)

    # 同步到 PyRIT 模块
    _sync_markers_to_pyrit()


def _sync_markers_to_pyrit() -> None:
    """将当前所有标记 (静态 + 动态) 同步到 PyRIT 两个模块。"""
    merged = _current_markers | frozenset(_discovered_markers)

    try:
        import pyrit.exceptions.exception_classes as exc_mod

        exc_mod.CONTENT_FILTER_MARKERS = merged
    except Exception as e:
        logger.warning("Failed to sync markers to exception_classes: %s", e)

    try:
        import pyrit.prompt_target.openai.openai_error_handling as eh_mod

        eh_mod.CONTENT_FILTER_MARKERS = merged
    except Exception as e:
        logger.warning("Failed to sync markers to openai_error_handling: %s", e)


def persist_discovered_markers() -> None:
    """将动态发现的标记持久化到 JSON 文件,供下次运行加载。"""
    if not _discovered_markers:
        return

    try:
        _DISCOVERED_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "discovered_markers": sorted(_discovered_markers),
            "description": "Auto-discovered content filter markers from unknown API providers",
        }
        with open(_DISCOVERED_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("Persisted %d discovered markers to %s", len(_discovered_markers), _DISCOVERED_CACHE_PATH)
    except Exception as e:
        logger.warning("Failed to persist discovered markers: %s", e)


def _load_discovered_markers() -> None:
    """从 JSON 文件加载上次运行发现的标记。"""
    if not _DISCOVERED_CACHE_PATH.exists():
        return

    try:
        with open(_DISCOVERED_CACHE_PATH, encoding="utf-8") as f:
            data = json.load(f) or {}
        markers = data.get("discovered_markers", [])
        if markers:
            _discovered_markers.update(markers)
            logger.info("Loaded %d previously discovered markers from cache", len(markers))
    except Exception as e:
        logger.warning("Failed to load discovered markers cache: %s", e)


# ============================================================
# 主扩展函数
# ============================================================


def extend_content_filter_markers(config_path: str | Path | None = None) -> frozenset[str]:
    """扩展 PyRIT 的 ``CONTENT_FILTER_MARKERS`` (三层防御机制)。

    执行流程:
      1. 加载 YAML 静态配置 (L1)
      2. 合并默认扩展标记 (L2)
      3. 加载上次运行发现的标记缓存 (L3)
      4. 替换 PyRIT 两个模块的 frozenset 引用
      5. 包装 ``_is_content_filter_error()`` 增加 heuristic 自动发现 (L3)

    Args:
        config_path: YAML 配置文件路径。如果为 None,使用默认路径
            ``data/config/content_filter_markers.yaml``。

    Returns:
        合并后的完整标记集 (静态部分,不含运行时动态发现)。
    """
    global _current_markers

    extra_markers = _DEFAULT_EXTRA_MARKERS

    # L1: 尝试从 YAML 加载静态配置
    if config_path is None:
        config_path = Path("data/config/content_filter_markers.yaml")

    config_path = Path(config_path)
    if config_path.exists():
        try:
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            yaml_markers = config.get("extra_markers", [])
            if yaml_markers:
                extra_markers = extra_markers | frozenset(yaml_markers)
                logger.info(
                    "Loaded %d extra content filter markers from %s",
                    len(yaml_markers),
                    config_path,
                )
        except Exception as e:
            logger.warning("Failed to load content filter markers config: %s", e)

    # 合并静态标记 (L1 + L2)
    _current_markers = _NATIVE_MARKERS | extra_markers

    # L3: 加载上次运行发现的标记缓存
    _load_discovered_markers()

    # 合并所有标记 (静态 + 缓存的动态发现)
    merged = _current_markers | frozenset(_discovered_markers)

    # Monkey-patch: 替换两个模块的 CONTENT_FILTER_MARKERS 引用
    patched_count = 0

    # 模块 1: pyrit.exceptions.exception_classes
    #   — handle_bad_request_exception() 使用 (else 分支 raise 的判定)
    try:
        import pyrit.exceptions.exception_classes as exc_mod

        exc_mod.CONTENT_FILTER_MARKERS = merged
        patched_count += 1
    except Exception as e:
        logger.warning("Failed to patch exception_classes.CONTENT_FILTER_MARKERS: %s", e)

    # 模块 2: pyrit.prompt_target.openai.openai_error_handling
    #   — _is_content_filter_error() 使用 (is_content_filter 判定)
    try:
        import pyrit.prompt_target.openai.openai_error_handling as eh_mod

        eh_mod.CONTENT_FILTER_MARKERS = merged
        patched_count += 1

        # L3: 包装 _is_content_filter_error 增加 heuristic 自动发现
        _patch_is_content_filter_error(eh_mod)
    except Exception as e:
        logger.warning("Failed to patch openai_error_handling: %s", e)

    # 输出摘要
    if patched_count > 0:
        total = len(merged)
        extra_count = len(merged - _NATIVE_MARKERS)
        print(f"  [OK] 内容过滤器标记扩展: {total} 个标记 ({patched_count}/2 模块已补丁)")
        print(f"       原生: {len(_NATIVE_MARKERS)} | 扩展: {extra_count}")
        if _discovered_markers:
            print(f"       动态发现: {len(_discovered_markers)} 个 (已缓存)")
        print(f"       heuristic 自动发现: 已启用 ({len(_SECURITY_KEYWORDS)} 个关键词)")
    else:
        print("  [警告] 内容过滤器标记扩展失败, 所有补丁均未生效")

    return merged


def _patch_is_content_filter_error(eh_mod) -> None:
    """包装 ``_is_content_filter_error`` 函数,增加 heuristic 自动发现 (L3)。

    包装后的函数执行流程:
      1. 调用原始函数 (使用已补丁的静态标记集)
      2. 如果原始函数返回 True → 直接返回
      3. 如果原始函数返回 False → 调用 heuristic 检测
      4. heuristic 匹配 → 自动注册新标记,返回 True
      5. heuristic 不匹配 → 返回 False

    Args:
        eh_mod: ``pyrit.prompt_target.openai.openai_error_handling`` 模块
    """
    original_fn = eh_mod._is_content_filter_error

    # 避免重复包装
    if getattr(original_fn, "_pyrit_pipeline_patched", False):
        return

    def _patched_is_content_filter_error(data: dict[str, object] | str) -> bool:
        # L1+L2: 原始逻辑 (已使用补丁后的标记集)
        try:
            if original_fn(data):
                return True
        except Exception:
            pass

        # L3: heuristic 自动发现
        is_cf, suggested = _heuristic_is_content_filter_error(data)
        if is_cf:
            # 自动注册新标记
            if suggested:
                _register_discovered_markers(suggested)
            return True

        return False

    # 标记为已补丁,避免重复包装
    _patched_is_content_filter_error._pyrit_pipeline_patched = True  # type: ignore[attr-defined]
    eh_mod._is_content_filter_error = _patched_is_content_filter_error
    logger.info("Patched _is_content_filter_error with heuristic auto-discovery")
