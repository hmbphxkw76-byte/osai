# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""扩展 PyRIT 内容过滤器标记 — 兼容第三方 OpenAI 兼容 API 的安全审查错误格式。.

PyRIT 原生 ``CONTENT_FILTER_MARKERS`` 仅覆盖 OpenAI/Azure MAI 的标记::

    content_filter, content_safety_violation, policy_violation, moderation_blocked

第三方 OpenAI 兼容 API (如 LongCat, DeepSeek, 通义千问等) 使用不同的错误码和类型,
导致 PyRIT 无法识别其内容过滤响应,将 400 错误视为普通 ``BadRequestError`` 重新抛出,
引发整个场景崩溃。

本模块在运行时扩展标记集 (monkey-patch),**不修改 PyRIT 源码**:

  1. 读取 ``data/setting/content_filter_markers.yaml`` 配置 (静态扩展)
  2. 合并原生标记 + 扩展标记
  3. 自动发现所有持有 ``CONTENT_FILTER_MARKERS`` 的已加载模块并替换
  4. 自动发现所有持有 ``_is_content_filter_error`` 的已加载模块并包装
  5. 补丁后功能验证 — 确保扩展标记被 PyRIT 实际识别
  6. 版本守护 — 检测 PyRIT 版本变更

**三层防御机制**:

  - **L1 静态标记** — YAML 配置的已知标记 (子串匹配)
  - **L2 默认扩展** — 硬编码的常见第三方 API 标记 (YAML 缺失时兜底)
  - **L3 动态发现** — heuristic 关键词检测,自动注册新标记并持久化

**可维护性设计** (v2.0 重构):

  - **自动模块发现** — 扫描 ``sys.modules`` 发现所有消费模块,无需硬编码路径
  - **功能验证** — 补丁后用扩展标记构造测试负载,断言 PyRIT 能识别
  - **版本守护** — 检查 ``pyrit.__version__`` 与已测试版本是否一致
  - **恢复机制** — 保存原始引用,支持 ``restore_content_filter_markers()``
  - **幂等性** — 重复调用安全,不重复包装
  - **Fail-fast** — 验证失败立即报错,阻止流水线带病运行

原理:
  - PyRIT 的 ``_is_content_filter_error()`` 和 ``handle_bad_request_exception()``
    均通过子串匹配方式检测内容过滤标记
  - 标记通过 ``from ... import CONTENT_FILTER_MARKERS`` 在多个模块产生本地绑定
  - 因此需要自动发现并替换所有持有该属性的模块,否则遗漏模块静默失效
  - ``_is_content_filter_error`` 同理被多个模块 ``from ... import`` 本地绑定
  - 动态发现通过包装 ``_is_content_filter_error()`` 实现,
    在静态标记不匹配时做 heuristic 降级检测

学术依据:
  - PyRIT (arXiv:2407.01232): ``response_error="blocked"`` 语义化错误响应设计,
    明确将内容过滤器拦截视为攻击结果而非异常
  - JailbreakBench (arXiv:2402.01135): 内容过滤拦截计为攻击失败 (ASR=0),
    不中断评估流程
  - Postel's Law (Robustness Principle): 对自身操作保守,对外部信息宽容
  - Fail-Fast Principle (Shore, "Fail Fast"): 错误尽早暴露,降低调试成本

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-2 — v2.0: 自动模块发现 + 功能验证 + 版本守护 + 恢复机制,
>     消除硬编码路径和静默失败风险
>   2026-8-1 — v1.0: 初始实现,三层防御机制 (L1/L2/L3)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ============================================================
# 已测试的 PyRIT 版本 — 版本守护基准
# ============================================================

_TESTED_PYRIT_VERSION = "1.1.0.dev0"

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
_DISCOVERED_CACHE_PATH = Path("data/setting/content_filter_discovered.json")

# 原始引用备份 — 用于恢复机制 (测试隔离 / 版本回退)
_original_state: dict[str, Any] = {
    "markers": {},  # {module_qualname: original_frozenset}
    "functions": {},  # {module_qualname: original_function}
    "patched": False,
}


# ============================================================
# 自动模块发现 — 扫描 sys.modules 查找所有消费模块
# ============================================================


def _discover_marker_holders() -> list[ModuleType]:
    """自动发现所有持有 ``CONTENT_FILTER_MARKERS`` 属性的已加载模块。.

    PyRIT 中 ``CONTENT_FILTER_MARKERS`` 通过 ``from ... import`` 在多个模块
    产生本地绑定。硬编码路径会在 PyRIT 新增消费模块时静默遗漏。

    Returns:
        持有 ``CONTENT_FILTER_MARKERS`` 属性的模块列表。
    """
    holders: list[ModuleType] = []
    for mod in sys.modules.values():
        if mod is None:
            continue
        # 排除自身
        if getattr(mod, "__name__", "") == __name__:
            continue
        try:
            if hasattr(mod, "CONTENT_FILTER_MARKERS"):
                holders.append(mod)
        except Exception:
            # 跳过触发 lazy import 错误的模块 (如 transformers)
            continue
    return holders


def _discover_function_holders() -> list[ModuleType]:
    """自动发现所有持有 ``_is_content_filter_error`` 属性的已加载模块。.

    ``_is_content_filter_error`` 被 ``openai_error_handling`` 定义,
    随后被 ``openai_video_target`` 和 ``openai_response_target`` 通过
    ``from ... import`` 导入为本地绑定。
    仅替换定义模块的属性不够,必须同时替换所有消费模块的本地绑定。

    Returns:
        持有 ``_is_content_filter_error`` 属性的模块列表。
    """
    holders: list[ModuleType] = []
    for mod in sys.modules.values():
        if mod is None:
            continue
        if getattr(mod, "__name__", "") == __name__:
            continue
        try:
            if hasattr(mod, "_is_content_filter_error"):
                holders.append(mod)
        except Exception:
            continue
    return holders


# ============================================================
# 版本守护
# ============================================================


def _check_pyrit_version() -> str | None:
    """检查 PyRIT 版本兼容性。.

    Returns:
        版本不匹配时返回警告消息,无问题时返回 None。
    """
    actual_version: str | None = None

    # 策略 1: pyrit.__version__
    try:
        import pyrit

        actual_version = getattr(pyrit, "__version__", None)
    except ImportError:
        pass

    # 策略 2: importlib.metadata
    if actual_version is None:
        try:
            from importlib.metadata import version as get_version

            actual_version = get_version("pyrit")
        except ImportError:
            pass

    if actual_version is None:
        return "无法检测 PyRIT 版本,补丁可能不兼容"

    if actual_version != _TESTED_PYRIT_VERSION:
        return f"PyRIT 版本不匹配: 已测试={_TESTED_PYRIT_VERSION}, 实际={actual_version}"

    return None


# ============================================================
# L3: heuristic 自动发现
# ============================================================


def _heuristic_is_content_filter_error(data: dict[str, object] | str) -> tuple[bool, set[str]]:
    """Heuristic 检测: 错误负载是否看起来像内容过滤拦截。.

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
    """注册动态发现的新标记并同步到所有 PyRIT 消费模块。.

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

    # 同步到所有已发现的 PyRIT 消费模块
    _sync_markers_to_pyrit()


def _sync_markers_to_pyrit() -> None:
    """将当前所有标记 (静态 + 动态) 同步到所有已发现的 PyRIT 消费模块。."""
    merged = _current_markers | frozenset(_discovered_markers)

    holders = _discover_marker_holders()
    for mod in holders:
        try:
            mod.CONTENT_FILTER_MARKERS = merged
        except Exception as e:
            logger.warning("Failed to sync markers to %s: %s", mod.__name__, e)


def persist_discovered_markers() -> None:
    """将动态发现的标记持久化到 JSON 文件,供下次运行加载。."""
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
    except (OSError, json.JSONDecodeError, ValueError) as e:
        logger.warning("Failed to persist discovered markers: %s", e)


def _load_discovered_markers() -> None:
    """从 JSON 文件加载上次运行发现的标记。."""
    if not _DISCOVERED_CACHE_PATH.exists():
        return

    try:
        with open(_DISCOVERED_CACHE_PATH, encoding="utf-8") as f:
            data = json.load(f) or {}
        markers = data.get("discovered_markers", [])
        if markers:
            _discovered_markers.update(markers)
            logger.info("Loaded %d previously discovered markers from cache", len(markers))
    except (OSError, json.JSONDecodeError, ValueError) as e:
        logger.warning("Failed to load discovered markers cache: %s", e)


# ============================================================
# 补丁验证 — 确保扩展标记被 PyRIT 实际识别
# ============================================================


def _verify_patch() -> tuple[bool, str]:
    """验证补丁是否实际生效。.

    用扩展标记构造测试负载,调用实际 PyRIT 函数,断言返回 True。
    如果验证失败,说明补丁未正确生效(可能 PyRIT 版本变更导致 API 变化)。

    Returns:
        (verified, message) 元组:
        - verified: 验证是否通过
        - message: 验证结果描述
    """
    # 选取一个不在原生标记中的扩展标记
    test_marker = "security_audit_fail"
    test_payload = {"error": {"code": test_marker, "message": "blocked by security audit"}}

    # 验证 1: _is_content_filter_error 能识别扩展标记
    try:
        import pyrit.prompt_target.openai.openai_error_handling as eh_mod

        if not eh_mod._is_content_filter_error(test_payload):
            return False, "_is_content_filter_error 未识别扩展标记 'security_audit_fail'"
    except ImportError as e:
        return False, f"调用 _is_content_filter_error 失败: {e}"

    # 验证 2: handle_bad_request_exception 不抛 RuntimeError (标记匹配路径)
    try:
        from unittest.mock import MagicMock

        from pyrit.exceptions.exception_classes import handle_bad_request_exception

        result = handle_bad_request_exception(
            response_text=json.dumps(test_payload),
            request=MagicMock(),
            is_content_filter=False,
        )
        if result is None:
            return False, "handle_bad_request_exception 返回 None (预期非 None)"
    except RuntimeError:
        return False, "handle_bad_request_exception 抛出 RuntimeError — 标记未被识别"
    except (OSError, ValueError) as e:
        return False, f"调用 handle_bad_request_exception 失败: {e}"

    return True, "验证通过"


# ============================================================
# 恢复机制 — 用于测试隔离
# ============================================================


def restore_content_filter_markers() -> None:
    """恢复所有补丁到原始状态。.

    用于:
      - 单元测试隔离 (每个测试后恢复)
      - PyRIT 版本升级后回退补丁
      - 调试时对比补丁前后行为
    """
    for mod_qualname, original in _original_state["markers"].items():
        mod = sys.modules.get(mod_qualname)
        if mod is not None:
            try:
                mod.CONTENT_FILTER_MARKERS = original
            except Exception as e:
                logger.warning("Failed to restore %s.CONTENT_FILTER_MARKERS: %s", mod_qualname, e)

    for mod_qualname, original in _original_state["functions"].items():
        mod = sys.modules.get(mod_qualname)
        if mod is not None:
            try:
                mod._is_content_filter_error = original
            except Exception as e:
                logger.warning("Failed to restore %s._is_content_filter_error: %s", mod_qualname, e)

    _original_state["markers"].clear()
    _original_state["functions"].clear()
    _original_state["patched"] = False
    logger.info("Restored all content filter marker patches to original state")


# ============================================================
# 健康报告
# ============================================================


def _print_health_report(
    *,
    total_markers: int,
    native_count: int,
    extra_count: int,
    discovered_count: int,
    marker_modules: int,
    marker_modules_total: int,
    function_modules: int,
    function_modules_total: int,
    verified: bool,
    version_warning: str | None,
) -> None:
    """打印补丁健康报告。.

    Args:
        total_markers: 合并后的总标记数。
        native_count: 原生标记数。
        extra_count: 扩展标记数。
        discovered_count: 动态发现的标记数。
        marker_modules: 成功补丁的标记模块数。
        marker_modules_total: 发现的标记模块总数。
        function_modules: 成功补丁的函数模块数。
        function_modules_total: 发现的函数模块总数。
        verified: 功能验证是否通过。
        version_warning: 版本警告消息 (无问题时为 None)。
    """
    status = "[OK]" if verified else "[FAIL]"
    print(f"  {status} 内容过滤器标记扩展: {total_markers} 个标记")

    print(f"       原生: {native_count} | 扩展: {extra_count}", end="")
    if discovered_count:
        print(f" | 动态发现: {discovered_count} 个 (已缓存)")
    else:
        print()

    print(f"       标记模块: {marker_modules}/{marker_modules_total} 已补丁")
    print(f"       函数模块: {function_modules}/{function_modules_total} 已补丁")
    print(f"       heuristic 自动发现: 已启用 ({len(_SECURITY_KEYWORDS)} 个关键词)")
    print(f"       功能验证: {'通过' if verified else '失败'}")

    if version_warning:
        print(f"       [版本警告] {version_warning}")


# ============================================================
# 主扩展函数
# ============================================================


def extend_content_filter_markers(config_path: str | Path | None = None) -> frozenset[str]:
    """扩展 PyRIT 的 ``CONTENT_FILTER_MARKERS`` (三层防御 + 健康检查)。.

    执行流程:
      0. 幂等检查 — 已补丁则跳过
      1. 版本守护 — 检查 PyRIT 版本兼容性
      2. 加载 YAML 静态配置 (L1)
      3. 合并默认扩展标记 (L2)
      4. 加载上次运行发现的标记缓存 (L3)
      5. 自动发现所有消费模块
      6. 保存原始引用 (用于恢复)
      7. 补丁所有模块的 CONTENT_FILTER_MARKERS
      8. 补丁所有模块的 _is_content_filter_error (L3 heuristic)
      9. 功能验证 — 确保扩展标记被 PyRIT 实际识别
      10. 健康报告
      11. Fail-fast — 验证失败则报错

    Args:
        config_path: YAML 配置文件路径。如果为 None,使用默认路径
            ``data/setting/content_filter_markers.yaml``。

    Returns:
        合并后的完整标记集 (静态部分,不含运行时动态发现)。

    Raises:
        RuntimeError: 如果补丁验证失败,说明扩展标记未被 PyRIT 识别。
    """
    global _current_markers

    # 0. 幂等检查
    if _original_state["patched"]:
        logger.info("Content filter markers already patched, skipping")
        return _current_markers | frozenset(_discovered_markers)

    # 1. 版本守护
    version_warning = _check_pyrit_version()
    if version_warning:
        logger.warning("Version check: %s", version_warning)

    extra_markers = _DEFAULT_EXTRA_MARKERS

    # 2. L1: 尝试从 YAML 加载静态配置
    if config_path is None:
        config_path = Path("data/setting/content_filter_markers.yaml")

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

    # 3. 合并静态标记 (L1 + L2)
    _current_markers = _NATIVE_MARKERS | extra_markers

    # 4. L3: 加载上次运行发现的标记缓存
    _load_discovered_markers()

    # 合并所有标记 (静态 + 缓存的动态发现)
    merged = _current_markers | frozenset(_discovered_markers)

    # 5. 自动发现所有消费模块
    marker_holders = _discover_marker_holders()
    function_holders = _discover_function_holders()

    logger.info(
        "Discovered %d marker holder(s) and %d function holder(s)",
        len(marker_holders),
        len(function_holders),
    )

    # 6. 保存原始引用 (用于恢复)
    for mod in marker_holders:
        _original_state["markers"][mod.__name__] = mod.CONTENT_FILTER_MARKERS
    for mod in function_holders:
        _original_state["functions"][mod.__name__] = mod._is_content_filter_error

    # 7. 补丁所有模块的 CONTENT_FILTER_MARKERS
    patched_marker_count = 0
    for mod in marker_holders:
        try:
            mod.CONTENT_FILTER_MARKERS = merged
            patched_marker_count += 1
            logger.info("Patched CONTENT_FILTER_MARKERS in %s", mod.__name__)
        except Exception as e:
            logger.warning("Failed to patch %s.CONTENT_FILTER_MARKERS: %s", mod.__name__, e)

    # 8. 补丁所有模块的 _is_content_filter_error (L3 heuristic)
    patched_function_count = 0
    for mod in function_holders:
        try:
            _patch_is_content_filter_error(mod)
            patched_function_count += 1
            logger.info("Patched _is_content_filter_error in %s", mod.__name__)
        except Exception as e:
            logger.warning("Failed to patch %s._is_content_filter_error: %s", mod.__name__, e)

    # 9. 功能验证
    verified, verify_msg = _verify_patch()
    if verified:
        logger.info("Patch verification: %s", verify_msg)
    else:
        logger.error("Patch verification FAILED: %s", verify_msg)

    # 10. 健康报告
    _print_health_report(
        total_markers=len(merged),
        native_count=len(_NATIVE_MARKERS),
        extra_count=len(merged - _NATIVE_MARKERS),
        discovered_count=len(_discovered_markers),
        marker_modules=patched_marker_count,
        marker_modules_total=len(marker_holders),
        function_modules=patched_function_count,
        function_modules_total=len(function_holders),
        verified=verified,
        version_warning=version_warning,
    )

    # 11. Fail-fast: 验证失败则报错
    if not verified:
        raise RuntimeError(
            f"Content filter marker patch verification FAILED: {verify_msg}. "
            "Extended markers are not recognized by PyRIT's functions. "
            "This likely indicates a PyRIT version incompatibility. "
            f"Version warning: {version_warning or 'none'}"
        )

    _original_state["patched"] = True
    return merged


def _patch_is_content_filter_error(mod: ModuleType) -> None:
    """包装模块的 ``_is_content_filter_error`` 函数,增加 heuristic 自动发现 (L3)。.

    包装后的函数执行流程:
      1. 调用原始函数 (使用已补丁的静态标记集)
      2. 如果原始函数返回 True → 直接返回
      3. 如果原始函数返回 False → 调用 heuristic 检测
      4. heuristic 匹配 → 自动注册新标记,返回 True
      5. heuristic 不匹配 → 返回 False

    Args:
        mod: 持有 ``_is_content_filter_error`` 属性的模块
    """
    original_fn = mod._is_content_filter_error

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
    mod._is_content_filter_error = _patched_is_content_filter_error
    logger.info("Patched _is_content_filter_error in %s with heuristic auto-discovery", mod.__name__)
