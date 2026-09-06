"""ContentFilterExt — 扩展 PyRIT 原生内容过滤器标记。

对齐 PyRIT 1.0.1 架构:
    PyRIT 1.0.1 中 ``CONTENT_FILTER_MARKERS`` 定义在
    ``pyrit.exceptions.exception_classes`` 模块中 (frozenset)。

    ``_is_content_filter_error`` 函数 (在 ``openai_error_handling`` 模块中)
    从 ``exception_classes`` 导入 ``CONTENT_FILTER_MARKERS`` 并执行
    子串扫描来判断是否为内容过滤错误。

    本模块通过直接扩展 ``exception_classes.CONTENT_FILTER_MARKERS``
    frozenset 来增强 PyRIT 原生内容过滤检测能力，无需包装函数。

三层防御机制:
    L1: 静态标记 (YAML 配置文件)
    L2: 默认扩展标记 (覆盖第三方 API 中文安全标记)
    L3: heuristic 动态发现 (从错误信息中发现新标记, 持久化缓存)

学术依据:
    - PyRIT (arXiv:2407.01232) — 内容过滤检测是 target 交互的核心
    - Greshake et al. (arXiv:2302.12173) — 目标安全系统探测
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# L2: 默认扩展标记 (覆盖第三方 API, 特别是中文 LLM 服务)
# PyRIT 原生 CONTENT_FILTER_MARKERS 已包含:
#   content_filter, content_safety_violation, policy_violation, moderation_blocked
# 这里补充第三方 API 常见的内容过滤标记
_DEFAULT_EXTRA_MARKERS = frozenset(
    {
        # 英文扩展标记
        "security_audit_fail",
        "security_error",
        "sensitive_content",
        "risk_content_detected",
        "review_blocked",
        "safety_system",
        "safety_system_triggered",
        # 中文内容过滤标记 (国产 LLM 服务常见)
        "违规信息",
        "内容违规",
        "内容包含敏感词",
        "我无法回答",
        "作为AI",
        "我不能提供",
        "敏感词",
        "内容审核",
        "安全拦截",
    }
)

# heuristic 发现的标记缓存路径
_CACHE_PATH = Path("outputs/cache/content_filter_markers.json")

# heuristic 模式: 从常见错误信息中发现新标记
_HEURISTIC_PATTERNS = [
    re.compile(r'"(block\w*|filter\w*|reject\w*|deny\w*)":\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'"(reason|message)":\s*"([^"]*(?:block|filter|reject|denied|violation)[^"]*)"', re.IGNORECASE),
]


def extend_content_filter_markers(
    config_path: str | Path | None = None,
) -> frozenset[str]:
    """扩展 PyRIT 原生 ``CONTENT_FILTER_MARKERS`` (三层防御)。

    对齐 PyRIT 1.0.1:
        PyRIT 1.0.1 的 ``CONTENT_FILTER_MARKERS`` 定义在
        ``pyrit.exceptions.exception_classes`` 模块中。
        ``_is_content_filter_error`` (在 ``openai_error_handling`` 中) 从
        ``exception_classes`` 导入此 frozenset。
        直接扩展此 frozenset 即可增强所有使用它的检测逻辑。

    执行流程:
        1. 加载 YAML 静态配置 (L1)
        2. 合并默认扩展标记 (L2)
        3. 加载上次运行发现的标记缓存 (L3)
        4. 扩展 ``exception_classes.CONTENT_FILTER_MARKERS`` frozenset
        5. 功能验证 — 确保扩展标记被 PyRIT 识别

    Args:
        config_path: YAML 配置文件路径 (可选)。

    Returns:
        所有扩展标记的 frozenset。
    """
    # L1: 静态配置
    static_markers: set[str] = set()
    if config_path:
        path = Path(config_path)
        if path.exists():
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and isinstance(data.get("markers"), list):
                static_markers.update(data["markers"])
            logger.info("L1: Loaded %d static markers from %s", len(static_markers), config_path)

    # L2: 默认扩展标记
    all_markers = static_markers | _DEFAULT_EXTRA_MARKERS
    logger.info("L2: %d default extra markers", len(_DEFAULT_EXTRA_MARKERS))

    # L3: heuristic 缓存
    cached_markers = _load_discovered_markers()
    all_markers |= cached_markers
    logger.info("L3: %d cached discovered markers", len(cached_markers))

    # 扩展 PyRIT 原生 CONTENT_FILTER_MARKERS
    _patch_content_filter_markers(all_markers)

    # 功能验证
    _verify_patch(all_markers)

    logger.info("Content filter extended with %d total markers", len(all_markers))
    return frozenset(all_markers)


def _patch_content_filter_markers(markers: set[str]) -> None:
    """扩展 PyRIT 原生 ``CONTENT_FILTER_MARKERS`` frozenset。

    对齐 PyRIT 1.0.1:
        ``CONTENT_FILTER_MARKERS`` 定义在
        ``pyrit.exceptions.exception_classes`` 模块中。
        直接替换该模块属性为合并后的 frozenset。

        ``openai_error_handling._is_content_filter_error`` 通过
        ``from pyrit.exceptions.exception_classes import CONTENT_FILTER_MARKERS``
        导入此集合，因此直接替换模块属性即可生效。
    """
    try:
        from pyrit.exceptions import exception_classes

        existing = getattr(exception_classes, "CONTENT_FILTER_MARKERS", frozenset())
        combined = frozenset(existing) | frozenset(markers)
        exception_classes.CONTENT_FILTER_MARKERS = combined
        logger.debug("Patched CONTENT_FILTER_MARKERS: %d total", len(combined))
    except ImportError:
        logger.warning("Could not import exception_classes for patching")

    # 也补丁 handle_bad_request_exception 中的引用 (如果存在)
    # handle_bad_request_exception 在 exception_classes 模块中,
    # 它直接引用模块级 CONTENT_FILTER_MARKERS 变量,
    # 所以上面的替换已经覆盖了它。


def _verify_patch(markers: set[str]) -> None:
    """功能验证 — 确保扩展标记被 PyRIT 识别。

    对齐 PyRIT 1.0.1: 验证 ``exception_classes.CONTENT_FILTER_MARKERS``
    已包含所有扩展标记。
    """
    try:
        from pyrit.exceptions import exception_classes

        current = getattr(exception_classes, "CONTENT_FILTER_MARKERS", frozenset())
        missing = markers - set(current)
        if missing:
            logger.error("Content filter verification FAILED: %d markers missing", len(missing))
            raise RuntimeError(f"Content filter markers not properly patched: {missing}")
        logger.debug("Content filter verification passed: all markers present")
    except ImportError:
        logger.warning("Could not verify content filter patch (module not found)")


def persist_discovered_markers() -> None:
    """持久化动态发现的标记到 JSON 文件。"""
    try:
        from pyrit.exceptions import exception_classes

        current = getattr(exception_classes, "CONTENT_FILTER_MARKERS", frozenset())
        discovered = set(current) - _DEFAULT_EXTRA_MARKERS
        # 也排除 PyRIT 原生标记
        _native_markers = frozenset(
            {
                "content_filter",
                "content_safety_violation",
                "policy_violation",
                "moderation_blocked",
            }
        )
        discovered -= _native_markers
        if not discovered:
            return

        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(
            json.dumps(list(discovered), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("Persisted %d discovered markers to %s", len(discovered), _CACHE_PATH)
    except ImportError:
        pass


def _load_discovered_markers() -> set[str]:
    """加载上次运行发现的标记缓存。"""
    if not _CACHE_PATH.exists():
        return set()
    try:
        data = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(data)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning("Failed to load discovered markers: %s", e)
    return set()


def discover_markers_from_error(error_str: str) -> set[str]:
    """从错误信息中 heuristic 发现新内容过滤标记。

    Args:
        error_str: 错误信息字符串。

    Returns:
        新发现的标记集合。
    """
    discovered: set[str] = set()
    for pattern in _HEURISTIC_PATTERNS:
        for match in pattern.finditer(error_str):
            marker = match.group(2).strip()
            if marker and len(marker) < 100:
                discovered.add(marker)
    if discovered:
        logger.info("Heuristic discovered %d new markers: %s", len(discovered), discovered)
    return discovered
