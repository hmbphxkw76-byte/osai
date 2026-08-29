"""ContentFilterExt — 扩展 PyRIT 内容过滤器标记。
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 扩展标记 (覆盖第三方 API)
_DEFAULT_EXTRA_MARKERS = frozenset(
    {
        "security_audit_fail",
        "security_error",
        "sensitive_content",
        "risk_content_detected",
        "review_blocked",
        "违规信息",
        "内容违规",
        "内容包含敏感词",
        "我无法回答",
        "作为AI",
        "我不能提供",
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
    """扩展 PyRIT 内容过滤器标记 (三层防御)。
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

    # 补丁 PyRIT 内容过滤器
    _patch_content_filter_markers(all_markers)

    # 补丁 _is_content_filter_error
    _patch_is_content_filter_error()

    # 功能验证
    _verify_patch(all_markers)

    logger.info("Content filter extended with %d total markers", len(all_markers))
    return frozenset(all_markers)

def _patch_content_filter_markers(markers: set[str]) -> None:
    """补丁 PyRIT 的 CONTENT_FILTER_MARKERS。"""
    try:
        from pyrit.prompt_target.openai import openai_error_handling

        existing = getattr(openai_error_handling, "CONTENT_FILTER_MARKERS", frozenset())
        combined = frozenset(existing) | frozenset(markers)
        openai_error_handling.CONTENT_FILTER_MARKERS = combined
        logger.debug("Patched CONTENT_FILTER_MARKERS: %d total", len(combined))
    except ImportError:
        logger.warning("Could not import openai_error_handling for patching")

    # 也补丁 openai_chat_target 中的引用
    try:
        from pyrit.prompt_target.openai import openai_chat_target

        if hasattr(openai_chat_target, "CONTENT_FILTER_MARKERS"):
            openai_chat_target.CONTENT_FILTER_MARKERS = openai_error_handling.CONTENT_FILTER_MARKERS
    except (ImportError, AttributeError):
        pass

def _patch_is_content_filter_error() -> None:
    """包装 _is_content_filter_error 以增加 heuristic 发现。"""
    try:
        from pyrit.prompt_target.openai import openai_error_handling

        original_fn = getattr(openai_error_handling, "_is_content_filter_error", None)
        if original_fn is None:
            return

        # 防止重复包装
        if getattr(original_fn, "_heuristic_wrapped", False):
            return

        def _heuristic_wrapper(error: Any) -> bool:
            # 先调用原始判断
            if original_fn(error):
                return True
            # heuristic: 检查错误信息中是否包含新标记
            error_str = str(error).lower()
            markers = getattr(openai_error_handling, "CONTENT_FILTER_MARKERS", frozenset())
            for marker in markers:
                if marker.lower() in error_str:
                    return True
            return False

        _heuristic_wrapper._heuristic_wrapped = True  # type: ignore[attr-defined]
        openai_error_handling._is_content_filter_error = _heuristic_wrapper
        logger.debug("Wrapped _is_content_filter_error with heuristic")

    except ImportError:
        logger.warning("Could not patch _is_content_filter_error")

def _verify_patch(markers: set[str]) -> None:
    """功能验证 — 确保扩展标记被 PyRIT 识别。"""
    try:
        from pyrit.prompt_target.openai import openai_error_handling

        current = getattr(openai_error_handling, "CONTENT_FILTER_MARKERS", frozenset())
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
        from pyrit.prompt_target.openai import openai_error_handling

        current = getattr(openai_error_handling, "CONTENT_FILTER_MARKERS", frozenset())
        discovered = set(current) - _DEFAULT_EXTRA_MARKERS
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
