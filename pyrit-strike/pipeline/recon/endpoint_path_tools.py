"""路径推断工具 — 从 Burp 请求路径推断 API 前缀与探测路径。

学术依据:
    - arXiv:2306.01943 §4.3-4.4 — 版本段与编号路径段的兄弟端点推断
    - PTES §2: Intelligence Gathering — 分层发现策略
"""

from __future__ import annotations

import re

from pipeline.recon.endpoint_constants import (
    _ALL_KEYWORDS,
    _API_SPEC_PATHS,
    _API_VERSION_PREFIXES,
    _BASELINE_PATHS,
    _HIGH_VALUE_PATHS,
    _TIER_A_KEYWORDS,
)

# ══════════════════════════════════════════════════════════════
# 路径推断工具
# ══════════════════════════════════════════════════════════════

def _infer_api_prefix(path: str) -> str:
    """从原始请求路径推断 API 前缀。

    通用前缀推断逻辑:
        /api/items/IT_01/chat → /api/items/IT_01/
        /api/v1/chat        → /api/v1/
        /api/chat            → /api/
        /custom/prefix/chat  → /custom/prefix/

    规则: 取路径中最后一个路径段之前的部分 (含尾部 /)
    如果路径只有一段 (如 /chat), 则返回 /

    Args:
        path: 原始请求路径。

    Returns:
        推断的 API 前缀 (以 / 结尾)。
    """
    if not path or not path.startswith("/"):
        return "/"

    clean_path = path.split("?")[0]
    parts = clean_path.rstrip("/").split("/")

    if len(parts) <= 2:
        return "/"

    prefix = "/".join(parts[:-1]) + "/"
    return prefix


def _infer_parent_prefix(path: str) -> str:
    """推断上一级前缀 (向上回溯一级)。

    /api/v1/chat → /api/
        /api/items/IT_01/chat → /api/items/
    """
    if not path or not path.startswith("/"):
        return "/"

    parts = path.split("?")[0].rstrip("/").split("/")
    if len(parts) <= 3:
        return "/"
    return "/".join(parts[:-2]) + "/"


def _infer_version_segments(path: str) -> list[str]:
    """从路径中提取版本段 (如 v1, v2) 用于版本化探测。

    学术依据: arXiv:2306.01943 §4.3
      — API 版本段在路径中的出现频率: v1 (78%), v2 (34%), v3 (12%)
    """
    parts = path.split("?")[0].rstrip("/").split("/")
    versions: list[str] = []
    for part in parts:
        if re.match(r"^v\d+$", part, re.IGNORECASE):
            versions.append(part)
    return versions


def _infer_numbered_siblings(path: str) -> list[str]:
    """从编号路径段推断兄弟端点 (如 IT_03 → IT_01, IT_02, IT_04, IT_05)。

    学术依据: arXiv:2306.01943 §4.4
      — 编号路径段 (item_1, IT_01) 的兄弟端点 ±2 范围内命中率 >90%
    """
    parts = path.split("?")[0].rstrip("/").split("/")
    if len(parts) < 3:
        return []

    current_segment = parts[-2]  # 如 IT_01
    parent_prefix = "/".join(parts[:-2]) + "/"

    num_match = re.search(r"(\d+)", current_segment)
    if not num_match:
        return []

    current_num = int(num_match.group(1))
    prefix_part = current_segment[:num_match.start()]
    suffix_part = current_segment[num_match.end():]
    num_width = len(num_match.group(1))

    siblings: list[str] = []
    for offset in range(-2, 3):
        if offset == 0:
            continue
        sibling_num = current_num + offset
        if sibling_num < 1:
            continue
        sibling_segment = f"{prefix_part}{sibling_num:0{num_width}d}{suffix_part}"
        siblings.append(f"{parent_prefix}{sibling_segment}/")

    return siblings


# ══════════════════════════════════════════════════════════════
# 分层探测路径构建
# ══════════════════════════════════════════════════════════════

def _build_layer0_paths() -> list[str]:
    """Layer 0: API 规范文档路径."""
    return list(_API_SPEC_PATHS)


def _build_layer1_paths() -> list[str]:
    """Layer 1: 高价值信息泄露端点."""
    return list(_HIGH_VALUE_PATHS)


def _build_layer2_paths(parsed_path: str) -> list[str]:
    """Layer 2: 同前缀路径推断 (从 Burp 请求路径推断).

    将关键词与推断的 API 前缀拼接, 按 Tier 优先级排序。
    """
    paths: list[str] = []
    prefix = _infer_api_prefix(parsed_path)

    if prefix and prefix != "/":
        # 按 Tier A → B → C 优先级生成
        for kw in _ALL_KEYWORDS:
            paths.append(f"{prefix}{kw}")

    # 兄弟编号探测
    for sibling_prefix in _infer_numbered_siblings(parsed_path):
        for kw in _ALL_KEYWORDS:
            paths.append(f"{sibling_prefix}{kw}")

    # 父级前缀 + 关键词
    parent_prefix = _infer_parent_prefix(parsed_path)
    if parent_prefix and parent_prefix != "/" and parent_prefix != prefix:
        for kw in _TIER_A_KEYWORDS:  # 父级只探测 Tier A (减少无效请求)
            paths.append(f"{parent_prefix}{kw}")

    return paths


def _build_layer3_paths(parsed_path: str) -> list[str]:
    """Layer 3: 版本化探测.

    如果原始路径有版本段 (如 /api/v1/chat), 探测其他版本 (v2, v3)。
    """
    paths: list[str] = []
    versions = _infer_version_segments(parsed_path)

    if not versions:
        # 原始路径无版本段, 探测常见版本前缀
        prefix = _infer_api_prefix(parsed_path)
        if prefix.startswith("/api/") and prefix != "/api/":
            # 已有子路径, 探测 /api/v1/ 等版本前缀
            for vp in _API_VERSION_PREFIXES:
                for kw in _TIER_A_KEYWORDS:
                    paths.append(f"{vp}/{kw}")
        return paths

    # 有版本段: 探测其他版本
    parts = parsed_path.split("?")[0].rstrip("/").split("/")
    for i, part in enumerate(parts):
        if re.match(r"^v\d+$", part, re.IGNORECASE):
            current_ver = int(part[1:])
            for new_ver in range(1, current_ver + 3):
                if new_ver == current_ver:
                    continue
                new_parts = parts.copy()
                new_parts[i] = f"v{new_ver}"
                new_prefix = "/".join(new_parts[:-1]) + "/"
                for kw in _TIER_A_KEYWORDS:
                    paths.append(f"{new_prefix}{kw}")

    return paths


def _build_layer5_paths() -> list[str]:
    """Layer 5: 通用基线路径 (兜底)."""
    return list(_BASELINE_PATHS)


def _build_probe_paths(parsed_path: str) -> list[str]:
    """构建探测路径列表 (兼容函数 — 合并所有 Layer 的路径)。

    用于测试和外部调用。实际运行时 discover_endpoints 使用分层并发探测。

    Args:
        parsed_path: 解析后的 Burp 请求路径。

    Returns:
        去重后的探测路径列表 (按 Layer 0→5 优先级排序)。
    """
    all_paths: list[str] = []

    # Layer 0: API 规范文档
    all_paths.extend(_build_layer0_paths())

    # Layer 1: 高价值端点
    all_paths.extend(_build_layer1_paths())

    # Layer 2: 同前缀推断
    all_paths.extend(_build_layer2_paths(parsed_path))

    # Layer 3: 版本化探测
    all_paths.extend(_build_layer3_paths(parsed_path))

    # Layer 5: 通用基线
    all_paths.extend(_build_layer5_paths())

    # 去重 (保持顺序)
    seen: set[str] = set()
    unique_paths: list[str] = []
    for p in all_paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)

    return unique_paths
