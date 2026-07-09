"""
Probe Cache — 探测结果持久化，实现探测之间的知识共享。

设计意图：
  当 API 类型识别成功后，结果写入缓存。后续探测（端点枚举、模型列表、
  护栏探测）自动读取缓存，基于已知 API 类型优化探测策略。

  例如：识别到 Ollama 后，端点枚举优先探测 Ollama 路径；
        模型枚举优先走 /api/tags 而非 /v1/models。

缓存文件：configs/.probe_cache.json
缓存键：URL scheme+netloc+path（归一化后），避免微小区分导致缓存不命中。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

_CACHE_FILE = Path(__file__).resolve().parent.parent / ".probe_cache.json"


def _read_cache() -> dict:
    """读取整个探测缓存。"""
    if not _CACHE_FILE.exists():
        return {}
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_cache(data: dict) -> None:
    """写入探测缓存。"""
    _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _normalize_cache_key(url: str) -> str:
    """归一化 URL 作为缓存键 — 去除尾部斜杠、fragment，用 scheme+netloc+path 区分。"""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def save_probe_result(url: str, result_type: str, data: dict) -> None:
    """保存一个探测结果到缓存。

    Args:
        url: 目标 URL（自动归一化）
        result_type: 探测类型名称，如 "api_type"、"models"、"connectivity"
        data: 探测结果数据
    """
    cache = _read_cache()
    key = _normalize_cache_key(url)
    if key not in cache:
        cache[key] = {}
    cache[key][result_type] = data
    cache[key]["cached_at"] = datetime.now(timezone.utc).isoformat()
    _write_cache(cache)


def get_probe_cache(url: str) -> dict:
    """获取某个目标 URL 的全部缓存结果。"""
    cache = _read_cache()
    key = _normalize_cache_key(url)
    return cache.get(key, {})


def get_api_type(url: str) -> str | None:
    """获取缓存的 API 类型。如果未探测或结果为 unknown，返回 None。"""
    c = get_probe_cache(url)
    api_data = c.get("api_type", {})
    api_type = api_data.get("api_type", "")
    if api_type and api_type != "unknown":
        return api_type
    return None


def get_cached_models(url: str) -> list[str]:
    """获取缓存的模型列表。"""
    c = get_probe_cache(url)
    return c.get("models", {}).get("models", []) or c.get("api_type", {}).get("models", []) or []
