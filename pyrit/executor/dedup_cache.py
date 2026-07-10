"""
===============================================================================
PyRIT Red Team — 请求级去重缓存 (P1)
===============================================================================
攻击请求去重层: 对 converter 管道的最终输出做 hash 去重。

核心功能:
  1. 相同 prompt+target 的请求只发一次
  2. 结果在多个 case 间共享
  3. 大幅减少重复调用（预计减少 30-50%）

实现:
  - 基于 prompt hash 的内存缓存
  - 线程安全的并发访问
  - 可选的磁盘持久化（跨战役复用）
===============================================================================
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)


@dataclass
class CachedResponse:
    """缓存响应条目。"""
    prompt_hash: str
    response_text: str
    score_value: str | None
    score_reason: str
    case_ids: set[str] = field(default_factory=set)
    combo_names: set[str] = field(default_factory=set)
    timestamp: float = field(default_factory=time.time)
    hit_count: int = 1


class AttackDeduplicator:
    """攻击请求去重器。

    对 (target_endpoint, prompt_text) 做 MD5 hash，
    相同请求直接返回缓存结果。

    Usage:
        dedup = AttackDeduplicator(max_cache_size=10000)

        # 检查是否已缓存
        cached = dedup.lookup(prompt_text, target_endpoint)
        if cached:
            return cached  # 直接复用

        # 执行攻击并缓存
        result = await do_attack(prompt_text)
        dedup.store(prompt_text, target_endpoint, result, case_id="case_1")

    Thread-safe for concurrent access.
    """

    def __init__(
        self,
        max_cache_size: int = 10000,
        ttl_seconds: float = 3600.0,  # 1 小时过期
        enable_persist: bool = False,
        persist_path: str = "",
    ):
        """
        Args:
            max_cache_size: 最大缓存条目数（LRU 淘汰）
            ttl_seconds: 缓存过期时间（秒）
            enable_persist: 是否启用磁盘持久化
            persist_path: 持久化文件路径
        """
        self._max_size = max_cache_size
        self._ttl = ttl_seconds
        self._cache: OrderedDict[str, CachedResponse] = OrderedDict()
        self._lock = threading.Lock()
        self._stats = {
            "total_lookups": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_stored": 0,
            "total_evicted": 0,
        }
        self._enable_persist = enable_persist
        self._persist_path = persist_path

        if enable_persist and persist_path:
            self._load_from_disk()

    def _make_hash(self, prompt_text: str, target_endpoint: str = "") -> str:
        """生成请求唯一 hash。

        Args:
            prompt_text: 发送的文本
            target_endpoint: 目标端点

        Returns:
            MD5 hash
        """
        # 归一化: 去除多余空白
        normalized = " ".join(prompt_text.split())
        content = f"{target_endpoint}|{normalized}"
        return hashlib.md5(content.encode("utf-8")).hexdigest()

    def _evict_expired(self):
        """淘汰过期条目。"""
        now = time.time()
        expired_keys = [
            key for key, entry in self._cache.items()
            if now - entry.timestamp > self._ttl
        ]
        for key in expired_keys:
            del self._cache[key]
            self._stats["total_evicted"] += 1

    def _evict_lru(self):
        """淘汰最久未使用的条目。"""
        while len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)
            self._stats["total_evicted"] += 1

    def lookup(
        self,
        prompt_text: str,
        target_endpoint: str = "",
    ) -> Optional[CachedResponse]:
        """查找缓存。

        Args:
            prompt_text: 发送的文本
            target_endpoint: 目标端点

        Returns:
            CachedResponse 或 None
        """
        with self._lock:
            self._stats["total_lookups"] += 1

            self._evict_expired()

            key = self._make_hash(prompt_text, target_endpoint)

            if key in self._cache:
                entry = self._cache[key]
                # LRU: 移到末尾
                self._cache.move_to_end(key)
                entry.hit_count += 1
                entry.timestamp = time.time()

                self._stats["cache_hits"] += 1
                _log.debug("dedup cache HIT: %s (hits=%d)", key[:8], entry.hit_count)
                return entry

            self._stats["cache_misses"] += 1
            return None

    def store(
        self,
        prompt_text: str,
        target_endpoint: str,
        response_text: str,
        score_value: str | None = None,
        score_reason: str = "",
        case_id: str = "",
        combo_name: str = "",
    ) -> CachedResponse:
        """存储响应到缓存。

        Args:
            prompt_text: 发送的文本
            target_endpoint: 目标端点
            response_text: 响应文本
            score_value: 评分值
            score_reason: 评分原因
            case_id: 用例 ID
            combo_name: 组合名称

        Returns:
            存储的 CachedResponse
        """
        with self._lock:
            self._evict_expired()
            self._evict_lru()

            key = self._make_hash(prompt_text, target_endpoint)

            if key in self._cache:
                # 更新已有条目
                entry = self._cache[key]
                if case_id:
                    entry.case_ids.add(case_id)
                if combo_name:
                    entry.combo_names.add(combo_name)
                self._cache.move_to_end(key)
                return entry

            # 新建条目
            entry = CachedResponse(
                prompt_hash=key,
                response_text=response_text,
                score_value=score_value,
                score_reason=score_reason,
                case_ids={case_id} if case_id else set(),
                combo_names={combo_name} if combo_name else set(),
            )
            self._cache[key] = entry
            self._stats["total_stored"] += 1

            if self._enable_persist:
                self._save_to_disk()

            return entry

    def get_stats(self) -> dict:
        """获取缓存统计信息。"""
        with self._lock:
            hit_rate = (
                self._stats["cache_hits"] / self._stats["total_lookups"]
                if self._stats["total_lookups"] > 0
                else 0.0
            )

            return {
                **self._stats,
                "hit_rate": round(hit_rate, 3),
                "current_size": len(self._cache),
                "estimated_savings": self._stats["cache_hits"],
            }

    def clear(self):
        """清空缓存。"""
        with self._lock:
            self._cache.clear()

    def cleanup(self):
        """强制清理过期和超量条目。"""
        with self._lock:
            self._evict_expired()

    # ── 磁盘持久化 ──

    def _save_to_disk(self):
        """保存缓存到磁盘。"""
        if not self._persist_path:
            return
        try:
            data = {
                key: {
                    "prompt_hash": entry.prompt_hash,
                    "response_text": entry.response_text,
                    "score_value": entry.score_value,
                    "score_reason": entry.score_reason,
                    "case_ids": list(entry.case_ids),
                    "combo_names": list(entry.combo_names),
                    "timestamp": entry.timestamp,
                    "hit_count": entry.hit_count,
                }
                for key, entry in self._cache.items()
            }
            with open(self._persist_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            _log.debug("dedup cache persisted: %d entries", len(data))
        except Exception as e:
            _log.warning("dedup cache persist failed: %s", e)

    def _load_from_disk(self):
        """从磁盘加载缓存。"""
        if not self._persist_path:
            return
        try:
            import os
            if not os.path.exists(self._persist_path):
                return

            with open(self._persist_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for key, entry_data in data.items():
                if len(self._cache) >= self._max_size:
                    break
                entry = CachedResponse(
                    prompt_hash=entry_data.get("prompt_hash", key),
                    response_text=entry_data.get("response_text", ""),
                    score_value=entry_data.get("score_value"),
                    score_reason=entry_data.get("score_reason", ""),
                    case_ids=set(entry_data.get("case_ids", [])),
                    combo_names=set(entry_data.get("combo_names", [])),
                    timestamp=entry_data.get("timestamp", time.time()),
                    hit_count=entry_data.get("hit_count", 0),
                )
                self._cache[key] = entry

            _log.info("dedup cache loaded from disk: %d entries", len(self._cache))
        except Exception as e:
            _log.warning("dedup cache load failed: %s", e)


# ═══════════════════════════════════════════════════════════════
# 全局单例
# ═══════════════════════════════════════════════════════════════

_global_deduplicator: AttackDeduplicator | None = None


def get_deduplicator() -> AttackDeduplicator:
    """获取全局去重器单例。"""
    global _global_deduplicator
    if _global_deduplicator is None:
        _global_deduplicator = AttackDeduplicator()
    return _global_deduplicator
