"""InMemoryMemory — 纯 Python 内存存储核心（零 SQLite 依赖）。

设计目标：
  - 提供独立的攻击结果存储，无需外部数据库
  - 实现报告友好的结构化导出（JSON/CSV）
  - 导出方法由 MemoryExportMixin 提供（memory_export.py）

使用方式：
    from redteam.attack.engine.in_memory_memory import InMemoryMemory

    mem = InMemoryMemory()
    # ... 攻击执行 ...
    mem.export_conversations(file_path=Path("reports/run_id/attack_results.json"))
    vulnerabilities = mem.get_high_risk(threshold=4.0)
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from redteam.attack.engine.memory_export import MemoryExportMixin

logger = logging.getLogger(__name__)


@dataclass
class ConversationEntry:
    """单条对话记录 — 核心字段。"""

    conversation_id: str
    role: str  # "user" | "assistant" | "system"
    content: str
    original_value: str = ""
    converted_value: str = ""
    conversation_index: int = 0
    timestamp: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResultEntry:
    """攻击结果记录 — 核心字段。"""

    id: str
    attack_id: str
    conversation_id: str
    is_successful: bool = False
    score: float = 0.0
    attack_name: str = ""
    attack_class: str = ""
    converter_class: str = ""
    objective: str = ""
    response: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class InMemoryMemory(MemoryExportMixin):
    """纯内存存储，实现 MemoryInterface 最低接口协议。

    特性：
      - 零外部依赖（无 SQLAlchemy/SQLite 依赖）
      - 线程安全（Python GIL 保证基本安全）
      - 导出功能通过 MemoryExportMixin 继承（export_conversations + export_for_report）
      - 支持按 risk_score 阈值过滤高风险发现
      - expire_after_seconds: 内存数据过期时间（默认 86400 = 24h）
    """

    def __init__(self, expire_after_seconds: int = 86400) -> None:
        # 核心存储
        self._conversations: dict[str, list[ConversationEntry]] = {}
        self._attack_results: dict[str, AttackResultEntry] = {}
        self._attack_ids: list[str] = []
        self._conversation_ids: list[str] = []

        # 元数据
        self._created_at = time.time()
        self._expire_after = expire_after_seconds
        self._attack_count = 0
        self._export_count = 0

        logger.info(
            "InMemoryMemory 已初始化 (expire=%ds, 零 SQLite 依赖)",
            expire_after_seconds,
        )

    # ------------------------------------------------------------------
    # MemoryInterface 协议：攻击结果管理
    # ------------------------------------------------------------------

    def add_attack_results_to_memory(
        self, *, attack_results: Sequence[Any]
    ) -> list[Any]:
        """添加攻击结果到内存。

        Args:
            attack_results: AttackResult 对象序列

        Returns:
            输入对象列表
        """
        now = datetime.now(timezone.utc).isoformat()
        _attack_id = self._next_attack_id()

        for result in attack_results:
            conv_id = getattr(result, "conversation_id", str(uuid.uuid4()))
            entry = AttackResultEntry(
                id=str(getattr(result, "id", uuid.uuid4())),
                attack_id=_attack_id,
                conversation_id=conv_id,
                is_successful=getattr(result, "is_successful", False),
                score=self._extract_score(result),
                attack_name=getattr(result, "attack_name", ""),
                attack_class=type(result).__name__ if result else "",
                converter_class=getattr(result, "converter_class", ""),
                objective=getattr(result, "objective", ""),
                response=self._extract_response_text(result),
                timestamp=now,
            )
            self._attack_results[entry.id] = entry

            if conv_id not in self._conversation_ids:
                self._conversation_ids.append(conv_id)

        self._attack_ids.append(_attack_id)
        self._attack_count += 1
        return list(attack_results)

    def get_attack_results(self) -> list[dict[str, Any]]:
        """获取所有攻击结果（dict 格式，方便序列化）。"""
        self._enforce_expiry()
        return [
            {
                "id": r.id,
                "attack_id": r.attack_id,
                "conversation_id": r.conversation_id,
                "is_successful": r.is_successful,
                "risk_score": round(r.score * 10.0, 1),  # 0.0-10.0 scale
                "score": round(r.score, 3),
                "attack_name": r.attack_name,
                "attack_class": r.attack_class,
                "converter_class": r.converter_class,
                "objective": r.objective,
                "response": r.response[:500],
                "timestamp": r.timestamp,
            }
            for r in self._attack_results.values()
        ]

    def get_high_risk(self, threshold: float = 4.0) -> list[dict[str, Any]]:
        """获取高风险漏洞列表（risk_score >= threshold）。

        Args:
            threshold: 风险阈值（0.0-10.0），默认 4.0

        Returns:
            高风险攻击结果列表，按 risk_score 降序排列
        """
        all_results = self.get_attack_results()
        high_risk = [r for r in all_results if r["risk_score"] >= threshold]
        high_risk.sort(key=lambda r: r["risk_score"], reverse=True)
        return high_risk

    # ------------------------------------------------------------------
    # MemoryInterface 协议：对话管理
    # ------------------------------------------------------------------

    def add_message_to_memory(self, *, message: Any) -> None:
        """添加单条消息到内存。"""
        conv_id = getattr(message, "conversation_id", str(uuid.uuid4()))
        entry = ConversationEntry(
            conversation_id=conv_id,
            role=getattr(message, "role", "assistant"),
            content=getattr(message, "content", ""),
            original_value=getattr(message, "original_value", ""),
            converted_value=getattr(message, "converted_value", ""),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        if conv_id not in self._conversations:
            self._conversations[conv_id] = []
            self._conversation_ids.append(conv_id)
        entry.conversation_index = len(self._conversations[conv_id])
        self._conversations[conv_id].append(entry)

    def add_message_pieces_to_memory(self, *, message_pieces: Sequence[Any]) -> None:
        """批量添加消息片段到内存。"""
        for piece in message_pieces:
            self.add_message_to_memory(message=piece)

    def get_conversation(self, *, conversation_id: str) -> list[dict[str, Any]]:
        """获取指定对话的全部消息。"""
        entries = self._conversations.get(conversation_id, [])
        return [
            {
                "role": e.role,
                "content": e.content,
                "index": e.conversation_index,
                "timestamp": e.timestamp,
            }
            for e in sorted(entries, key=lambda x: x.conversation_index)
        ]

    def get_conversation_stats(self) -> dict[str, Any]:
        """获取对话统计信息。"""
        return {
            "total_conversations": len(self._conversation_ids),
            "total_messages": sum(len(v) for v in self._conversations.values()),
            "total_attacks": self._attack_count,
            "created_at": datetime.fromtimestamp(
                self._created_at, tz=timezone.utc
            ).isoformat(),
        }

    # ------------------------------------------------------------------
    # 评分相关
    # ------------------------------------------------------------------

    def add_scores_to_memory(self, *, scores: Sequence[Any]) -> None:
        """添加评分结果（轻量存储）。"""
        for score in scores:
            result_id = getattr(score, "id", None)
            if result_id and result_id in self._attack_results:
                self._attack_results[result_id].metadata.setdefault(
                    "scores", []
                ).append({
                    "score_type": getattr(score, "score_type", ""),
                    "score_value": getattr(score, "score_value", 0.0),
                    "score_category": getattr(score, "score_category", ""),
                })

    def get_scores(self) -> list[dict[str, Any]]:
        """获取所有评分记录。"""
        scores: list[dict[str, Any]] = []
        for result in self._attack_results.values():
            for s in result.metadata.get("scores", []):
                s_copy = dict(s)
                s_copy["attack_id"] = result.attack_id
                scores.append(s_copy)
        return scores

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    def _next_attack_id(self) -> str:
        """生成递增攻击 ID。"""
        return f"attack_{self._attack_count + 1:04d}_{int(time.time())}"

    @staticmethod
    def _extract_score(result: Any) -> float:
        """从 AttackResult 提取评分。"""
        try:
            scores = getattr(result, "objective_scores", None) or []
            if scores:
                return float(sum(s.score for s in scores) / len(scores))
        except Exception:
            pass
        try:
            return float(getattr(result, "score", 0.0))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _extract_response_text(result: Any) -> str:
        """从 AttackResult 提取响应文本。"""
        try:
            conv = getattr(result, "conversation", None)
            if conv:
                msgs = getattr(conv, "messages", None) or []
                for m in reversed(msgs):
                    content = getattr(m, "content", None)
                    if content and getattr(m, "role", "") == "assistant":
                        return str(content)[:2000]
        except Exception:
            pass
        return ""

    def _enforce_expiry(self) -> None:
        """检查并清理过期数据。"""
        if self._expire_after <= 0:
            return
        cutoff = time.time() - self._expire_after
        if self._created_at < cutoff:
            self._conversations.clear()
            self._attack_results.clear()
            self._attack_ids.clear()
            self._conversation_ids.clear()
            self._created_at = time.time()
            logger.debug("InMemoryMemory: 过期数据已清理")

    # ------------------------------------------------------------------
    # 其他 MemoryInterface 协议方法（最低实现）
    # ------------------------------------------------------------------

    def dispose_engine(self) -> None:
        """清理资源。"""
        pass

    def cleanup(self) -> None:
        """清理所有存储数据。"""
        self._conversations.clear()
        self._attack_results.clear()
        self._attack_ids.clear()
        self._conversation_ids.clear()

    def reset_database(self) -> None:
        """重置数据库。"""
        self.cleanup()
        self._created_at = time.time()

    def get_all_embeddings(self) -> list[Any]:
        """获取所有 embedding（空实现，无 embedding 支持）。"""
        return []

    def get_session(self) -> Any:
        """获取数据库 session（InMemory 无 session，返回 None）。"""
        return None

    def get_prompt_scores(self) -> list[Any]:
        """获取提示评分。"""
        return self.get_scores()

    def get_seeds(self) -> list[Any]:
        """获取种子数据（空实现）。"""
        return []

    def get_seed_groups(self) -> list[Any]:
        """获取种子组（空实现）。"""
        return []

    def print_schema(self) -> None:
        """打印 schema（空实现）。"""
        logger.debug("InMemoryMemory: schema 不可用（纯内存存储）")

    def results_path(self) -> Path:
        """返回结果路径。"""
        return Path("reports") / "memory_exports"

    def results_storage_io(self) -> Any:
        """结果存储 IO（空实现）。"""
        return None


__all__ = [
    "InMemoryMemory",
    "ConversationEntry",
    "AttackResultEntry",
]
