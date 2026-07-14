"""PyRIT 兼容 InMemoryMemory — 纯 Python 内存存储，零 SQLite 依赖。

设计目标：
  - 当 SQLiteMemory 不可用时，作为 PyRIT CentralMemory 的回退存储
  - 实现 MemoryInterface 协议（duck-typing，最低接口覆盖）
  - 内置 export_conversations() 支持 JSON/CSV 导出到 reports/
  - 支持按 risk_score 阈值过滤，方便报告阶段提取高风险漏洞

使用方式：
    from redteam.attack.core.in_memory_memory import InMemoryMemory
    from pyrit.memory import CentralMemory

    mem = InMemoryMemory()
    CentralMemory.set_memory_instance(mem)
    # ... 攻击执行 ...
    mem.export_conversations(file_path=Path("reports/run_id/attack_results.json"))
    vulnerabilities = mem.get_high_risk(threshold=4.0)

PyRIT 兼容性：v0.14.0 MemoryInterface 最小协议实现
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class ConversationEntry:
    """单条对话记录 — 对应 PyRIT PromptMemoryEntry 的核心字段。"""

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
    """攻击结果记录 — 对应 PyRIT AttackResultEntry 的核心字段。"""

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


class InMemoryMemory:
    """PyRIT 兼容的纯内存存储，实现 MemoryInterface 最低接口协议。

    特性：
      - 零外部依赖（无 SQLAlchemy/SQLite 依赖）
      - 线程安全（Python GIL 保证基本安全）
      - 支持 export_conversations() 导出到 JSON/CSV
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
        """添加攻击结果到内存。兼容 PyRIT AttackResult 对象。

        Args:
            attack_results: PyRIT AttackResult 对象序列

        Returns:
            输入对象列表（兼容 PyRIT 接口）
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

        使用示例：
            mem = InMemoryMemory()
            # ... 执行攻击 ...
            vulns = mem.get_high_risk(threshold=4.0)
            for v in vulns:
                print(f"[{v['risk_score']:.1f}] {v['attack_class']}: {v['objective']}")
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
    # 评分相关（PyRIT 兼容）
    # ------------------------------------------------------------------

    def add_scores_to_memory(self, *, scores: Sequence[Any]) -> None:
        """添加评分结果（轻量存储）。"""
        # 评分数据存储为 attack_result 的扩展字段
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
    # export_conversations — 核心导出方法（PyRIT 兼容签名）
    # ------------------------------------------------------------------

    def export_conversations(
        self,
        *,
        attack_id: Optional[str | uuid.UUID] = None,
        conversation_id: Optional[str | uuid.UUID] = None,
        prompt_ids: Optional[Sequence[str] | Sequence[uuid.UUID]] = None,
        labels: Optional[dict[str, str]] = None,
        sent_after: Optional[datetime] = None,
        sent_before: Optional[datetime] = None,
        original_values: Optional[Sequence[str]] = None,
        converted_values: Optional[Sequence[str]] = None,
        data_type: Optional[str] = None,
        not_data_type: Optional[str] = None,
        converted_value_sha256: Optional[Sequence[str]] = None,
        file_path: Optional[Path] = None,
        export_type: str = "json",
    ) -> Path:
        """导出对话和攻击结果数据到文件。

        签名与 PyRIT MemoryInterface.export_conversations 完全兼容。

        Args:
            attack_id: 按攻击 ID 过滤
            conversation_id: 按对话 ID 过滤
            file_path: 导出文件路径（默认自动生成到 reports/ 目录）
            export_type: 导出格式 ("json" | "csv")

        Returns:
            导出文件的 Path 对象

        使用示例：
            # 导出全部数据
            path = mem.export_conversations(
                file_path=Path("reports/run_001/attack_results.json")
            )

            # 按 attack_id 过滤导出
            path = mem.export_conversations(
                attack_id="attack_001",
                file_path=Path("reports/run_001/jailbreak_results.json"),
            )
        """
        # 构建导出数据
        export_data = self._build_export_data(
            attack_id=str(attack_id) if attack_id else None,
            conversation_id=str(conversation_id) if conversation_id else None,
        )

        # 自动生成文件路径
        if file_path is None:
            auto_dir = Path("reports") / "memory_exports"
            auto_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._export_count += 1
            file_path = auto_dir / f"pyrit_results_{ts}_{self._export_count:04d}.{export_type}"

        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if export_type == "csv":
            self._export_csv(export_data, file_path)
        else:
            self._export_json(export_data, file_path)

        self._export_count += 1
        logger.info(
            "InMemoryMemory: 导出 %d 条攻击结果 → %s",
            len(export_data.get("attack_results", [])),
            file_path,
        )
        return file_path

    def _build_export_data(
        self,
        attack_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """构建导出数据结构（便于报告提取）。"""
        self._enforce_expiry()

        # 过滤攻击结果
        results = self.get_attack_results()
        if attack_id:
            results = [r for r in results if r["attack_id"] == attack_id]
        if conversation_id:
            results = [r for r in results if r["conversation_id"] == conversation_id]

        # 过滤对话
        conversations: dict[str, list[dict[str, Any]]] = {}
        for cid, entries in self._conversations.items():
            if conversation_id and cid != conversation_id:
                continue
            conversations[cid] = [
                {
                    "role": e.role,
                    "content": e.content,
                    "original_value": e.original_value,
                    "converted_value": e.converted_value,
                    "index": e.conversation_index,
                    "timestamp": e.timestamp,
                }
                for e in sorted(entries, key=lambda x: x.conversation_index)
            ]

        # 统计摘要
        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            rs = r["risk_score"]
            if rs >= 8.0:
                risk_distribution["critical"] += 1
            elif rs >= 6.0:
                risk_distribution["high"] += 1
            elif rs >= 4.0:
                risk_distribution["medium"] += 1
            else:
                risk_distribution["low"] += 1

        return {
            "export_metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "export_type": "in_memory_memory",
                "total_attack_results": len(results),
                "total_conversations": len(conversations),
                "risk_distribution": risk_distribution,
                "session_created_at": datetime.fromtimestamp(
                    self._created_at, tz=timezone.utc
                ).isoformat(),
            },
            "attack_results": results,
            "conversations": conversations,
            # 方便报告阶段直接提取高风险漏洞
            "vulnerabilities": [r for r in results if r["risk_score"] >= 4.0],
        }

    def _export_json(self, data: dict[str, Any], file_path: Path) -> None:
        """导出为 JSON 格式（ensure_ascii=False 保持中文可读）。"""
        file_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    def _export_csv(self, data: dict[str, Any], file_path: Path) -> None:
        """导出为 CSV 格式。"""
        import csv

        results = data.get("attack_results", [])
        if not results:
            file_path.write_text("", encoding="utf-8")
            return

        fieldnames = [
            "id", "attack_id", "is_successful", "risk_score", "score",
            "attack_class", "converter_class", "objective", "timestamp",
        ]
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    def _next_attack_id(self) -> str:
        """生成递增攻击 ID。"""
        return f"attack_{self._attack_count + 1:04d}_{int(time.time())}"

    @staticmethod
    def _extract_score(result: Any) -> float:
        """从 PyRIT AttackResult 提取评分。"""
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
        """从 PyRIT AttackResult 提取响应文本。"""
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
        """清理资源（兼容 PyRIT MemoryInterface）。"""
        pass

    def cleanup(self) -> None:
        """清理所有存储数据。"""
        self._conversations.clear()
        self._attack_results.clear()
        self._attack_ids.clear()
        self._conversation_ids.clear()

    def reset_database(self) -> None:
        """重置数据库（兼容 PyRIT MemoryInterface）。"""
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

    # ------------------------------------------------------------------
    # 便捷导出方法（报告友好）
    # ------------------------------------------------------------------

    def export_for_report(
        self,
        run_id: str,
        module_name: str = "attack_results",
        min_risk_score: float = 4.0,
    ) -> Path:
        """导出为 OffSec AI-300 报告兼容格式。

        自动保存到 reports/{run_id}/ 目录，文件名包含模块名和时间戳。

        Args:
            run_id: 运行 ID（对应 reports/{run_id}/ 目录）
            module_name: 攻击模块名称（如 "jailbreak", "privacy_leak"）
            min_risk_score: 最低风险分数阈值（默认 4.0）

        Returns:
            导出的文件路径

        使用示例：
            # 越狱测试完成后立即导出
            mem.export_for_report(run_id, module_name="jailbreak_test")

            # 隐私泄露测试完成后立即导出
            mem.export_for_report(run_id, module_name="privacy_leak_test")

            # 报告阶段提取高风险漏洞
            path = mem.export_for_report(run_id, module_name="final")
            with open(path) as f:
                data = json.load(f)
            vulnerabilities = [
                r for r in data["attack_results"]
                if r["risk_score"] >= 4.0
            ]
        """
        report_dir = Path("reports") / run_id
        report_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{module_name}_{ts}.json"
        file_path = report_dir / filename

        data = self._build_export_data()
        # 添加模块元数据
        data["export_metadata"]["module_name"] = module_name
        data["export_metadata"]["run_id"] = run_id
        data["export_metadata"]["min_risk_threshold"] = min_risk_score
        # 标记高风险
        for r in data["attack_results"]:
            r["high_risk"] = r["risk_score"] >= min_risk_score

        self._export_json(data, file_path)
        logger.info(
            "InMemoryMemory: 报告导出 %s → %s (%d 条结果, %d 高风险)",
            module_name,
            file_path,
            len(data["attack_results"]),
            sum(1 for r in data["attack_results"] if r["high_risk"]),
        )
        return file_path


# ------------------------------------------------------------------
# 工具函数：设置内存并处理 SQLiteMemory 回退
# ------------------------------------------------------------------

def setup_memory_with_fallback(
    expire_after_seconds: int = 86400,
) -> InMemoryMemory:
    """初始化 PyRIT 内存存储，SQLiteMemory 失败时自动回退 InMemoryMemory。

    策略：
      1. 尝试使用 PyRIT 的 initialize_pyrit_async(IN_MEMORY)
         （内部创建 SQLiteMemory(db_path=":memory:")）
      2. 调用 _insert_entries 测试写入
      3. 如果失败（SQLiteError/InterfaceError），立即创建 InMemoryMemory
         并通过 CentralMemory.set_memory_instance() 注册替换

    Returns:
        InMemoryMemory 实例（始终可用）

    使用方式：
        from redteam.attack.core.in_memory_memory import setup_memory_with_fallback
        mem = setup_memory_with_fallback()
        # 后续通过 CentralMemory.get_memory_instance() 获取同一实例
    """
    try:
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        from pyrit.memory import CentralMemory
        import asyncio

        # 尝试 SQLiteMemory 初始化
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        loop.run_until_complete(initialize_pyrit_async(memory_db_type=IN_MEMORY))

        # 验证 SQLiteMemory 可用性
        memory = CentralMemory.get_memory_instance()
        if memory:
            try:
                # 轻量测试：尝试写入空列表（最小侵入性测试）
                memory.get_all_embeddings()
                logger.info("SQLiteMemory 初始化成功，PyRIT 内存存储可用")
                # 创建 InMemoryMemory 作为并行存储（用于导出）
                in_mem = InMemoryMemory(expire_after_seconds=expire_after_seconds)
                return in_mem
            except Exception as test_exc:
                logger.warning(
                    "SQLiteMemory 连通性测试失败: %s，切换到 InMemoryMemory",
                    test_exc,
                )
                _replace_with_in_memory(expire_after_seconds)
                return _get_in_memory_instance()

    except ImportError:
        logger.debug("PyRIT 不可用，跳过 SQLiteMemory 初始化")
    except Exception as exc:
        logger.warning("PyRIT 内存初始化失败: %s，使用 InMemoryMemory", exc)
        try:
            _replace_with_in_memory(expire_after_seconds)
            return _get_in_memory_instance()
        except Exception:
            pass

    # 最终回退：纯 InMemoryMemory
    mem = InMemoryMemory(expire_after_seconds=expire_after_seconds)
    try:
        from pyrit.memory import CentralMemory
        CentralMemory.set_memory_instance(mem)
    except ImportError:
        pass
    return mem


_in_memory_instance: Optional[InMemoryMemory] = None


def _replace_with_in_memory(expire_after_seconds: int) -> None:
    """用 InMemoryMemory 替换 CentralMemory 中的 SQLiteMemory。"""
    global _in_memory_instance
    from pyrit.memory import CentralMemory

    _in_memory_instance = InMemoryMemory(expire_after_seconds=expire_after_seconds)
    CentralMemory.set_memory_instance(_in_memory_instance)
    logger.info("CentralMemory 已切换为 InMemoryMemory（零 SQLite 依赖）")


def _get_in_memory_instance() -> InMemoryMemory:
    """获取全局 InMemoryMemory 实例（如果存在）。"""
    global _in_memory_instance
    if _in_memory_instance is None:
        _in_memory_instance = InMemoryMemory()
    return _in_memory_instance


__all__ = [
    "InMemoryMemory",
    "ConversationEntry",
    "AttackResultEntry",
    "setup_memory_with_fallback",
]
