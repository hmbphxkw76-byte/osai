"""InMemoryMemory 导出功能 Mixin。

将 export_conversations + export_for_report 方法从 InMemoryMemory 中提取，
保持核心存储类的职责单一（<500 行）。
"""

from __future__ import annotations

import csv
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)


class MemoryExportMixin:
    """导出方法 Mixin，需与 InMemoryMemory 组合使用。

    依赖注入要求：
      - self._attack_results: dict[str, AttackResultEntry]
      - self._conversations: dict[str, list[ConversationEntry]]
      - self._conversation_ids: list[str]
      - self._export_count: int
      - self._created_at: float
      - self._enforce_expiry(): 过期数据清理
      - self.get_attack_results(): 获取所有攻击结果（dict 格式）
    """

    # 由 InMemoryMemory 提供，此处仅声明类型提示
    _attack_results: dict[str, Any]
    _conversations: dict[str, Any]
    _conversation_ids: list[str]
    _export_count: int
    _created_at: float

    def _enforce_expiry(self) -> None: ...  # pragma: no cover
    def get_attack_results(self) -> list[dict[str, Any]]: ...  # pragma: no cover

    # ------------------------------------------------------------------
    # export_conversations — 核心导出方法
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

        签名与 MemoryInterface.export_conversations 完全兼容。

        Args:
            attack_id: 按攻击 ID 过滤
            conversation_id: 按对话 ID 过滤
            file_path: 导出文件路径（默认自动生成到 results/ 目录）
            export_type: 导出格式 ("json" | "csv")

        Returns:
            导出文件的 Path 对象
        """
        export_data = self._build_export_data(
            attack_id=str(attack_id) if attack_id else None,
            conversation_id=str(conversation_id) if conversation_id else None,
        )

        if file_path is None:
            auto_dir = Path("results") / "memory_exports"
            auto_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._export_count += 1
            file_path = auto_dir / f"attack_results_{ts}_{self._export_count:04d}.{export_type}"

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

        results = self.get_attack_results()
        if attack_id:
            results = [r for r in results if r["attack_id"] == attack_id]
        if conversation_id:
            results = [r for r in results if r["conversation_id"] == conversation_id]

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
    # 便捷导出方法（报告友好）
    # ------------------------------------------------------------------

    def export_for_report(
        self,
        run_id: str,
        module_name: str = "attack_results",
        min_risk_score: float = 4.0,
    ) -> Path:
        """导出为 OffSec AI-300 报告兼容格式。

        自动保存到 results/{run_id}/ 目录，文件名包含模块名和时间戳。

        Args:
            run_id: 运行 ID（对应 results/{run_id}/ 目录）
            module_name: 攻击模块名称（如 "jailbreak", "privacy_leak"）
            min_risk_score: 最低风险分数阈值（默认 4.0）

        Returns:
            导出的文件路径
        """
        report_dir = Path("results") / run_id
        report_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{module_name}_{ts}.json"
        file_path = report_dir / filename

        data = self._build_export_data()
        data["export_metadata"]["module_name"] = module_name
        data["export_metadata"]["run_id"] = run_id
        data["export_metadata"]["min_risk_threshold"] = min_risk_score
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


__all__ = [
    "MemoryExportMixin",
]
