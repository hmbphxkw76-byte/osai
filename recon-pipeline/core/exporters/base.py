# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconExporter 抽象基类 + JSONExporter。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.models.recon_report import ReconReport


class ReconExporter(ABC):
    """侦察结果导出器抽象基类。"""

    @abstractmethod
    def export(self, report: ReconReport, *args: Any, **kwargs: Any) -> Any:
        ...


class JSONExporter(ReconExporter):
    """通用 JSON 导出器。"""

    def export(self, report: ReconReport, output_path: str | Path | None = None, **kwargs: Any) -> Path | dict[str, Any]:
        data = report.to_dict()
        if output_path is None:
            return data
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        import json

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return path
