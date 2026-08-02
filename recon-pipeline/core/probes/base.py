# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconProbe 抽象基类 — 统一探针接口。"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class ReconProbe(ABC):
    """侦察探针抽象基类。"""

    @abstractmethod
    async def probe(self, session: ReconSession) -> dict[str, Any]:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return True
