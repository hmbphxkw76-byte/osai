# -*- coding: utf-8 -*-
"""
ART Adapter
===========

通过 Adversarial Robustness Toolbox（ART）对目标模型执行评估。

当前实现要点：
  - ART 是 optional dependency，使用 lazy import
  - 当前版本为 stub：验证 ART 是否可导入并返回占位发现
  - 后续迭代可接入 ART 的文本/分类器对抗样本能力
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from ai300_schemas import PyRITTargetConfig, UnifiedFinding

from ..adapters.base import EvalAdapter, EvalResult, EvalStrategy

logger = logging.getLogger(__name__)


class ARTAdapter(EvalAdapter):
    """ART 评估适配器（MVP stub）"""

    # 适配器标识名
    name = "art"

    def __init__(self, config: Dict[str, Any]):
        """接收配置，初始化缓存字段"""
        super().__init__(config)
        # _art 用于缓存 lazy import 后的模块对象
        self._art = None

    def _load_art(self) -> Any:
        """延迟导入 ART，未安装时给出明确提示"""
        if self._art is None:
            try:
                import art

                self._art = art
            except ImportError as exc:
                raise RuntimeError(
                    "ART is not installed. "
                    "Install with: pip install 'ai300-eval-kit[art]'"
                ) from exc
        return self._art

    def is_available(self) -> bool:
        """通过尝试导入判断 ART 是否可用"""
        try:
            self._load_art()
            return True
        except Exception:
            return False

    def supported_strategies(self) -> List[str]:
        """声明本适配器支持的评估策略"""
        return [
            "robustness",
            "harmfulness",
            "bias_stereotypes",
            "sensitive_info_disclosure",
        ]

    def run(
        self,
        target: PyRITTargetConfig,
        strategy: EvalStrategy,
    ) -> EvalResult:
        """
        调用 ART 执行指定评估策略。

        Args:
            target: PyRIT target 配置
            strategy: 评估策略
        """
        # 第一步：确认 ART 已安装
        try:
            art = self._load_art()
        except RuntimeError as exc:
            return EvalResult(
                adapter=self.name,
                strategy=strategy.name,
                success=False,
                error=str(exc),
            )

        logger.info(
            "ART adapter stub: target=%s strategy=%s art_version=%s",
            target.endpoint,
            strategy.name,
            getattr(art, "__version__", "unknown"),
        )

        # MVP 阶段返回占位发现，避免在未实现完整攻击时误报风险
        finding = UnifiedFinding(
            finding_id=f"art-stub-{id(target)}",
            source_tool="art",
            task_type="ai_gauntlet",
            target=target.endpoint,
            endpoint_url=target.endpoint,
            severity="info",
            confidence=0.0,
            title=f"ART adapter stub for strategy '{strategy.name}'",
            description="ART integration is installed but evaluation execution is not yet implemented in this MVP.",
            ai_payload_class=strategy.name,
            raw={"strategy": strategy.name, "adapter": self.name},
        )

        return EvalResult(
            adapter=self.name,
            strategy=strategy.name,
            success=True,
            findings=[finding],
            raw_output={"art_version": getattr(art, "__version__", "unknown")},
        )
