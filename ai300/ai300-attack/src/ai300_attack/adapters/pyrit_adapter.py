# -*- coding: utf-8 -*-
"""
PyRIT Adapter
=============

通过 Python API 调用 PyRIT 执行攻击。

注意：PyRIT 是 optional dependency，本模块使用 lazy import。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from ai300_schemas import PyRITTargetConfig, UnifiedFinding

from ..adapters.base import AttackAdapter, AttackResult, AttackStrategy

logger = logging.getLogger(__name__)


class PyRITAdapter(AttackAdapter):
    """PyRIT 库适配器"""

    name = "pyrit"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._pyrit = None
        self._prompt_target_cls = None

    def _load_pyrit(self) -> Any:
        """延迟导入 PyRIT"""
        if self._pyrit is None:
            try:
                import pyrit

                self._pyrit = pyrit
            except ImportError as exc:
                raise RuntimeError(
                    "PyRIT is not installed. Install with: pip install 'ai300-attack[pyrit]'"
                ) from exc
        return self._pyrit

    def is_available(self) -> bool:
        try:
            self._load_pyrit()
            return True
        except Exception:
            return False

    def supported_strategies(self) -> List[str]:
        return [
            "jailbreak_direct",
            "api_prompt_injection",
            "web_ui_prompt_injection",
            "rag_context_manipulation",
            "agent_tool_misuse",
            "sensitive_data_exfil",
        ]

    def run(
        self,
        target: PyRITTargetConfig,
        strategy: AttackStrategy,
    ) -> AttackResult:
        """
        调用 PyRIT 执行指定策略。

        当前版本为 stub：完成目标构造和 lazy import 验证，
        实际 PromptTarget / Orchestrator 调用将在后续迭代中补全。
        """
        try:
            pyrit = self._load_pyrit()
        except RuntimeError as exc:
            return AttackResult(
                adapter=self.name,
                strategy=strategy.name,
                success=False,
                error=str(exc),
            )

        # 构造 PromptTarget
        try:
            prompt_target = self._build_prompt_target(target)
        except Exception as exc:
            return AttackResult(
                adapter=self.name,
                strategy=strategy.name,
                success=False,
                error=f"Failed to build PyRIT PromptTarget: {exc}",
            )

        logger.info(
            "PyRIT adapter stub: target=%s strategy=%s pyrit_version=%s",
            target.endpoint,
            strategy.name,
            getattr(pyrit, "__version__", "unknown"),
        )

        # TODO: 在后续迭代中接入 PromptSendingOrchestrator + SeedPrompt
        finding = UnifiedFinding(
            finding_id=f"pyrit-stub-{id(prompt_target)}",
            source_tool="pyrit",
            task_type="prompt_injection",
            target=target.endpoint,
            endpoint_url=target.endpoint,
            severity="info",
            confidence=0.0,
            title=f"PyRIT adapter stub for strategy '{strategy.name}'",
            description="PyRIT integration is installed but attack execution is not yet implemented in this MVP.",
        )

        return AttackResult(
            adapter=self.name,
            strategy=strategy.name,
            success=True,
            findings=[finding],
            raw_output={"prompt_target_type": target.target_type},
        )

    def _build_prompt_target(self, target: PyRITTargetConfig) -> Any:
        """根据配置构造 PyRIT PromptTarget"""
        from pyrit.prompt_target import (  # type: ignore[import]
            AzureOpenAITarget,
            HTTPTarget,
            OpenAITarget,
        )

        tt = target.target_type
        if tt == "AzureOpenAITarget" or "azure" in target.api_type.lower():
            return AzureOpenAITarget(
                deployment_name=target.model_name,
                endpoint=target.endpoint,
                api_key=target.api_key,
            )
        if tt == "OpenAITarget":
            return OpenAITarget(
                model_name=target.model_name,
                endpoint=target.endpoint,
                api_key=target.api_key,
            )
        # 默认 HTTPTarget
        return HTTPTarget(
            http_request=f"""
POST {target.endpoint} HTTP/1.1
Content-Type: application/json
Authorization: Bearer {target.api_key or ''}

{{"model": "{target.model_name}", "messages": [{{"role": "user", "content": "{{prompt}}"}}]}}
""",
        )
