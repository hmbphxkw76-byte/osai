# -*- coding: utf-8 -*-
"""
阶段 7：探测交互

在发现的聊天输入框中发送探测消息，触发 LLM API 调用，
并捕获响应容器与响应文本。对 SSE 流式响应做额外等待。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from src.interaction import send_chat_message
from src.utils import truncate_error, truncate_stage_error

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class ProbeInteractionStage(PipelineStage):
    """探测交互阶段"""

    name = "probe_interaction"
    description = "发送探测消息触发 LLM API"

    async def run(self, context: PipelineContext) -> StageResult:
        if context.target_type == "api":
            return StageResult(
                success=True,
                skipped=True,
                message="API 目标无需 Web 探测交互",
                data={},
            )

        page = context.page
        detection = context.detection

        if not page:
            return StageResult(success=False, message="页面未初始化")

        if not detection or not detection.get("input_selector"):
            return StageResult(
                success=True,
                skipped=True,
                message="未检测到聊天输入框，跳过探测发送",
                data={},
            )

        if self._spa_config(context, "enable_probe_send", True) is False:
            return StageResult(
                success=True,
                skipped=True,
                message="用户指定 --no-send，跳过探测发送",
                data={},
            )

        probe_text = self._spa_config(context, "send_probe_text", "你好，请介绍一下你自己。")
        post_send_wait_ms = self._spa_config(context, "post_send_wait_ms", 8000)
        type_delay_ms = self._spa_config(context, "type_delay_ms", 50)
        send_strategy_wait_ms = self._spa_config(context, "send_strategy_wait_ms", 2000)
        click_timeout_ms = self._spa_config(context, "click_timeout_ms", 3000)

        try:
            # 1. 发送主探测消息（连通性探测）
            result = await send_chat_message(
                page,
                input_selector=detection["input_selector"],
                send_selector=detection.get("send_selector"),
                response_selector=detection.get("response_selector"),
                text=probe_text,
                post_send_wait_ms=post_send_wait_ms,
                type_delay_ms=type_delay_ms,
                send_strategy_wait_ms=send_strategy_wait_ms,
                click_timeout_ms=click_timeout_ms,
            )

            # 2. 给 SSE / 流式渲染额外一点时间，然后捕获响应容器
            await page.wait_for_timeout(1500)
            response_containers = await self._capture_response_containers(page)
            result["response_containers"] = response_containers

            # 3. 将发送结果写入上下文，供 analysis 阶段使用
            context.send_result = result

            # 4. 记录探针响应，供后续 Profile 使用
            probe_responses = context.config.get("probe_responses", [])
            probe_responses.append({
                "purpose": "connectivity",
                "text": probe_text,
                "response": result.get("response_text", ""),
                "source": result.get("send_strategy", "unknown"),
                "send_method": result.get("send_strategy", "unknown"),
            })
            context.config["probe_responses"] = probe_responses

            # 5. 如果主探测成功，再发送一条模型自识别探测（可选，失败不影响主流程）
            await self._send_model_probe(context, page, detection)

            if result.get("success"):
                preview_limit = self._spa_config(context, "response_text_limit", 1000)
                return StageResult(
                    success=True,
                    message="探测消息发送成功",
                    data={
                        "response_preview": result.get("response_text", "")[:preview_limit],
                        "strategy": result.get("send_strategy"),
                        "response_containers": len(response_containers),
                    },
                )

            return StageResult(
                success=True,
                message=f"探测消息发送完成但可能未收到响应: {result.get('error', '')}",
                data={"result": result},
            )

        except Exception as exc:
            logger.exception("Probe send failed")
            return StageResult(
                success=False,
                message=f"探测发送失败: {truncate_stage_error(str(exc), context.config)}",
                data={},
            )

    async def _send_model_probe(
        self,
        context: PipelineContext,
        page: Any,
        detection: Dict[str, Any],
    ) -> None:
        """发送模型自识别探测，结果仅用于补充响应样本"""
        model_probe_text = self._spa_config(context, "model_probe_text", "What is your model name?")
        if not model_probe_text:
            return

        try:
            post_send_wait_ms = self._spa_config(context, "post_send_wait_ms", 8000)
            result = await send_chat_message(
                page,
                input_selector=detection["input_selector"],
                send_selector=detection.get("send_selector"),
                response_selector=detection.get("response_selector"),
                text=model_probe_text,
                post_send_wait_ms=post_send_wait_ms,
                type_delay_ms=50,
                send_strategy_wait_ms=2000,
                click_timeout_ms=3000,
            )

            await page.wait_for_timeout(1500)
            response_containers = await self._capture_response_containers(page)
            result["response_containers"] = response_containers

            # 合并到已有的 send_result 中，优先保留第一次的响应
            existing = context.send_result or {}
            existing_containers = existing.get("response_containers", [])
            existing_containers.extend(response_containers)
            existing["response_containers"] = existing_containers
            context.send_result = existing

            probe_responses = context.config.get("probe_responses", [])
            probe_responses.append({
                "purpose": "model_identify",
                "text": model_probe_text,
                "response": result.get("response_text", ""),
                "source": result.get("send_strategy", "unknown"),
                "send_method": result.get("send_strategy", "unknown"),
            })
            context.config["probe_responses"] = probe_responses

            logger.info("Model probe sent via %s", result.get("send_strategy", "unknown"))
        except Exception as exc:
            logger.debug("Model probe failed (non-critical): %s", exc)

    async def _capture_response_containers(self, page) -> List[Dict[str, Any]]:
        """从 DOM 捕获所有可能的 AI 响应容器"""
        try:
            containers = await page.evaluate(
                """() => {
                    const selectors = [
                        '[class*="answer"]', '[class*="response"]',
                        '[class*="message"]', '[class*="markdown"]',
                        '[class*="prose"]', '[class*="chat-content"]',
                        '[class*="ai-msg"]', '[class*="assistant"]',
                        '[class*="reply"]', '[class*="bot-msg"]'
                    ];
                    const results = [];
                    const seen = new Set();
                    for (const sel of selectors) {
                        const els = document.querySelectorAll(sel);
                        for (const el of els) {
                            const text = (el.innerText || '').trim();
                            if (text.length < 3) continue;
                            const key = (el.className || '') + '|' + text.substring(0, 80);
                            if (seen.has(key)) continue;
                            seen.add(key);
                            results.push({
                                selector: sel,
                                class: (el.className || '').substring(0, 80),
                                tag: el.tagName.toLowerCase(),
                                text: text.substring(0, 300),
                                textLength: text.length,
                            });
                        }
                    }
                    return results;
                }"""
            )
            return containers or []
        except Exception as exc:
            logger.warning("Failed to capture response containers: %s", exc)
            return []
