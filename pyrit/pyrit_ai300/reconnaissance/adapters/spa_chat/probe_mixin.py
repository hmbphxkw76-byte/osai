# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 探测消息 Mixin

提供 SPA 聊天侦察的探测消息发送和 LLM 信息提取能力（作为 SPAChatReconAdapter 的 Mixin）：
- 探测消息发送（多轮对话 + 网络流量捕获）
- LLM 端点信息提取（model/provider/auth_type/streaming）
- 模型家族识别（model 字段 → family 映射）
- 系统提示泄露检测
- 能力探测（function_calling / vision / streaming）

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .constants import (
    MODEL_FAMILY_PATTERNS,
    PROBE_MESSAGES,
)

logger = logging.getLogger(__name__)


class ProbeMixin:
    """探测消息 Mixin：为 SPAChatReconAdapter 提供探测和 LLM 信息提取能力。"""


    async def _send_probe_messages(
        self,
        page: Any,
        selectors: dict,
        probe_list: List[Dict[str, str]],
        errors: List[str],
        traffic: Optional["NetworkTrafficCapture"] = None,
    ) -> List[Dict[str, str]]:
        """
        发送探测消息并捕获响应

        策略：
        1. 优先从 DOM 获取响应文本（response_sel）
        2. DOM 失败时，从网络流量中提取 LLM API 响应内容（traffic 补充）
        3. 两者都失败时，返回空响应

        Args:
            page: Playwright 页面
            selectors: DOM 选择器配置
            probe_list: 探测消息列表
            errors: 错误收集列表
            traffic: 网络流量捕获器（可选，用于补充策略）

        Returns:
            探测响应列表，每项包含 text, purpose, response, source
        """
        input_sel = selectors.get(
            "input",
            "textarea, input[type='text'], [contenteditable='true']"
        )
        send_sel = selectors.get(
            "send_button",
            "button[type='submit'], .send-btn, [aria-label='Send']"
        )
        response_sel = selectors.get(
            "response",
            ".response, .ai-message, .assistant-message, .chat-message-ai"
        )

        # 响应选择器降级列表（当配置的选择器不匹配时依次尝试）
        response_fallback_sels = [
            response_sel,
            '[class*="answer"]', '[class*="response"]',
            '[class*="message"]', '[class*="markdown"]',
            '[class*="prose"]', '[class*="chat-content"]',
            '[class*="ai-msg"]', '[class*="assistant"]',
            '[class*="reply"]', '[class*="bot-msg"]',
            '[class*="model-output"]', '[class*="generated"]',
            '[role="log"]', '[aria-live="polite"]',
        ]

        wait_timeout = selectors.get("wait_timeout", 15000)

        results: List[Dict[str, str]] = []

        # 探测结果汇总
        probe_summary = {"sent": 0, "responded": 0, "no_response": 0, "failed": 0}

        # ── 登录页前置检测 ──
        # 如果当前页面被重定向到登录页，说明应用层认证无效
        # 此时继续发送探测消息毫无意义，应提前终止
        is_login_page = await self._detect_login_page(page)
        if is_login_page:
            print("\n  ⛔ 跳过探测 — 当前页面是登录页")
            print("  ──────────────────────────────────────────")
            print("  当前 URL: %s" % page.url[:100])
            print("  原因: Cookie/Header 认证在 HTTP 层有效，但应用层重定向到登录页")
            print("  说明: WAF/CDN 层 Cookie 通过了预检，但应用 Session/JWT 已过期或无效")
            print("  建议:")
            print("    1. 在浏览器中手动登录目标应用，从 F12 → Network 复制完整 Request Headers")
            hostname = urlparse(page.url).hostname or "target"
            print("    2. 保存到 config/targets/credentials/%s.txt" % hostname)
            print("    3. 重新运行侦察（系统将自动注入新的认证凭据）")
            print("  ──────────────────────────────────────────\n")
            logger.warning("Skipping probes: page redirected to login page (%s)", page.url)
            errors.append("Probe skipped: login page detected (auth invalid at application layer)")

            # ── 交互式询问：是否仍尝试发送探测消息 ──
            # 虽然当前仍在登录页，但用户可能希望强行尝试发送探测
            # （例如聊天入口点击后页面状态可能已变化）
            print("\n  ❓ 当前在登录页，是否仍尝试发送探测消息？")
            print("     y = 尝试发送探测（可能失败）")
            print("     n = 跳过探测（建议）")
            user_continue = await self._prompt_user_continue(
                "  请选择", default=False
            )
            if not user_continue:
                logger.info("User chose to skip probes on login page")
                return results
            else:
                print("  ▶️  尝试发送探测消息...\n")
                logger.info(
                    "User chose to attempt probes despite login page detection"
                )

        print("\n  📨 探测消息发送 (WAF 安全模式: 随机延迟)")
        print("  ──────────────────────────────────────────")

        for probe in probe_list:
            text = probe["text"]
            purpose = probe.get("purpose", "unknown")
            probe_summary["sent"] += 1

            # 用途中文映射
            purpose_cn = {
                "connectivity": "连通性测试",
                "model_identify": "模型识别",
                "system_prompt_leak": "系统提示泄露",
                "capability_probe": "能力探测",
                "custom": "自定义",
            }.get(purpose, purpose)

            print("\n  ▸ [%s] 发送: %s" % (purpose_cn, text[:50]))
            logger.info("Sending probe [%s]: %s", purpose, text[:50])

            try:
                # 记录发送前的 LLM API 调用数量（用于后续定位新调用）
                llm_count_before = len(traffic.llm_api_calls) if traffic else 0

                # 等待输入框
                await page.wait_for_selector(input_sel, state="visible", timeout=wait_timeout)

                # 点击前模拟人类思考延迟
                await page.wait_for_timeout(self._waf_safe_delay_ms("pre_click"))

                # 清空并输入（WAF 安全打字速度）
                await page.click(input_sel)
                await page.fill(input_sel, "")
                typing_delay = self._waf_safe_typing_delay()
                await page.type(input_sel, text, delay=typing_delay)

                # 点击发送前模拟人类短暂停顿
                await page.wait_for_timeout(self._waf_safe_delay_ms("pre_click"))

                # 点击发送（三级降级策略）
                # 1. 优先点击配置的 send_button 选择器
                # 2. 找不到按钮 → 按 Enter 键发送（常见于无独立发送按钮的 SPA 聊天）
                # 3. Enter 失败 → 点击输入框的可点击父容器（cursor:pointer）
                message_sent = False
                send_method = ""

                # 策略 1：点击 send_button
                if send_sel:
                    try:
                        await page.wait_for_selector(send_sel, state="visible", timeout=5000)
                        await page.click(send_sel)
                        message_sent = True
                        send_method = "button"
                        logger.info("Message sent via send_button click")
                    except Exception as btn_err:
                        logger.debug(
                            "send_button not found or click failed (%s), trying Enter key",
                            str(btn_err)[:80],
                        )

                # 策略 2：按 Enter 键发送（Ctrl+Enter 或 Shift+Enter 部分应用要求）
                if not message_sent:
                    try:
                        # 先尝试普通 Enter
                        await page.press(input_sel, "Enter")
                        message_sent = True
                        send_method = "enter"
                        logger.info("Message sent via Enter key")
                    except Exception as enter_err:
                        logger.debug("Enter key press failed (%s), trying container click", str(enter_err)[:80])

                # 策略 3：点击输入框的可点击父容器
                if not message_sent:
                    try:
                        # 查找 cursor:pointer 的父容器（常见于无独立按钮的 SPA 聊天）
                        clicked_container = await page.evaluate("""(inputSel) => {
                            const input = document.querySelector(inputSel);
                            if (!input) return false;
                            let node = input;
                            for (let i = 0; i < 5 && node.parentElement; i++) {
                                node = node.parentElement;
                                const style = getComputedStyle(node);
                                if (style.cursor === 'pointer') {
                                    node.click();
                                    return true;
                                }
                            }
                            return false;
                        }""", input_sel)
                        if clicked_container:
                            message_sent = True
                            send_method = "container"
                            logger.info("Message sent via parent container click")
                    except Exception as container_err:
                        logger.debug("Container click failed: %s", str(container_err)[:80])

                if not message_sent:
                    logger.warning("Failed to send message via any method (button/enter/container)")
                    print("  ⚠️  消息发送失败（按钮/回车/容器点击均失败）")

                # 等待响应（WAF 安全随机延迟）
                response_wait_ms = self._waf_safe_delay_ms("response_wait")
                await page.wait_for_timeout(response_wait_ms)

                # ── 策略 1：从 DOM 获取响应文本（多选择器降级） ──
                response_text = ""
                response_source = ""

                # 先尝试配置的选择器
                try:
                    # 等待响应元素出现（缩短超时以快速降级）
                    await page.wait_for_selector(response_sel, state="visible", timeout=min(wait_timeout, 8000))
                    # 额外等待确保响应完整
                    await page.wait_for_timeout(self._waf_safe_delay_ms("post_click"))

                    # 获取最后一个响应元素（可能是多轮对话）
                    response_elements = await page.query_selector_all(response_sel)
                    if response_elements:
                        response_text = await response_elements[-1].inner_text()
                    else:
                        response_text = await page.inner_text(response_sel)

                    if response_text.strip():
                        response_source = "dom"
                except Exception as dom_err:
                    logger.debug("DOM response extraction failed with primary selector: %s", str(dom_err))

                # 配置选择器失败，依次尝试降级选择器
                if not response_text.strip():
                    for fb_sel in response_fallback_sels:
                        if fb_sel == response_sel:
                            continue
                        try:
                            elements = await page.query_selector_all(fb_sel)
                            if elements:
                                # 获取最后一个元素的文本（最新的回复）
                                text = await elements[-1].inner_text()
                                if text and text.strip() and len(text.strip()) > 5:
                                    response_text = text
                                    response_source = "dom_fallback"
                                    logger.info("Response found via fallback selector: %s", fb_sel)
                                    break
                        except Exception:
                            continue

                # ── 策略 2：DOM 失败时，从网络流量提取 ──
                if not response_text.strip() and traffic:
                    # 等待网络响应完成（WAF 安全随机延迟）
                    await page.wait_for_timeout(self._waf_safe_delay_ms("post_click"))

                    # 查找发送消息后新增的 LLM API 调用
                    new_llm_calls = traffic.llm_api_calls[llm_count_before:]
                    for call in reversed(new_llm_calls):
                        extracted = call.get("response_text_extracted", "")
                        if extracted and extracted.strip():
                            response_text = extracted
                            response_source = "network_traffic"
                            logger.info("Response extracted from network traffic (URL: %s)",
                                        call.get("url", "")[:60])
                            break

                    # 如果没有提取到文本，尝试从 response_body 解析
                    if not response_text.strip():
                        for call in reversed(new_llm_calls):
                            body = call.get("response_body", "")
                            if body and body.strip():
                                # 直接使用原始 body（可能包含有用信息）
                                response_text = body[:2000]
                                response_source = "network_raw"
                                logger.info("Raw response body captured from network (URL: %s)",
                                            call.get("url", "")[:60])
                                break

                results.append({
                    "purpose": purpose,
                    "text": text,
                    "response": response_text.strip() if response_text else "",
                    "source": response_source,
                    "send_method": send_method if message_sent else "failed",
                })

                # ── 输出回复状态 ──
                if response_text.strip():
                    probe_summary["responded"] += 1
                    source_label = {"dom": "DOM", "network_traffic": "网络流量", "network_raw": "网络原始"}.get(response_source, response_source)
                    print("  ✅ 有回复 (来源: %s, %d 字符)" % (source_label, len(response_text)))
                    # 显示回复内容前 100 字符
                    preview = response_text.strip()[:100]
                    if len(response_text.strip()) > 100:
                        preview += "..."
                    print("     📝 回复内容: %s" % preview)
                    logger.info("Probe response: %d chars (source: %s)",
                                len(response_text), response_source or "none")
                else:
                    probe_summary["no_response"] += 1
                    print("  ❌ 无回复")
                    if traffic:
                        total_new = len(traffic.llm_api_calls) - llm_count_before
                        if total_new == 0:
                            print("     ⚠️ 发送后未检测到 LLM API 调用")
                            print("     可能原因: 聊天窗口未打开 / 消息未发送成功 / 响应被拦截")
                        else:
                            print("     ℹ️ 检测到 %d 个 API 调用但无法提取回复文本" % total_new)
                    logger.warning("Probe '%s': no response captured", purpose)

                # 消息间隔（WAF 安全随机延迟，模拟人类阅读回复后思考）
                await page.wait_for_timeout(self._waf_safe_delay_ms("probe_interval"))

            except Exception as e:
                probe_summary["failed"] += 1
                error_brief = self._extract_playwright_error_brief(str(e))
                logger.warning("Probe '%s' failed: %s", purpose, error_brief)
                errors.append("Probe '%s' failed: %s" % (purpose, error_brief))
                results.append({
                    "purpose": purpose,
                    "text": text,
                    "response": "",
                    "source": "error",
                    "error": error_brief,
                })
                print("  ❌ 发送失败: %s" % error_brief)

        # 探测汇总
        print("\n  ──────────────────────────────────────────")
        print("  📊 探测汇总: 发送 %d | 有回复 %d | 无回复 %d | 失败 %d" % (
            probe_summary["sent"], probe_summary["responded"],
            probe_summary["no_response"], probe_summary["failed"]
        ))
        if probe_summary["responded"] == 0:
            print("  ⚠️ 所有探测消息均无回复，请检查:")
            print("     1. 聊天入口是否正确点击（查看上方选择器探测报告）")
            print("     2. 输入框/发送按钮选择器是否匹配（配置 selectors.input / selectors.send_button）")
            print("     3. 认证是否有效（当前页面是否已重定向到登录页）")
        print()

        return results

    async def _scan_response_containers(self, page: Any) -> List[Dict[str, Any]]:
        """
        扫描页面中的 AI 响应容器，提取选择器和内容

        在探测消息发送后调用，用于发现实际的响应容器选择器。
        覆盖多种常见命名模式（answer/response/message/markdown 等）。

        Args:
            page: Playwright 页面

        Returns:
            [{selector, class, text, tag}, ...] 按文本长度降序排列
        """
        response_info = await page.evaluate("""() => {
            const selectors = [
                '[class*="answer"]', '[class*="response"]',
                '[class*="message"]', '[class*="markdown"]',
                '[class*="prose"]', '[class*="chat-content"]',
                '[class*="ai-msg"]', '[class*="assistant"]',
                '[class*="reply"]', '[class*="bot-msg"]',
                '[class*="model-output"]', '[class*="generated"]',
                '[role="log"]', '[aria-live="polite"]',
            ];
            const results = [];
            for (const sel of selectors) {
                const els = document.querySelectorAll(sel);
                for (const el of els) {
                    const text = (el.innerText || '').trim();
                    if (text.length > 10) {
                        results.push({
                            selector: sel,
                            class: (typeof el.className === 'string' ? el.className : '').substring(0, 100),
                            tag: el.tagName.toLowerCase(),
                            text: text.substring(0, 500),
                            textLength: text.length,
                        });
                    }
                }
            }
            results.sort((a, b) => b.textLength - a.textLength);
            return results.slice(0, 10);
        }""")
        return response_info

    # ── 信息提取方法 ──

    def _extract_llm_info(
        self,
        endpoint: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """从 LLM API 端点信息中提取有价值数据"""
        info: Dict[str, Any] = {}

        # 模型名称
        model_name = endpoint.get("model_extracted")
        if model_name:
            info["model_name_from_traffic"] = model_name
            findings.append({
                "category": "model_identified",
                "severity": "low",
                "description": f"Backend LLM model identified: {model_name}",
                "evidence": f"model field in request body: {model_name}",
                "owasp_mapping": "LLM02",
                "confidence": 0.9,
            })

        # 模型参数
        model_params = endpoint.get("model_parameters")
        if model_params:
            info["model_parameters"] = model_params
            param_str = ", ".join(f"{k}={v}" for k, v in model_params.items())
            findings.append({
                "category": "model_parameters_captured",
                "severity": "low",
                "description": f"Model parameters captured: {param_str}",
                "evidence": param_str,
                "owasp_mapping": "LLM02",
                "confidence": 0.9,
            })

        # 提供商
        provider = endpoint.get("provider_inferred")
        if provider:
            info["provider_inferred"] = provider

        # 系统提示
        system_prompt = endpoint.get("system_prompt_extracted")
        if system_prompt:
            info["system_prompt"] = system_prompt
            findings.append({
                "category": "system_prompt_captured",
                "severity": "high",
                "description": "System prompt captured from request body",
                "evidence": system_prompt[:200],
                "owasp_mapping": "LLM07",
                "confidence": 0.95,
            })

        # API 端点 finding
        findings.append({
            "category": "llm_api_endpoint_detected",
            "severity": "medium",
            "description": f"LLM API endpoint detected: {endpoint.get('path', '')}",
            "evidence": f"URL: {endpoint.get('url', '')}, Method: {endpoint.get('method', '')}, Streaming: {endpoint.get('is_streaming', False)}",
            "owasp_mapping": "LLM01",
            "confidence": 0.9,
        })

        # 流式响应
        if endpoint.get("is_streaming"):
            findings.append({
                "category": "streaming_response",
                "severity": "low",
                "description": "LLM API uses streaming (Server-Sent Events)",
                "evidence": "Response content-type: text/event-stream",
                "owasp_mapping": "",
                "confidence": 0.9,
            })

        return info

    def _extract_model_from_responses(self, probe_responses: List[Dict[str, str]]) -> Optional[str]:
        """从探测响应中提取模型名称"""
        # 模型名称正则模式
        model_patterns = [
            r'(?:model[:\s]+)([A-Za-z0-9\-_.]+)',
            r'(?:我是|I\s+am|I\'m)\s+(?:一个\s*)?(?:基于|based\s+on)\s+([A-Za-z0-9\-_.]+)',
            r'(GPT[-\s]?\d(?:\.\d)?)',
            r'(Claude[-\s]?\d(?:\.\d)?)',
            r'(Qwen[-\s]?\d(?:\.\d)?)',
            r'(GLM[-\s]?\d(?:\.\d)?)',
            r'(文心一言|ERNIE|文心)',
            r'(通义千问|Qwen)',
            r'(星火|Spark)',
            r'(混元|Hunyuan)',
            r'(Kimi|Moonshot)',
            r'(DeepSeek)',
            r'(Llama[-\s]?\d)',
            r'(Mistral)',
            r'(Gemini)',
        ]

        for resp in probe_responses:
            if resp.get("purpose") in ("model_identify", "capability_probe"):
                text = resp.get("response", "")
                if not text:
                    continue
                for pattern in model_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        return match.group(1).strip()

        return None

    @staticmethod
    def _extract_model_family(model_name: str) -> str:
        """从模型名称提取家族"""
        name = model_name.lower()
        for pattern, family in MODEL_FAMILY_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                return family
        # 兜底
        return name.split("-")[0].split("_")[0].split(":")[0] if name else ""
