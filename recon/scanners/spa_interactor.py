"""
SPA 交互模块 — 模拟用户在浏览器中的操作以触发真实 API 调用。

解决核心问题：仅加载页面（Phase 3）不会触发 AI Chat 的 POST/GET 请求，
必须模拟用户在对话框中输入消息并发送，才能捕获到真实的 AI API 端点。

支持多层反检测：
- 贝塞尔曲线鼠标移动（ghost-cursor 算法）
- 拟人化打字节奏（随机延迟 + 思考停顿）
- 随机滚动行为
- 随机动作间延迟
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()


@dataclass
class InteractionResult:
    """SPA 交互探测结果。"""
    interaction_performed: bool = False
    input_found: bool = False
    input_type: str = ""           # textarea / input / contenteditable
    send_clicked: bool = False
    response_received: bool = False
    response_snippet: str = ""
    captured_requests: int = 0
    new_endpoints_found: int = 0
    errors: list[str] = field(default_factory=list)
    trace_log: str = ""


class SpaInteractor:
    """SPA Chat 交互器 — 在 headed/headless 浏览器中模拟用户对话。

    检测并操作 Chat UI 常见组件：
    - textarea / input[type="text"] — 消息输入框
    - button[type="submit"] / 发送按钮 — 各种变体
    - contenteditable div — 富文本编辑区

    使用 BrowserManager 的 humanize 方法实现拟人操作，避免被反爬系统检测。
    """

    # ── Chat 输入选择器（按优先级） ──
    _INPUT_SELECTORS = [
        # textarea 中文/英文常见占位符
        'textarea[placeholder*="消息" i]',
        'textarea[placeholder*="message" i]',
        'textarea[placeholder*="chat" i]',
        'textarea[placeholder*="输入" i]',
        'textarea[placeholder*="input" i]',
        'textarea[placeholder*="ask" i]',
        'textarea[placeholder*="type" i]',
        'textarea[placeholder*="问题" i]',
        'textarea[placeholder*="question" i]',
        'textarea[placeholder*="提问" i]',
        'textarea[placeholder*="您的问题" i]',
        'textarea[placeholder*="说点什么" i]',
        'textarea[placeholder*="请输入" i]',
        'textarea[placeholder*="send a message" i]',
        'textarea[placeholder*="type a message" i]',
        'textarea[placeholder*="what can i help" i]',
        'textarea[placeholder*="start a conversation" i]',
        'textarea[placeholder*="tell me" i]',
        'textarea[placeholder*="how can i" i]',
        # 通用 textarea
        'textarea:not([hidden]):not([disabled])',
        # input 中文/英文占位符
        'input[type="text"][placeholder*="消息" i]',
        'input[type="text"][placeholder*="message" i]',
        'input[type="text"][placeholder*="chat" i]',
        'input[type="text"][placeholder*="输入" i]',
        'input[type="text"][placeholder*="ask" i]',
        'input[type="text"][placeholder*="问题" i]',
        'input[type="text"][placeholder*="提问" i]',
        'input[type="text"][placeholder*="您的问题" i]',
        'input[type="text"][placeholder*="请输入" i]',
        'input[type="text"]:not([hidden]):not([disabled])',
        # contenteditable
        'div[contenteditable="true"]:not([hidden])',
        '[role="textbox"]:not([hidden])',
    ]

    # ── 发送按钮选择器（按优先级） ──
    _SEND_BUTTON_SELECTORS = [
        'button[type="submit"]:not([hidden]):not([disabled])',
        'button[aria-label*="发送" i]',
        'button[aria-label*="send" i]',
        'button[title*="发送" i]',
        'button[title*="send" i]',
        'button:has(svg):not([hidden])',  # SVG 图标发送按钮常见
        # 常见 SVG 箭头/飞机图标按钮
        'button svg[class*="send"]',
        'button svg[class*="arrow"]',
        'button svg[class*="paper-plane"]',
        'button svg[class*="plane"]',
        '[class*="send-btn"]',
        '[class*="send-button"]',
        '[class*="submit-btn"]',
        # 具体 class/variant 匹配
        'button.send-btn',
        'button[class*="send"]',
        'button[class*="submit"]',
        'button[class*="arrow"]',
        # 兜底: 输入框旁边的最后一个 button
        'form button:last-of-type:not([hidden])',
        # 如果 Chat 组件在父容器内，找同级的最后一个 button
        '.chat-input-area button:last-of-type:not([hidden])',
        '[class*="chat-input"] button:last-of-type:not([hidden])',
    ]

    _TEST_MESSAGE = (
        "Hello! I'm testing the AI chat interface. "
        "Please respond with a brief greeting in JSON format: {\"greeting\": \"Hello!\"}"
    )
    _WAIT_AFTER_SEND = 4  # 等待 AI 回复的秒数
    _MAX_RESPONSE_POLLS = 8  # 4 秒内轮询 8 次

    def __init__(self, browser_manager):
        self._browser = browser_manager

    async def interact_with_chat(
        self,
        page,
        traffic_capture=None,
        target_url: str = "",
    ) -> InteractionResult:
        """在已加载的 SPA 页面上模拟一次对话交互。

        流程:
        1. 查找聊天输入框
        2. 键入测试消息
        3. 查找并点击发送按钮
        4. 等待 AI 回复
        5. 返回交互结果和捕获的请求数

        Args:
            page: Playwright Page 对象（已加载目标 URL）
            traffic_capture: TrafficCapture 实例（已启动捕获）
            target_url: 目标 URL（用于日志）

        Returns:
            InteractionResult
        """
        result = InteractionResult()
        t0 = time.monotonic()
        trace_lines = [f"[{time.strftime('%H:%M:%S')}] SPA 交互开始"]

        console.print()
        console.print("[bold magenta]💬 SPA Chat 交互探测[/bold magenta]")

        # ── Step 0: 模拟浏览行为（滚动、鼠标移动） ──
        await self._browser.random_delay(0.5, 1.5)
        await self._browser.human_scroll(page, distance=300)

        # ── Step 1: 查找输入框 ──
        input_elem = None
        input_found_by = ""
        for selector in self._INPUT_SELECTORS:
            try:
                input_elem = await page.query_selector(selector)
                if input_elem and await input_elem.is_visible():
                    input_found_by = selector
                    break
            except Exception:
                continue

        if not input_elem:
            msg = "未找到可用的 Chat 输入框"
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            result.errors.append(msg)
            console.print(f"  [yellow]⚠ {msg}[/yellow]")
            console.print(
                "  [dim]  提示: 目标可能使用了非标准选择器，"
                "请检查页面 HTML 结构[/dim]"
            )
            result.trace_log = "\n".join(trace_lines)
            return result

        result.input_found = True
        result.input_type = await input_elem.evaluate("el => el.tagName.toLowerCase()")
        console.print(
            f"  [green]✅ 找到输入框: <{result.input_type}> "
            f"[dim]({input_found_by})[/dim][/green]"
        )
        trace_lines.append(
            f"[{time.strftime('%H:%M:%S')}] 输入框: {result.input_type} ({input_found_by})"
        )

        # ── Step 2: 输入测试消息 ──
        try:
            # 聚焦并清空输入框
            await self._browser.human_click(page, input_elem)
            await self._browser.random_delay(0.3, 0.8)

            # contenteditable 用 evaluate，否则用 human_type
            is_contenteditable = result.input_type == "div" or await input_elem.evaluate(
                "el => el.getAttribute('contenteditable') === 'true'"
            )

            if is_contenteditable:
                await input_elem.evaluate(
                    "el => { el.textContent = ''; el.focus(); }"
                )
                await self._browser.human_type(page, self._TEST_MESSAGE)
            else:
                await input_elem.fill("")
                await self._browser.human_type(page, self._TEST_MESSAGE, field=input_elem)

            console.print(
                f"  [dim]  已输入测试消息 ({len(self._TEST_MESSAGE)} 字符)[/dim]"
            )
            trace_lines.append(
                f"[{time.strftime('%H:%M:%S')}] 已输入 {len(self._TEST_MESSAGE)} 字符测试消息"
            )
        except Exception as e:
            msg = f"输入消息失败: {e}"
            result.errors.append(msg)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            console.print(f"  [red]❌ {msg}[/red]")
            result.trace_log = "\n".join(trace_lines)
            return result

        # ── Step 3: 延迟后查找并点击发送按钮 ──
        await self._browser.random_delay(0.3, 1.0)

        send_btn = None
        send_found_by = ""
        for selector in self._SEND_BUTTON_SELECTORS:
            try:
                send_btn = await page.query_selector(selector)
                if send_btn and await send_btn.is_visible():
                    send_found_by = selector
                    break
            except Exception:
                continue

        if not send_btn:
            # 尝试按 Enter 发送
            msg = "未找到发送按钮，尝试按 Enter 发送"
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            console.print(f"  [dim]  ⚡ {msg}[/dim]")
            try:
                await self._browser.random_delay(0.1, 0.3)
                await page.keyboard.press("Enter")
                result.send_clicked = True
            except Exception as e:
                result.errors.append(f"Enter 发送失败: {e}")
        else:
            result.send_clicked = True
            console.print(
                f"  [green]✅ 找到发送按钮 "
                f"[dim]({send_found_by})[/dim][/green]"
            )
            trace_lines.append(
                f"[{time.strftime('%H:%M:%S')}] 发送按钮: {send_found_by}"
            )

            try:
                await self._browser.human_click(page, send_btn)
            except Exception:
                # 点击失败，尝试 Enter
                await page.keyboard.press("Enter")

        if not result.send_clicked:
            console.print(f"  [yellow]⚠ 未成功发送消息[/yellow]")
            result.trace_log = "\n".join(trace_lines)
            return result

        # ── Step 4: 等待 AI 回复 ──
        console.print(
            f"  [dim]⏳ 等待 AI 回复 (最多 {self._WAIT_AFTER_SEND}s)...[/dim]"
        )

        response_text = ""
        try:
            # 轮询检测页面上是否出现 AI 回复内容
            for i in range(self._MAX_RESPONSE_POLLS):
                await asyncio.sleep(0.5)

                # 检测是否有新消息出现（常见选择器）
                response_text = await page.evaluate("""
                    () => {
                        const selectors = [
                            '.message:last-child', '.chat-message:last-child',
                            '[role="log"] > *:last-child', '.conversation-item:last-child',
                            '.assistant-message:last-child', '.ai-message:last-child',
                            '.response:last-child', '.answer:last-child',
                            'div[class*="message"]:last-child',
                            'div[class*="response"]:last-child',
                            'div[class*="answer"]:last-child',
                            'div[class*="assistant"]:last-child',
                            'div[class*="ai"]:last-child',
                        ];
                        for (const sel of selectors) {
                            try {
                                const el = document.querySelector(sel);
                                if (el && el.textContent && el.textContent.trim().length > 10) {
                                    return el.textContent.trim().substring(0, 500);
                                }
                            } catch(e) {}
                        }
                        return '';
                    }
                """)
                if response_text:
                    break

                # 中间点检查 network idle
                if i == self._MAX_RESPONSE_POLLS // 2:
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass

        except Exception as e:
            trace_lines.append(
                f"[{time.strftime('%H:%M:%S')}] 等待回复警告: {e}"
            )

        if response_text:
            result.response_received = True
            result.response_snippet = response_text[:200]
            console.print(
                f"  [green]✅ 收到 AI 回复 "
                f"[dim]({len(response_text)} 字符)[/dim][/green]"
            )
            console.print(
                f"  [dim]  回复片段: {response_text[:100]}...[/dim]"
            )
            trace_lines.append(
                f"[{time.strftime('%H:%M:%S')}] 收到回复 ({len(response_text)} 字符)"
            )
        else:
            console.print(
                f"  [yellow]⚠ 未检测到 AI 回复文本 "
                f"(可能异步加载中或使用了非标准 DOM)[/yellow]"
            )
            trace_lines.append(
                f"[{time.strftime('%H:%M:%S')}] 未检测到回复文本"
            )

        result.interaction_performed = True
        result.trace_log = "\n".join(trace_lines)
        return result

    async def extract_chat_ui_info(self, page) -> dict:
        """提取 Chat UI 的结构信息（辅助调试）。

        Returns:
            {
                has_textarea: bool,
                has_input: bool,
                has_contenteditable: bool,
                input_placeholder: str,
                button_count: int,
                chat_container: str,
            }
        """
        info = await page.evaluate("""
            () => {
                const textarea = document.querySelector('textarea:not([hidden])');
                const input = document.querySelector('input[type="text"]:not([hidden])');
                const ce = document.querySelector('[contenteditable="true"]:not([hidden])');

                // 统计所有可见按钮
                const buttons = document.querySelectorAll(
                    'button:not([hidden]), [role="button"]:not([hidden])'
                );

                // 查找聊天容器
                const containers = [
                    '[role="log"]', '.chat-container', '.conversation',
                    '[class*="chat"]', '[class*="conversation"]',
                    '[class*="message-list"]', '.messages',
                ];
                let chatContainer = '';
                for (const sel of containers) {
                    const el = document.querySelector(sel);
                    if (el) { chatContainer = sel; break; }
                }

                return {
                    has_textarea: !!textarea,
                    has_input: !!input,
                    has_contenteditable: !!ce,
                    input_placeholder: (textarea || input || ce)?.placeholder || '',
                    button_count: buttons.length,
                    chat_container: chatContainer,
                };
            }
        """)
        return info
