# -*- coding: utf-8 -*-
"""
AI-300 Framework - Template Renderer
三级占位符渲染器

职责：
- Tier 1: {goal} / {objective} 占位符替换
- Tier 2: 14 种编码变体占位符渲染（base64/rot13/hex/zalgo 等）
- Tier 3: 用户自定义领域参数占位符渲染

从 AttackOrchestrator._extract_payload_text() 和
_render_encoding_placeholders() 拆分而来，遵循单一职责原则。
"""

from __future__ import annotations

import base64
import codecs
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class TemplateRenderer:
    """
    三级占位符渲染器

    支持三级占位符：
    - Tier 1: {goal} / {objective} → 攻击目标替换
    - Tier 2: {base64_goal} / {rot13_goal} 等 14 种编码变体
    - Tier 3: 用户自定义 {domain} / {task} 等领域参数

    使用方式：
        renderer = TemplateRenderer()
        text = renderer.render(payload, objective="steal password", placeholders={"domain": "evil.com"})
    """

    def render(
        self,
        payload: str,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        从载荷中提取文本并渲染所有占位符

        Args:
            payload: 载荷文本（字符串或字典格式的 payload 字段）
            objective: 用户指定的攻击目标（替换 {objective} 占位符）
            placeholders: 用户自定义占位符字典（如 {"domain": "evil.com", "task": "whoami"}）

        Returns:
            渲染后的载荷文本字符串
        """
        text = self._extract_text(payload)

        # 确定替换值
        if objective:
            replacement = objective
        else:
            # 未指定 objective，使用去除占位符后的载荷文本本身
            replacement = text.replace("{objective}", "").replace("{goal}", "").strip()
            replacement = replacement.rstrip("：: ")

        # Tier 1: 替换 {objective} / {goal} 占位符
        if "{objective}" in text or "{goal}" in text:
            text = text.replace("{objective}", replacement).replace("{goal}", replacement)

        # Tier 2: 编码变体占位符渲染
        text = self._render_encoding_placeholders(text, replacement)

        # Tier 3: 用户自定义占位符渲染（领域参数）
        if placeholders:
            for key, value in placeholders.items():
                placeholder = "{" + key + "}"
                if placeholder in text:
                    text = text.replace(placeholder, value)

        return text

    def _extract_text(self, payload) -> str:
        """从载荷中提取文本（兼容字符串和字典格式）"""
        if isinstance(payload, dict):
            return payload.get("payload", str(payload))
        return str(payload)

    def _render_encoding_placeholders(self, text: str, goal: str) -> str:
        """
        渲染编码变体占位符（14 种）

        将 goal 进行各种编码转换后替换对应占位符。
        如果 goal 为空，返回原始文本。
        """
        if not goal:
            return text

        # {base64_goal}
        if "{base64_goal}" in text:
            encoded = base64.b64encode(goal.encode()).decode()
            text = text.replace("{base64_goal}", encoded)

        # {base32_goal}
        if "{base32_goal}" in text:
            encoded = base64.b32encode(goal.encode()).decode()
            text = text.replace("{base32_goal}", encoded)

        # {ascii85_goal}
        if "{ascii85_goal}" in text:
            try:
                encoded = base64.a85encode(goal.encode()).decode()
            except Exception:
                encoded = base64.b85encode(goal.encode()).decode()
            text = text.replace("{ascii85_goal}", encoded)

        # {french_goal} — 模拟多语言翻译（标记前缀，实际翻译需调用翻译API）
        if "{french_goal}" in text:
            french_simulated = f"[FR] {goal}"
            text = text.replace("{french_goal}", french_simulated)

        # {bidi_override_goal} — Bidi 覆盖字符编码
        if "{bidi_override_goal}" in text:
            bidi_encoded = "\u202E" + goal + "\u202C"
            text = text.replace("{bidi_override_goal}", bidi_encoded)

        # {unicode_tag_goal} — Unicode 标签字符编码（U+E0000-U+E007F）
        if "{unicode_tag_goal}" in text:
            tag_chars = []
            for ch in goal:
                tag_chars.append(chr(0xE0000 + ord(ch) % 128))
            text = text.replace("{unicode_tag_goal}", "".join(tag_chars))

        # {zalgo_goal} — Zalgo 文字变形（添加组合变音符号）
        if "{zalgo_goal}" in text:
            zalgo_marks = [
                "\u0300", "\u0301", "\u0302", "\u0303", "\u0304", "\u0305",
                "\u0306", "\u0307", "\u0308", "\u0309", "\u030A", "\u030B",
                "\u030C", "\u030D", "\u030E", "\u030F", "\u0310", "\u0311",
            ]
            zalgo_text = []
            for i, ch in enumerate(goal):
                zalgo_text.append(ch)
                zalgo_text.append(zalgo_marks[i % len(zalgo_marks)])
                if i % 3 == 0:
                    zalgo_text.append(zalgo_marks[(i + 5) % len(zalgo_marks)])
            text = text.replace("{zalgo_goal}", "".join(zalgo_text))

        # {chain_encoded_goal} — 链式编码（base64 + reverse）
        if "{chain_encoded_goal}" in text:
            b64 = base64.b64encode(goal.encode()).decode()
            reversed_b64 = b64[::-1]
            text = text.replace("{chain_encoded_goal}", reversed_b64)

        # {ascii_tag_deep_goal} — 深层 ASCII 标签编码
        if "{ascii_tag_deep_goal}" in text:
            deep_encoded = "".join(f"\\u{ord(ch):04X}" for ch in goal)
            text = text.replace("{ascii_tag_deep_goal}", deep_encoded)

        # {hex_goal} — 十六进制编码
        if "{hex_goal}" in text:
            hex_encoded = goal.encode().hex()
            text = text.replace("{hex_goal}", hex_encoded)

        # {rot13_goal} — ROT13 编码
        if "{rot13_goal}" in text:
            rot13_encoded = codecs.encode(goal, "rot_13")
            text = text.replace("{rot13_goal}", rot13_encoded)

        # {sneaky_bits_goal} — 零宽字符隐写编码
        if "{sneaky_bits_goal}" in text:
            sneaky_chars = []
            for ch in goal:
                bits = format(ord(ch), "08b")
                for bit in bits:
                    sneaky_chars.append("\u200C" if bit == "1" else "\u200B")
            text = text.replace("{sneaky_bits_goal}", "".join(sneaky_chars))

        # {interlinear_ws_goal} — 行间空白编码（零宽字符 + 换行隐藏）
        if "{interlinear_ws_goal}" in text:
            interlinear_lines = []
            for ch in goal:
                bits = format(ord(ch), "08b")
                line = "".join("\u200C" if bit == "1" else "\u200B" for bit in bits)
                interlinear_lines.append(line)
            interlinear_encoded = "\n".join(interlinear_lines)
            text = text.replace("{interlinear_ws_goal}", interlinear_encoded)

        # {multi_tag_mix_goal} — 多标签混合编码（bidi + zero-width + tag 三层嵌套）
        if "{multi_tag_mix_goal}" in text:
            tag_chars = []
            for ch in goal:
                tag_chars.append(chr(0xE0000 + ord(ch) % 128))
                tag_chars.append("\u200B")
            multi_encoded = "\u202E" + "".join(tag_chars) + "\u202C"
            text = text.replace("{multi_tag_mix_goal}", multi_encoded)

        return text


# 模块级单例（便捷访问）
_renderer = TemplateRenderer()


def render_payload(
    payload: str,
    objective: Optional[str] = None,
    placeholders: Optional[Dict[str, str]] = None,
) -> str:
    """
    便捷函数：渲染载荷占位符

    Args:
        payload: 载荷文本（字符串或字典格式）
        objective: 用户指定的攻击目标
        placeholders: 用户自定义占位符字典

    Returns:
        渲染后的载荷文本
    """
    return _renderer.render(payload, objective=objective, placeholders=placeholders)
