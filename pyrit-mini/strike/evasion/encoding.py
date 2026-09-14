# -*- coding: utf-8 -*-
"""encoding — 编码混淆绕过生成器 (coverage 策略 encoding_evasion)。

真实实现：对原始 payload 施加多种编码混淆变换（hex / unicode / base64 / 字符拼接 /
URL 编码 / 双重编码），产出可绕过 WAF/过滤器签名的变体。纯函数，无网络。

Constitution compliance:
    - R-H3: 单一职责 — encoding evasion only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import base64
import logging
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_METHODS = ("hex", "unicode_escape", "base64", "char_concat", "url_encode", "double_url_encode")


def _hex_encode(text: str) -> str:
    return "0x" + text.encode("utf-8").hex()


def _unicode_escape(text: str) -> str:
    return text.encode("unicode_escape").decode("ascii")


def _char_concat(text: str) -> str:
    # 构造 'a'+'b'+... 形式的字符拼接，绕过简单关键字签名
    return "+".join(repr(c) for c in text)


def _url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _double_url_encode(text: str) -> str:
    return urllib.parse.quote(_url_encode(text), safe="")


def run_encoding_evasion(payload: str, *, methods: tuple[str, ...] | None = None) -> dict[str, Any]:
    """编码混淆绕过（coverage 策略 encoding_evasion）。

    对 payload 施加多种编码变换，产出绕过变体列表。

    Args:
        payload: 原始待混淆 payload
        methods: 启用的变换方法；缺省为全部内置方法

    Returns:
        {"original": str, "variants": [{"method": str, "value": str}, ...], "count": int}
    """
    chosen = methods or _DEFAULT_METHODS
    transforms = {
        "hex": _hex_encode,
        "unicode_escape": _unicode_escape,
        "base64": lambda t: base64.b64encode(t.encode("utf-8")).decode("ascii"),
        "char_concat": _char_concat,
        "url_encode": _url_encode,
        "double_url_encode": _double_url_encode,
    }
    variants: list[dict[str, str]] = []
    for name in chosen:
        fn = transforms.get(name)
        if fn is None:
            logger.warning("[EncodingEvasion] 未知方法 %s，跳过", name)
            continue
        try:
            variants.append({"method": name, "value": fn(payload)})
        except Exception as e:  # noqa: BLE001
            logger.debug("[EncodingEvasion] 方法 %s 失败: %s", name, e)
    return {"original": payload, "variants": variants, "count": len(variants)}
