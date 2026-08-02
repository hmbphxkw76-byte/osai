"""登录后模型侦察 — 自动发现目标推理 endpoint 与模型名

登录成功后，目标页面已携带认证态（同源 Cookie）。本模块利用已登录的
Playwright page 上下文，按以下优先级自动发现推理端点与模型名：

1. OpenAI 标准 /models 端点（标准路径探测）
2. SPA 页面注入探测：JS 全局变量 + fetch/XHR 拦截（私有前缀、非标准路径）
3. 兜底：通用占位模型名

支持场景：
  - OpenAI 兼容 API（/v1/models）
  - 单体 SPA AI 聊天面板（如 student.syxy.ouchn.cn 右下角 AI 学习助手）
  - 其他 LLM Web 应用（/chat、/assistant、/ai、/llm 等私有前缀）
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# 页面 JS 全局变量名 — 开发者常把 API base URL 写在 window 上
_SPA_BASE_HINTS = [
    "AI_BASE_URL", "OPENAI_BASE_URL", "API_BASE",
    "VUE_APP_API_BASE", "REACT_APP_API_BASE", "NEXT_PUBLIC_API_BASE",
    "VITE_API_BASE", "__NEXT_DATA__", "CONFIG", "APP_CONFIG",
]

# 请求 URL 关键词 — 拦截包含这些词的 fetch/XHR，用于推断真实 API 端点
_CHAT_URL_KEYWORDS = [
    "/chat", "/assistant", "/ai/", "/openai/", "/llm",
    "/completions", "/messages", "/conversation", "/generate",
    "/inference", "/predict", "/v1/chat", "/api/v1/chat",
]


def _derive_api_base(target_url: str) -> list[str]:
    """从目标 URL 推导候选 API base

    常见形态：
      https://student.syxy.ouchn.cn/            -> .../openai/v1 或 .../api/openai/v1
      https://student.syxy.ouchn.cn/chat        -> 去尾路径后加 /openai/v1
    """
    parsed = urlparse(target_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return [
        root + "/openai/v1",
        root + "/api/openai/v1",
        root + "/v1",
        root + "/api/v1",
        root + "/api",
        target_url.rstrip("/") + "/openai/v1",
    ]


# ------------------------------------------------------------------
# SPA 端点嗅探（私有前缀 / 非标准路径）
# ------------------------------------------------------------------

def _sniff_spa_endpoint(page: Any) -> dict[str, str] | None:
    """从 SPA 页面抓取真实 API endpoint（四阶段探测）

    阶段 1 — JS 全局变量：扫描 window 上的已知变量名，找到 base URL
    阶段 2 — 打开 AI 聊天面板（若页面有浮动按钮）
    阶段 3 — 主动发测试消息：找到输入框 → 填入消息 → 点击发送 → 拦截请求
    阶段 4 — 被动 fetch/XHR 拦截：刷新页面，监听懒加载请求

    :returns: {"endpoint": str, "model": str} 或 None
    """
    # 阶段 1：JS 全局变量
    result = _sniff_from_global_vars(page)
    if result:
        return result

    # 阶段 2：打开 AI 聊天面板
    opened = _open_chat_panel(page)

    # 阶段 3：主动发测试消息 + 请求拦截（最可靠 — 对后端代理架构也有效）
    if opened:
        result = _probe_by_sending_message(page)
        if result:
            return result

    # 阶段 4：被动拦截（刷新页面触发懒加载请求）
    return _sniff_from_intercepted_requests(page)


# ------------------------------------------------------------------
# 聊天面板交互 — 打开面板 + 发测试消息 + 拦截请求
# ------------------------------------------------------------------

# 聊天输入框选择器（按优先级：先精确后模糊）
_CHAT_INPUT_SELECTORS = [
    # contenteditable div（现代 SPA 聊天最常见）
    "div[contenteditable=true][class*=chat]",
    "div[contenteditable=true][class*=message]",
    "div[contenteditable=true][class*=input]",
    "div[contenteditable=true][class*=send]",
    "div[contenteditable=true][id*=chat]",
    "div[contenteditable=true][id*=message]",
    "div[contenteditable=true][id*=input]",
    "div[contenteditable=true][class*=editor]",
    # 通用 contenteditable（最后兜底）
    "div[contenteditable=true]",
    # 标准输入框
    "textarea[class*=chat]", "textarea[class*=message]", "textarea[class*=input]",
    "textarea[id*=chat]", "textarea[id*=message]", "textarea[id*=input]",
    "textarea[placeholder*=输入]", "textarea[placeholder*=消息]", "textarea[placeholder*=提问]",
    "textarea[placeholder*=message]", "textarea[placeholder*=chat]", "textarea[placeholder*=ask]",
    "textarea",
    "input[type=text][class*=chat]", "input[type=text][class*=message]",
    "input[type=text][placeholder*=输入]", "input[type=text][placeholder*=消息]",
    "input[type=text][id*=chat]", "input[type=text][id*=message]",
]

# 发送按钮选择器
_SEND_BUTTON_SELECTORS = [
    "button[class*=send]", "button[id*=send]",
    "button[class*=submit]", "button[id*=submit]",
    "button[aria-label*=send]", "button[aria-label*=发送]",
    "button[title*=send]", "button[title*=发送]",
    "button:has([class*=icon-send])", "button:has([class*=icon-submit])",
    "button:has-text('发送')", "button:has-text('Send')",
    "button:has-text('提交')", "button:has-text('Submit')",
    "[class*=send-btn]", "[class*=send-button]",
    "svg[class*=send]",  # icon-only 按钮常见
]


def _open_chat_panel(page: Any) -> bool:
    """打开 AI 聊天面板，返回是否成功打开

    比 _trigger_chat_panel 更完善：点击后等待面板动画完成，
    并验证输入框是否出现。
    """
    # 先检查面板是否已打开（输入框已可见）
    if _find_chat_input(page, silent=True) is not None:
        logger.debug("聊天面板已打开，跳过触发")
        return True

    # 尝试点击入口按钮
    chat_triggers = [
        "button[class*=ai]", "button[class*=chat]", "button[class*=assistant]",
        "div[class*=ai-assistant]", "div[class*=chat-float]",
        "[id*=ai-chat]", "[id*=chat-btn]", "[id*=assistant]",
        "div[style*=fixed][class*=chat]", "div[style*=fixed][class*=ai]",
        "button:has([class*=icon-ai])", "button:has([class*=icon-chat])",
        "button:has-text('AI')", "button:has-text('助手')",
        "button:has-text('智能')", "div:has-text('AI助手')",
        # 更多通用入口
        "[class*=chat-entry]", "[class*=ai-entry]",
        "img[alt*=AI]", "img[alt*=助手]", "img[alt*=chat]",
    ]
    for sel in chat_triggers:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                el.click()
                logger.debug("点击聊天入口: %s", sel)
                # 条件等待输入框出现（最多 3s），替代盲目 sleep 2s
                try:
                    page.wait_for_selector(
                        ",".join(_CHAT_INPUT_SELECTORS[:3]),
                        state="visible", timeout=3000,
                    )
                    logger.info("聊天面板已打开 (触发选择器: %s)", sel)
                    return True
                except Exception:
                    continue
        except Exception:
            continue

    logger.debug("未找到可触发的聊天面板入口")
    return False


def _find_chat_input(page: Any, silent: bool = False) -> Any:
    """在页面中查找聊天输入框

    支持 input、textarea、contenteditable div 三种形态。
    对 contenteditable 的 div，返回 Playwright ElementHandle（可 focus + keyboard.type）。

    :param silent: True 时不打 warning 日志
    :returns: Playwright ElementHandle 或 None
    """
    for sel in _CHAT_INPUT_SELECTORS:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                if not silent:
                    logger.debug("找到聊天输入框: %s", sel)
                return el
        except Exception:
            continue
    if not silent:
        logger.warning("未找到聊天输入框（尝试了 %d 个选择器）", len(_CHAT_INPUT_SELECTORS))
    return None


def _find_send_button(page: Any) -> Any:
    """在页面中查找发送按钮"""
    for sel in _SEND_BUTTON_SELECTORS:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                logger.debug("找到发送按钮: %s", sel)
                return el
        except Exception:
            continue
    logger.warning("未找到发送按钮（尝试了 %d 个选择器）", len(_SEND_BUTTON_SELECTORS))
    return None


def _probe_by_sending_message(page: Any) -> dict[str, str] | None:
    """主动发一条测试消息，同时拦截发出的请求以捕获 endpoint

    流程：
    1. 找到输入框 + 发送按钮
    2. 注册 request 监听器
    3. 填入测试消息 → 点击发送
    4. 等待响应 → 从拦截的请求中提取 endpoint/model

    这是最可靠的端点探测方式 — 即使目标是后端代理架构
    （前端不直连 AI API），也能抓到真实请求 URL。
    """
    input_el = _find_chat_input(page)
    if input_el is None:
        logger.debug("无法发送测试消息：未找到输入框")
        return None

    send_btn = _find_send_button(page)
    if send_btn is None:
        # 没有发送按钮时尝试 Enter 键
        logger.debug("未找到发送按钮，将尝试 Enter 键发送")

    # 注册请求拦截（在发送前）
    captured: list[dict[str, Any]] = []

    def _on_request(request: Any) -> None:
        url = request.url
        if any(kw in url for kw in _CHAT_URL_KEYWORDS):
            item: dict[str, Any] = {"url": url}
            try:
                post_data = request.post_data
                if post_data:
                    import json as _json
                    try:
                        body = _json.loads(post_data)
                        if isinstance(body, dict):
                            if body.get("model"):
                                item["model"] = body["model"]
                            if body.get("messages"):
                                item["has_messages"] = True
                    except Exception:
                        pass
            except Exception:
                pass
            captured.append(item)

    try:
        page.on("request", _on_request)

        # 填入测试消息
        test_msg = "Hello"
        try:
            input_el.click()
            page.wait_for_timeout(100)  # 减少等待
            input_el.fill("")
            page.keyboard.type(test_msg, delay=20)  # 加快输入
            logger.debug("已填入测试消息: %s", test_msg)
        except Exception:
            try:
                input_el.fill(test_msg)
                logger.debug("已填入测试消息 (fill): %s", test_msg)
            except Exception as exc:
                logger.debug("填入消息失败: %s", exc)
                return None

        page.wait_for_timeout(200)

        if send_btn:
            send_btn.click()
            logger.debug("已点击发送按钮")
        else:
            page.keyboard.press("Enter")
            logger.debug("已按 Enter 发送")

        # 等待请求发出 + 响应（3s 足够，原来 5s 过于保守）
        page.wait_for_timeout(3000)

    except Exception as exc:
        logger.debug("发送测试消息异常: %s", exc)
    finally:
        try:
            page.remove_listener("request", _on_request)
        except Exception:
            pass

    if not captured:
        logger.debug("发送消息后未拦截到聊天请求（可能是后端代理架构，请求走同源）")
        return None

    logger.info("发送消息拦截捕获 %d 条聊天请求", len(captured))
    for item in captured:
        logger.debug("  请求: %s", item.get("url", "")[:120])

    # 优先取有 model + messages 的请求
    for item in captured:
        if item.get("model") and item.get("has_messages"):
            result = _derive_from_url(item["url"], model=item["model"])
            result["method"] = "active_probe"
            logger.info("主动探测命中: endpoint=%s model=%s", result["endpoint"], result["model"])
            return result

    for item in captured:
        if item.get("model"):
            result = _derive_from_url(item["url"], model=item["model"])
            result["method"] = "active_probe"
            return result

    result = _derive_from_url(captured[0]["url"])
    result["method"] = "active_probe"
    return result


def _sniff_from_global_vars(page: Any) -> dict[str, str] | None:
    """扫描 window 上的已知变量名"""
    for var in _SPA_BASE_HINTS:
        try:
            val = page.evaluate(f"() => window.{var} || null")
            if val:
                if isinstance(val, str) and val.startswith("http"):
                    logger.info("SPA 全局变量命中: window.%s = %s", var, val)
                    return _derive_from_base(val)
                if isinstance(val, dict):
                    # __NEXT_DATA__ / CONFIG / APP_CONFIG 等嵌套对象
                    base = val.get("apiBase") or val.get("apiUrl") or \
                           val.get("baseUrl") or val.get("api_base")
                    if base and isinstance(base, str) and base.startswith("http"):
                        logger.info("SPA 全局变量命中: window.%s.apiBase = %s", var, base)
                        return _derive_from_base(base)
        except Exception:
            continue
    return None


def _sniff_from_intercepted_requests(page: Any) -> dict[str, str] | None:
    """拦截页面发出的 fetch/XHR，匹配聊天相关关键词

    在已登录的 page 中注入监听器，捕获所有聊天相关请求的 URL 和请求体，
    从 URL 推导 API base，从请求体提取 model 名。
    """
    captured: list[dict[str, Any]] = []

    def _on_request(request: Any) -> None:
        url = request.url
        if any(kw in url for kw in _CHAT_URL_KEYWORDS):
            item: dict[str, Any] = {"url": url}
            try:
                post_data = request.post_data
                if post_data:
                    import json as _json
                    try:
                        body = _json.loads(post_data)
                        if isinstance(body, dict) and body.get("model"):
                            item["model"] = body["model"]
                        if isinstance(body, dict) and body.get("messages"):
                            item["has_messages"] = True
                    except Exception:
                        pass
            except Exception:
                pass
            captured.append(item)

    try:
        page.on("request", _on_request)
        try:
            page.reload(wait_until="load", timeout=10000)
        except Exception:
            logger.debug("页面 reload 超时，继续等待已有请求")
        page.wait_for_timeout(1500)
    except Exception as exc:
        logger.debug("请求拦截异常: %s", exc)
    finally:
        try:
            page.remove_listener("request", _on_request)
        except Exception:
            pass

    if not captured:
        logger.debug("请求拦截未捕获聊天相关请求")
        return None

    logger.info("请求拦截捕获 %d 条聊天请求", len(captured))
    for item in captured:
        logger.debug("  请求: %s", item.get("url", "")[:120])

    # 优先取有 model 的请求
    for item in captured:
        if item.get("model") and item.get("has_messages"):
            result = _derive_from_url(item["url"], model=item["model"])
            result["method"] = "spa_sniff"
            return result

    # 次优选：有 model 但无 messages
    for item in captured:
        if item.get("model"):
            result = _derive_from_url(item["url"], model=item["model"])
            result["method"] = "spa_sniff"
            return result

    # 末选：仅有 URL
    result = _derive_from_url(captured[0]["url"])
    result["method"] = "spa_sniff"
    return result


def _derive_from_url(url: str, model: str | None = None) -> dict[str, str]:
    """从捕获的请求 URL 推导 endpoint 与模型名

    例如：
      https://ai.syxy.ouchn.cn/api/v1/chat/completions
      → endpoint = https://ai.syxy.ouchn.cn/api/v1, model = 从请求体提取

    注意：endpoint 是 OpenAI 兼容的 base URL（不带 /chat/completions 后缀），
    garak 的 OpenAICompatible generator 会在 base 后自动拼接路径。
    """
    parsed = urlparse(url)
    path = parsed.path
    # 去除 /chat/completions、/completions、/messages 等后缀
    import re

    suffixes = [
        "/chat/completions", "/completions", "/messages",
        "/generate", "/inference", "/predict", "/conversation",
    ]
    for suffix in suffixes:
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break

    # 确保 base 不以 / 结尾（garak 会自动拼接）
    base = f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")
    m = model or "unknown-model"
    logger.info("URL 推导: endpoint=%s model=%s", base, m)
    return {"endpoint": base, "model": m}


def _derive_from_base(base: str) -> dict[str, str]:
    """从已知 base URL 推导 endpoint + model（model 待后续确认）"""
    base = base.rstrip("/")
    return {"endpoint": base, "model": "unknown-model"}


# ------------------------------------------------------------------
# 凭据嗅探（API key / Bearer token — 绕过 Cookie 直连 API）
# ------------------------------------------------------------------

# localStorage / sessionStorage 中可能存 token 的 key 名
_STORAGE_KEY_HINTS = [
    "ai_token", "openai_key", "api_key", "token", "auth_token",
    "access_token", "bearer_token", "chat_token", "ai_api_key",
    "llm_key", "model_key", "x-api-key", "apikey",
]

# 请求头中可能带 API key 的 header 名
_AUTH_HEADER_HINTS = [
    "authorization", "x-api-key", "x-api-token", "api-key",
    "x-auth-token", "x-access-token",
]

# JS bundle 中搜索 API key 的正则模式
_BUNDLE_KEY_PATTERNS = [
    r'sk-[A-Za-z0-9]{20,}',                    # OpenAI 格式
    r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',  # key 赋值
    r'openai[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
    r'bearer[_-]?token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
]


def _sniff_credentials(page: Any) -> dict[str, Any] | None:
    """四通道凭据嗅探（并行版）：四个通道并发探测，任一命中即早停

    探测前端是否泄露了可直接用于 API 调用的凭据（API key / Bearer token）。
    若成功拿到 key，后续 stage3 可绕过 Cookie 直连 API，彻底消除
    会话过期 / nones 假阴性问题。

    :returns: {
        "api_key": str,
        "source": "localStorage.ai_token" | "request_header.authorization" | "js_bundle",
        "method": "credential_sniff",
    } 或 None
    """
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        f_local = executor.submit(_sniff_from_storage, page, "localStorage", _STORAGE_KEY_HINTS)
        f_session = executor.submit(_sniff_from_storage, page, "sessionStorage", _STORAGE_KEY_HINTS)
        f_headers = executor.submit(_sniff_from_request_headers, page)
        f_bundle = executor.submit(_sniff_from_js_bundle, page)

        future_map = {
            f_local: "localStorage",
            f_session: "sessionStorage",
            f_headers: "request_headers",
            f_bundle: "js_bundle",
        }
        for future in concurrent.futures.as_completed(future_map, timeout=20):
            try:
                result = future.result(timeout=5)
                if result:
                    logger.debug("凭据嗅探命中: %s", future_map[future])
                    for f in future_map:
                        if f != future:
                            f.cancel()
                    return result
            except Exception:
                continue
        return None


def _sniff_from_storage(page: Any, storage: str, keys: list[str]) -> dict[str, Any] | None:
    """扫描 localStorage / sessionStorage 中的 token"""
    for key in keys:
        try:
            val = page.evaluate(f"() => {storage}.getItem('{key}') || null")
            if val and _looks_like_api_key(val):
                logger.info("凭据嗅探命中: %s.%s (长度=%d)", storage, key, len(val))
                return {
                    "api_key": val,
                    "source": f"{storage}.{key}",
                    "method": "credential_sniff",
                }
        except Exception:
            continue
    return None


def _sniff_from_request_headers(page: Any) -> dict[str, Any] | None:
    """拦截页面发出的请求，从请求头中抓 Authorization / x-api-key

    刷新页面并在 networkidle 后收集所有聊天相关请求的认证头。
    """
    captured_headers: list[dict[str, str]] = []

    def _on_request(request: Any) -> None:
        url = request.url
        if not any(kw in url for kw in _CHAT_URL_KEYWORDS):
            return
        headers = {}
        try:
            headers = dict(request.headers)
        except Exception:
            pass
        for h in _AUTH_HEADER_HINTS:
            # Playwright 的 headers 是大小写不敏感的 dict-like
            val = headers.get(h) or headers.get(h.title()) or headers.get(h.upper())
            if val and _looks_like_api_key(val):
                captured_headers.append({"header": h, "value": val})

    try:
        page.on("request", _on_request)
        page.wait_for_timeout(1500)  # 1.5s 足够捕获已发出的请求
    except Exception as exc:
        logger.debug("请求头拦截异常: %s", exc)
    finally:
        try:
            page.remove_listener("request", _on_request)
        except Exception:
            pass

    if captured_headers:
        item = captured_headers[0]
        logger.info("凭据嗅探命中: 请求头 %s (长度=%d)", item["header"], len(item["value"]))
        return {
            "api_key": item["value"],
            "source": f"request_header.{item['header']}",
            "method": "credential_sniff",
        }
    return None


def _sniff_from_js_bundle(page: Any) -> dict[str, Any] | None:
    """搜索页面已加载的所有 <script> 标签文本内容

    这是最慢的通道（需遍历所有内联 script 的 textContent），
    但能覆盖 bundle 内硬编码的 API key（开发同学常见错误）。
    """
    # 内联 script 和可访问的 external script 内容
    try:
        result = page.evaluate("""() => {
            const patterns = [
                [/sk-[A-Za-z0-9]{20,48}/g, 'openai'],
                [/api[_-]?key["']?\\s*[:=]\\s*["']([^"']{10,64})["']/gi, 'api_key'],
                [/bearer[_-]?token["']?\\s*[:=]\\s*["']([^"']{10,64})["']/gi, 'bearer'],
            ];
            const scripts = Array.from(document.querySelectorAll('script'));
            for (const script of scripts) {
                const text = script.textContent || '';
                if (text.length < 50) continue;
                for (const [pat, label] of patterns) {
                    pat.lastIndex = 0;
                    const m = pat.exec(text);
                    if (m) {
                        const val = m[1] || m[0];
                        if (val.length >= 10 && val.length <= 256) {
                            return {api_key: val, source: 'js_bundle.' + label};
                        }
                    }
                }
            }
            return null;
        }""")
        if result and result.get("api_key"):
            logger.info("凭据嗅探命中: JS bundle (source=%s, 长度=%d)",
                        result["source"], len(result["api_key"]))
            return {
                "api_key": result["api_key"],
                "source": result["source"],
                "method": "credential_sniff",
            }
    except Exception as exc:
        logger.debug("JS bundle 搜索异常: %s", exc)
    return None


def _looks_like_api_key(val: str) -> bool:
    """启发式判断字符串是否像 API key

    常见形态：
      - sk- 开头（OpenAI / 兼容服务）
      - eyJ 开头（JWT Bearer token）
      - 长度 > 20 且不包含空格（排除普通短字符串 / 中文）
    """
    if not val or not isinstance(val, str):
        return False
    if " " in val or "\n" in val:
        return False
    if val.startswith("sk-") and len(val) >= 30:
        return True
    if val.startswith("eyJ") and len(val) >= 50:
        return True
    if len(val) >= 30:
        return True
    return False


# ------------------------------------------------------------------
# 主入口
# ------------------------------------------------------------------

def discover(page: Any, target_url: str) -> dict[str, Any]:
    """用已登录 page 探测模型信息与凭据（优化版：并行化 + 早停）

    探测策略：
    1. 凭据嗅探 + /models 端点探测 并行执行（两者互不依赖）
    2. 任一命中即早停返回
    3. 都失败则回退 SPA 嗅探
    4. 总超时 45s（比原 90s 更激进，超时意味着不可达）

    :param page: Playwright Page 对象（已登录，携带同源 Cookie）
    :param target_url: 用户原始输入的目标 URL
    :returns: {endpoint, model, method, api_key, key_source}
    """
    import concurrent.futures

    DISCOVER_TIMEOUT = 45

    # ---- 并行任务 1：凭据嗅探 ----
    def _task_credentials() -> dict[str, Any] | None:
        return _sniff_credentials(page)

    # ---- 并行任务 2：/models 端点批量探测（并发所有候选 URL） ----
    def _task_models() -> dict[str, Any] | None:
        candidates = _derive_api_base(target_url)

        def _try_model_url(base: str, auth_header: str | None = None) -> dict | None:
            url = base.rstrip("/") + "/models"
            if auth_header:
                js = f"""async () => {{
                  try {{
                    const r = await fetch('{url}', {{
                      headers: {{'Authorization': '{auth_header}'}}
                    }});
                    if (!r.ok) return null;
                    const j = await r.json();
                    return (j.data || [])[0] || null;
                  }} catch (e) {{ return null; }}
                }}"""
            else:
                js = f"""async () => {{
                  try {{
                    const r = await fetch('{url}', {{credentials: 'same-origin'}});
                    if (!r.ok) return null;
                    const j = await r.json();
                    return (j.data || [])[0] || null;
                  }} catch (e) {{ return null; }}
                }}"""
            try:
                first_model = page.evaluate(js)
                if first_model:
                    model_id = first_model.get("id") or first_model.get("name")
                    if model_id:
                        logger.info("模型侦察命中: endpoint=%s model=%s", base, model_id)
                        return {"endpoint": base, "model": model_id}
            except Exception:
                pass
            return None

        # 先用 Cookie 并发探测所有候选 URL
        for base in candidates:
            result = _try_model_url(base)
            if result:
                return result
        return None

    # ---- 主流程 ----
    logger.info("开始模型侦察（超时=%ds）...", DISCOVER_TIMEOUT)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_creds = executor.submit(_task_credentials)
            future_models = executor.submit(_task_models)

            # 等待任一完成
            creds = future_creds.result(timeout=DISCOVER_TIMEOUT)
            api_key = creds["api_key"] if creds else None
            key_source = creds["source"] if creds else None

            # 凭据嗅探拿到 key 后，用 key 重试 /models 探测
            if api_key:
                candidates = _derive_api_base(target_url)
                for base in candidates:
                    url = base.rstrip("/") + "/models"
                    try:
                        resp = page.evaluate(
                            """async (u, k) => {
                              try {
                                const r = await fetch(u, {
                                  headers: {'Authorization': 'Bearer ' + k}
                                });
                                if (!r.ok) return {ok:false, status:r.status};
                                return {ok:true, json: await r.json()};
                              } catch (e) { return {ok:false, error: String(e)}; }
                            }""",
                            url, api_key,
                        )
                    except Exception:
                        continue
                    if resp.get("ok") and resp.get("json"):
                        models = resp["json"].get("data") or []
                        if models:
                            model_id = models[0].get("id") or models[0].get("name")
                            if model_id:
                                logger.info("API key 直连命中: endpoint=%s model=%s", base, model_id)
                                return {
                                    "endpoint": base, "model": model_id,
                                    "method": "models_api_key",
                                    "api_key": api_key, "key_source": key_source,
                                }

            # 检查 /models 并行探测结果
            try:
                models_result = future_models.result(timeout=5)
            except concurrent.futures.TimeoutError:
                models_result = None

            if models_result:
                return {
                    "endpoint": models_result["endpoint"],
                    "model": models_result["model"],
                    "method": "models_api",
                    "api_key": api_key, "key_source": key_source,
                }

            # 回退：SPA 嗅探
            spa = _sniff_spa_endpoint(page)
            if spa:
                method = spa.get("method", "spa_sniff")
                logger.info("SPA 嗅探命中: endpoint=%s model=%s method=%s",
                             spa["endpoint"], spa["model"], method)
                return {
                    "endpoint": spa["endpoint"], "model": spa["model"],
                    "method": method, "api_key": api_key, "key_source": key_source,
                }

            # 兜底
            model = _sniff_from_traffic(page)
            base = _derive_api_base(target_url)[0]
            logger.warning("所有探测方法未命中，使用兜底 endpoint=%s model=%s", base, model)
            return {
                "endpoint": base, "model": model, "method": "sniff",
                "api_key": api_key, "key_source": key_source,
            }

    except concurrent.futures.TimeoutError:
        logger.warning("模型侦察超时（%ds），使用兜底值", DISCOVER_TIMEOUT)
        base = _derive_api_base(target_url)[0]
        return {
            "endpoint": base, "model": "unknown-model", "method": "timeout_fallback",
            "api_key": None, "key_source": None,
        }
    except Exception as exc:
        logger.warning("模型侦察异常: %s，使用兜底值", exc)
        base = _derive_api_base(target_url)[0]
        return {
            "endpoint": base, "model": "unknown-model", "method": "error_fallback",
            "api_key": None, "key_source": None,
        }


def _sniff_from_traffic(page: Any) -> str:
    """从页面已捕获的请求 URL 中嗅探模型名（兜底策略）

    许多聊天页面会在请求体里带 ``"model": "xxx"``。这里仅返回占位，
    真实嗅探需配合 page.on("request") 钩子（本方案最小实现返回通用占位）。
    """
    try:
        captured = page.evaluate(
            "() => window.__garak_sniffed_model || null"
        )
        if captured:
            return captured
    except Exception:
        pass
    return "unknown-model"
