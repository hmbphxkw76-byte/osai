# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 网络流量捕获模块

NetworkTrafficCapture: 捕获并分析浏览器网络请求/响应
- 识别 LLM API 端点（路径关键词 + body 字段 + 响应特征）
- 提取模型信息 / 认证方式 / 流式响应检测
- RAG 端点探测

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .constants import (
    LLM_PATH_KEYWORDS,
    LLM_PATH_NEGATIVE_KEYWORDS,
    LLM_BODY_FIELDS,
    LLM_RESPONSE_FIELDS,
    NOISE_URL_PATTERNS,
    NOISE_DOMAIN_SUFFIXES,
    RAG_PATH_KEYWORDS,
)

logger = logging.getLogger(__name__)

class NetworkTrafficCapture:
    """
    网络流量捕获器

    在浏览器自动化过程中监听所有请求和响应，
    识别 LLM 相关的 API 调用并提取有价值信息。
    """

    def __init__(self):
        self.captured_requests: List[Dict[str, Any]] = []
        self.captured_responses: List[Dict[str, Any]] = []
        self.llm_api_calls: List[Dict[str, Any]] = []
        self.rag_api_calls: List[Dict[str, Any]] = []
        self._request_map: Dict[str, Dict[str, Any]] = {}  # 请求 ID → 请求数据
        self._noise_filtered_count: int = 0  # 被噪声过滤掉的请求数
        # ── WebSocket 流量捕获（v3 新增） ──
        # 某些 AI 平台（如千问、ChatGPT）使用 WebSocket 进行实时通信，
        # HTTP 请求/响应监听器无法捕获 WebSocket 流量。
        # Playwright 提供 page.on("websocket") 事件来监听 WebSocket 连接。
        self.websocket_connections: List[Dict[str, Any]] = []
        self.websocket_messages: List[Dict[str, Any]] = []

    # ── gzip/deflate 请求体解码（问题③修复） ──
    #
    # 根因：某些网站（如京东）使用 gzip 压缩 POST 请求体，
    # Playwright 的 request.post_data 返回原始字节，
    # 直接 json.loads() 会抛出 UnicodeDecodeError。
    #
    # 修复策略：检测 gzip 魔数（\x1f\x8b）并解压，
    # 同时支持 deflate 和 br 压缩。

    @staticmethod
    def _decode_post_data(post_data: Any) -> str:
        """
        解码可能被压缩的 POST 请求体

        支持的编码：
        - gzip（魔数 \x1f\x8b）
        - deflate（zlib 压缩）
        - 原始 UTF-8 文本（直接返回）

        Args:
            post_data: Playwright 返回的 post_data（str 或 bytes 或 None）

        Returns:
            解码后的字符串
        """
        if not post_data:
            return ""

        # 如果已经是字符串，直接返回
        if isinstance(post_data, str):
            # 检查是否是 gzip 的 base64 编码（罕见但可能）
            return post_data

        # bytes 类型：检测压缩格式
        if isinstance(post_data, (bytes, bytearray)):
            # gzip 魔数：\x1f\x8b
            if len(post_data) >= 2 and post_data[0] == 0x1f and post_data[1] == 0x8b:
                try:
                    decompressed = gzip.decompress(post_data)
                    return decompressed.decode("utf-8", errors="replace")
                except Exception as e:
                    logger.debug("gzip decompress failed: %s", str(e))
                    return post_data.decode("utf-8", errors="replace")
            # 尝试直接解码为 UTF-8
            try:
                return post_data.decode("utf-8", errors="replace")
            except Exception:
                return str(post_data)

        return str(post_data)

    # ── 噪声 URL 过滤（问题⑦修复） ──
    #
    # 过滤分析/追踪/广告/遥测请求，减少噪声、提升 LLM API 检测信噪比。
    # 过滤策略：URL 模式匹配 + 域名后缀匹配。

    @staticmethod
    def _is_noise_url(url: str) -> bool:
        """
        判断 URL 是否为噪声请求（分析/追踪/广告/CDN 静态资源）

        过滤标准：
        1. URL 包含已知噪声模式（NOISE_URL_PATTERNS）
        2. 域名匹配噪声域名后缀（NOISE_DOMAIN_SUFFIXES）
        3. 静态资源扩展名（.css/.js/.png/.jpg/.gif/.svg/.woff/.ico 等）

        Args:
            url: 请求 URL

        Returns:
            True 如果是噪声请求（应跳过）
        """
        if not url:
            return True

        url_lower = url.lower()

        # 1. 噪声 URL 模式匹配
        for pattern in NOISE_URL_PATTERNS:
            if pattern in url_lower:
                return True

        # 2. 噪声域名后缀匹配
        try:
            hostname = urlparse(url).hostname or ""
            for suffix in NOISE_DOMAIN_SUFFIXES:
                if hostname.endswith(suffix):
                    return True
        except Exception:
            pass

        # 3. 静态资源扩展名（更全面的列表）
        static_exts = (
            ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".webp", ".bmp", ".ico", ".woff", ".woff2", ".ttf", ".eot",
            ".otf", ".mp4", ".mp3", ".webm", ".avi", ".mov",
            ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
            ".map", ".json.map", ".d.ts",
        )
        # 提取路径部分（去除 query string）
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in static_exts):
            return True

        return False

    def on_request(self, request: Any) -> None:
        """请求事件回调"""
        try:
            url = request.url

            # ── 噪声过滤：跳过分析/追踪/广告/CDN 请求 ──
            if self._is_noise_url(url):
                self._noise_filtered_count += 1
                return

            method = request.method
            headers = dict(request.headers)
            post_data = None

            # 尝试获取 POST body
            try:
                post_data = request.post_data
            except Exception:
                pass

            # ── gzip/deflate 请求体解码（问题③修复） ──
            # Playwright 的 post_data 可能是 gzip 压缩的 bytes，
            # 需要检测魔数并解压后才能 json.loads
            post_data = self._decode_post_data(post_data)

            req_info: Dict[str, Any] = {
                "url": url,
                "method": method,
                "headers": headers,
                "post_data": post_data,
                "timestamp": time.time(),
                "path": urlparse(url).path,
            }

            self._request_map[url] = req_info
            self.captured_requests.append(req_info)

        except Exception as e:
            logger.debug("Failed to capture request: %s", str(e))

    async def on_response(self, response: Any) -> None:
        """响应事件回调（异步，捕获 LLM API 响应体）"""
        try:
            url = response.url

            # ── 噪声过滤：跳过分析/追踪/广告/CDN 响应 ──
            if self._is_noise_url(url):
                return

            status = response.status
            headers = dict(response.headers)
            content_type = headers.get("content-type", "")
            content_encoding = headers.get("content-encoding", "").lower()

            resp_info: Dict[str, Any] = {
                "url": url,
                "status": status,
                "headers": headers,
                "content_type": content_type,
                "content_encoding": content_encoding,
                "timestamp": time.time(),
                "path": urlparse(url).path,
            }

            # 关联请求
            req_info = self._request_map.get(url)
            # 提前提取 method，避免后续引用未定义变量
            method = req_info.get("method", "") if req_info else ""
            if req_info:
                resp_info["request"] = req_info
                # 如果 on_request 未捕获到 post_data，在 on_response 中补充获取
                # 仅对 POST/PUT/PATCH 请求警告（GET 请求天然无 body）
                if not req_info.get("post_data") and method in ("POST", "PUT", "PATCH"):
                    try:
                        req_post_data = response.request.post_data
                        if req_post_data:
                            # ── gzip 解码补充获取的 post_data ──
                            req_info["post_data"] = self._decode_post_data(req_post_data)
                            logger.debug("Post data captured+decoded in on_response (%d chars) for %s", len(req_info["post_data"]), url[:80])
                        else:
                            logger.warning("Post data is None even in on_response for %s %s", method, url[:80])
                    except Exception as pd_err:
                        logger.warning("Failed to get post_data in on_response: %s", str(pd_err)[:100])
                elif req_info.get("post_data"):
                    logger.debug("Post data already captured (%d chars) for %s %s", len(req_info.get("post_data", "")), method, url[:80])
                # 分析是否是 LLM API 调用（同步分析，不获取 body）
                self._analyze_llm_call(req_info, resp_info)

            # 异步获取响应体（仅对 LLM API 调用和 RAG 调用）
            if req_info:
                path_lower = req_info.get("path", "").lower()
                # 排除静态资源（JS/CSS/图片/字体等），避免误报和性能浪费
                static_extensions = (
                    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                    '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map',
                    '.mp4', '.mp3', '.webp', '.pdf', '.zip', '.tar', '.gz',
                )
                if any(path_lower.endswith(ext) for ext in static_extensions):
                    is_potential_llm = False
                else:
                    is_potential_llm = (
                        any(kw in path_lower for kw in LLM_PATH_KEYWORDS) or
                        method == "POST"
                    )
                if is_potential_llm:
                    try:
                        body_text = await response.text()
                        # ── gzip 响应体解码（问题③修复） ──
                        # Playwright response.text() 通常已自动解压，
                        # 但某些边缘情况下可能返回原始压缩数据
                        if body_text and body_text[0:1] == '\x1f' and len(body_text) > 1 and body_text[1:2] == '\x8b':
                            try:
                                body_bytes = body_text.encode('latin-1')
                                body_text = gzip.decompress(body_bytes).decode('utf-8', errors='replace')
                                logger.debug("Response body gzip-decoded (%d chars) for %s", len(body_text), url[:80])
                            except Exception:
                                pass

                        if not body_text:
                            logger.warning("Response body is EMPTY for %s %s (content-type: %s)", method, url[:80], content_type)
                        else:
                            logger.debug("Response body captured (%d chars) for %s %s", len(body_text), method, url[:80])
                        resp_info["body"] = body_text[:10000]  # 限制大小
                        # 查找匹配的 LLM API 调用并附加响应体
                        # 从列表尾部搜索最近匹配的 URL（竞态条件下更稳健）
                        for i in range(len(self.llm_api_calls) - 1, -1, -1):
                            if self.llm_api_calls[i].get("url") == url:
                                self.llm_api_calls[i]["response_body"] = body_text[:10000]
                                # 尝试从响应体提取模型生成的文本
                                extracted = self._extract_response_text(body_text, content_type)
                                if extracted:
                                    self.llm_api_calls[i]["response_text_extracted"] = extracted
                                # 如果请求 body 未提取到模型名，尝试从响应 body 提取
                                if not self.llm_api_calls[i].get("model_extracted"):
                                    model_from_resp = self._extract_model_from_response_body(body_text[:10000])
                                    if model_from_resp:
                                        self.llm_api_calls[i]["model_extracted"] = model_from_resp
                                        self.llm_api_calls[i]["model_source"] = "response_body"
                                        # 重新推断提供商
                                        self.llm_api_calls[i]["provider_inferred"] = self._infer_provider(
                                            model_from_resp, url,
                                        )
                                        logger.info("Model extracted from response body: %s", model_from_resp)
                                    else:
                                        logger.warning("Model NOT found in response body (body length: %d)", len(body_text[:10000]))
                                break
                    except Exception as body_err:
                        logger.warning("Failed to capture response body for %s: %s", url[:80], str(body_err)[:100])

            self.captured_responses.append(resp_info)

        except Exception as e:
            logger.debug("Failed to capture response: %s", str(e))

    @staticmethod
    def _extract_response_text(body: str, content_type: str) -> str:
        """从 LLM API 响应体中提取模型生成的文本"""
        if not body:
            return ""

        # SSE 流式响应
        if "text/event-stream" in content_type:
            lines = body.split("\n")
            texts = []
            for line in lines:
                if line.startswith("data:"):
                    data = line[5:].strip()
                    if data and data != "[DONE]":
                        try:
                            chunk = json.loads(data)
                            # OpenAI 格式
                            choices = chunk.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    texts.append(content)
                                # 或 message.content
                                message = choices[0].get("message", {})
                                if message.get("content"):
                                    texts.append(message["content"])
                        except (json.JSONDecodeError, ValueError):
                            continue
            return "".join(texts)

        # JSON 响应
        if "application/json" in content_type:
            try:
                data = json.loads(body)
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    return message.get("content", "")
                # 通义千问格式
                output = data.get("output", {})
                if isinstance(output, dict):
                    return output.get("text", "")
                # 其他格式
                return data.get("response", data.get("answer", data.get("reply", "")))
            except (json.JSONDecodeError, ValueError):
                pass

        return body[:2000]  # 返回原始文本的前 2000 字符

    @staticmethod
    def _extract_model_from_response_body(body: str) -> Optional[str]:
        """
        从 LLM API 响应体中提取模型名称（增强版 v2）

        v2 增强：
        - 解析所有 SSE data 块（模型名可能在末尾块中）
        - 大小写不敏感字段查找（Model/model/ModelName/model_name 等）
        - 正则兜底搜索：在全文中搜索 model/Model 字段
        - 嵌套字段查找（metadata.model）
        """
        if not body:
            return None

        # 所有可能包含模型名的字段名
        model_fields = [
            "model", "Model", "MODEL",
            "model_name", "ModelName", "modelName",
            "model_id", "ModelId", "modelId",
        ]

        # SSE 流式响应：逐行解析所有块
        if "data:" in body:
            for line in body.split("\n"):
                if line.startswith("data:"):
                    data = line[5:].strip()
                    if data and data != "[DONE]":
                        try:
                            chunk = json.loads(data)
                            if isinstance(chunk, dict):
                                for field in model_fields:
                                    model = chunk.get(field)
                                    if model and isinstance(model, str) and len(model) > 1:
                                        return model
                                # 嵌套字段（metadata.model）
                                meta = chunk.get("metadata") or chunk.get("Metadata") or {}
                                if isinstance(meta, dict):
                                    for field in model_fields:
                                        model = meta.get(field)
                                        if model and isinstance(model, str) and len(model) > 1:
                                            return model
                        except (json.JSONDecodeError, ValueError):
                            continue

        # JSON 响应
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for field in model_fields:
                    model = data.get(field)
                    if model and isinstance(model, str) and len(model) > 1:
                        return model
                meta = data.get("metadata") or data.get("Metadata") or {}
                if isinstance(meta, dict):
                    for field in model_fields:
                        model = meta.get(field)
                        if model and isinstance(model, str) and len(model) > 1:
                            return model
        except (json.JSONDecodeError, ValueError):
            pass

        # 正则兜底：在整个响应体中搜索 model 字段
        import re as _re
        pattern = r'["\']?(?:model|Model|model_name|ModelName)["\']?\s*:\s*["\']([\w\-./:]+)["\']'
        matches = _re.findall(pattern, body)
        for match in matches:
            if match.lower() not in ("chat", "completion", "text", "stream", "json"):
                return match

        return None

    async def capture_response_body(self, response: Any) -> str:
        """异步获取响应 body 文本"""
        try:
            return await response.text()
        except Exception:
            return ""

    def _analyze_llm_call(self, req_info: Dict[str, Any], resp_info: Dict[str, Any]) -> None:
        """分析请求/响应是否是 LLM API 调用（v2 增强版）

        v2 增强（问题⑥修复）：
        - 增加 response body 字段检测（LLM_RESPONSE_FIELDS）
        - 增加 SSE/JSON 响应内容特征检测
        - 降低误报率：POST 请求需要至少 2 个 LLM body 字段才判定
        v3.2 增强：
        - 域名关键词匹配（hostname_match）：chat2-api.qianwen.com 等域名含 "chat"
          但路径可能不含关键词，需同时检查域名
        """
        url = req_info.get("url", "")
        path = req_info.get("path", "").lower()
        method = req_info.get("method", "")
        # post_data 可能为 None（Playwright 未捕获到 body）
        post_data = req_info.get("post_data") or ""
        content_type = resp_info.get("content_type", "").lower()

        # 提取 hostname 用于域名级关键词匹配（v3.2 新增）
        try:
            hostname = urlparse(url).hostname or ""
            hostname_lower = hostname.lower()
        except Exception:
            hostname_lower = ""

        # 1. 路径关键词匹配
        path_match = any(kw in path for kw in LLM_PATH_KEYWORDS)

        # 1a. 域名关键词匹配（v3.2 新增）
        # 千问 chat2-api.qianwen.com 域名含 "chat"，但 API 路径可能不含关键词
        # 如 /api/v1/sse/send → path 不匹配，但 hostname 匹配 "chat"
        hostname_match = any(kw in hostname_lower for kw in LLM_PATH_KEYWORDS)

        # 1b. 路径负向关键词排除（v3 新增）
        # 千问 aide.qianwen.com/api/general/config/query 含 "query" 但实际是配置查询；
        # api.qianwen.com/api/account/login/v2/qrcode/generate 含 "ai"+"generate" 但是二维码生成。
        # 如果路径包含负向关键词，降级 path_match 的权重（不直接排除，交给后续判断）
        path_negative = any(nk in path for nk in LLM_PATH_NEGATIVE_KEYWORDS)

        # 2. POST 请求 + JSON body 包含 LLM 字段
        body_match = False
        body_match_score = 0  # 加权评分，越多 LLM 字段越可信
        parsed_body: Optional[Dict[str, Any]] = None
        if post_data and method == "POST":
            try:
                parsed_body = json.loads(post_data)
                if isinstance(parsed_body, dict):
                    body_fields = set(parsed_body.keys())
                    overlap = body_fields & set(LLM_BODY_FIELDS)
                    body_match_score = len(overlap)
                    # v2: 至少 1 个 LLM 字段即判定（保持灵敏度）
                    body_match = body_match_score >= 1
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. 响应 content-type 为 SSE 或 JSON
        is_sse = "text/event-stream" in content_type
        is_json = "application/json" in content_type

        # 3b. 响应 content-type 排除规则（v3 新增）
        # 某些跟踪/统计 API 的 URL 包含 "message" 等关键词（如 gm.mmstat.com 的
        # hvn_minilogin_page.postMessage），但响应是 image/gif（1x1 跟踪像素）或
        # text/html（空响应），绝对不是 LLM API。
        # 排除条件：响应类型为图片/HTML/二进制/空 → 不可能是 LLM API
        is_non_llm_response = any(ct in content_type for ct in (
            "image/",        # image/gif, image/png 等（跟踪像素）
            "text/html",     # 空响应/重定向页面
            "application/octet-stream",  # 二进制下载
            "application/x-gzip",        # 压缩文件
        ))

        # 4. 综合判断（v3 优化）
        # v2: POST + path_match 或 body_match 即判定
        # v3: 新增响应 content-type 排除规则
        #   - 如果响应是图片/HTML/二进制 → 排除（即使路径关键词匹配）
        #   - 仍保留 body_match 的高灵敏度（但 body_match + 非API响应 → 排除）
        # v3.1: 新增负向关键词降权
        #   - 路径同时匹配 LLM 关键词和负向关键词（如 config/query）时，
        #     仅当 body 有强 LLM 信号（≥2 个 LLM body 字段）才判定为 LLM API
        # v3.2: 新增域名关键词匹配
        #   - hostname 含 LLM 关键词（如 chat2-api）也作为判定信号
        #   - 负向关键词同样适用于域名匹配
        path_llm = (path_match or hostname_match) and method == "POST"
        if path_negative and body_match_score < 2:
            # 负向关键词 + 弱 body 信号 → 大概率不是 LLM API
            path_llm = False
        if is_non_llm_response and not is_sse and not is_json:
            # 响应不是 JSON/SSE，不可能是 LLM API
            path_llm = False
            body_match = False
        is_llm = path_llm or body_match or is_sse

        if is_llm:
            call_info: Dict[str, Any] = {
                "url": url,
                "path": req_info.get("path", ""),
                "method": method,
                "status": resp_info.get("status"),
                "content_type": content_type,
                "is_streaming": is_sse,
                "request_body": parsed_body,
                "request_headers": req_info.get("headers", {}),
                "model_extracted": None,
                "system_prompt_extracted": None,
                "messages_count": 0,
                "detection_signals": [],  # v2: 记录检测信号用于调试
            }

            # 记录检测信号
            if path_match:
                call_info["detection_signals"].append("path_keyword")
            if hostname_match and not path_match:
                call_info["detection_signals"].append("hostname_keyword")
            if path_negative:
                call_info["detection_signals"].append("negative_keyword")
            if body_match:
                call_info["detection_signals"].append(f"body_fields({body_match_score})")
            if is_sse:
                call_info["detection_signals"].append("sse_content_type")

            # 从请求 body 提取模型名称和参数
            if parsed_body:
                # 模型名称（兼容多种字段名，含 Go 风格大写）
                model_name = (
                    parsed_body.get("model")
                    or parsed_body.get("Model")
                    or parsed_body.get("model_name")
                    or parsed_body.get("ModelName")
                    or parsed_body.get("modelName")
                    or parsed_body.get("model_id")
                    or parsed_body.get("ModelId")
                    or parsed_body.get("modelId")
                )
                # 嵌套模型字段（部分平台放在 extra_body 或 config 中）
                if not model_name:
                    extra = parsed_body.get("extra_body")
                    if isinstance(extra, dict):
                        model_name = extra.get("model") or extra.get("model_name")
                call_info["model_extracted"] = model_name

                # 模型参数（top_p / temperature / max_tokens / stream 等）
                model_params = {}
                for param_key in ("top_p", "temperature", "max_tokens", "max_new_tokens",
                                  "stream", "top_k", "frequency_penalty", "presence_penalty",
                                  "stop", "n", "seed"):
                    val = parsed_body.get(param_key)
                    if val is not None:
                        model_params[param_key] = val
                if model_params:
                    call_info["model_parameters"] = model_params

                messages = parsed_body.get("messages", [])
                call_info["messages_count"] = len(messages) if isinstance(messages, list) else 0

                # 提取系统提示
                if isinstance(messages, list):
                    for msg in messages:
                        if isinstance(msg, dict) and msg.get("role") == "system":
                            content = msg.get("content", "")
                            if content:
                                call_info["system_prompt_extracted"] = str(content)[:2000]
                            break

                # 检测 function_calling
                if parsed_body.get("tools") or parsed_body.get("functions"):
                    call_info["has_tools"] = True

                # 检测 vision（多模态）
                if isinstance(messages, list):
                    for msg in messages:
                        content = msg.get("content")
                        if isinstance(content, list):
                            for part in content:
                                if isinstance(part, dict) and part.get("type") == "image_url":
                                    call_info["has_vision"] = True
                                    break

            # 提供商推断（优先模型名，其次域名）
            call_info["provider_inferred"] = self._infer_provider(
                call_info.get("model_extracted"), url,
            )

            # 从请求头提取认证方式
            auth_header = call_info["request_headers"].get("authorization", "")
            if auth_header:
                if auth_header.lower().startswith("bearer "):
                    call_info["auth_type"] = "bearer"
                elif auth_header.lower().startswith("basic "):
                    call_info["auth_type"] = "basic"
                else:
                    call_info["auth_type"] = "custom"
            elif call_info["request_headers"].get("cookie"):
                call_info["auth_type"] = "cookie"
            elif call_info["request_headers"].get("x-api-key"):
                call_info["auth_type"] = "api_key"
            else:
                call_info["auth_type"] = "none"

            self.llm_api_calls.append(call_info)

        # RAG 端点检测（排除静态资源和已被分类为 LLM 的调用）
        is_rag = any(kw in path for kw in RAG_PATH_KEYWORDS)
        # 排除静态资源（CSS/JS/图片/字体等）
        static_exts = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                       ".woff", ".woff2", ".ttf", ".ico", ".map")
        is_static = path.endswith(static_exts)
        # 排除已被分类为 LLM API 的调用（避免 /chat/completions/with-knowledge 同时出现在两个列表中）
        is_llm_already = is_llm
        if is_rag and not is_static and not is_llm_already and method in ("GET", "POST"):
            self.rag_api_calls.append({
                "url": url,
                "path": req_info.get("path", ""),
                "method": method,
                "status": resp_info.get("status"),
                "content_type": content_type,
            })

    # ── WebSocket 流量捕获（v3 新增） ──
    #
    # 某些 AI 平台（如千问、ChatGPT、Claude）使用 WebSocket 进行实时聊天通信，
    # 而非 HTTP POST 请求。Playwright 的 page.on("request"/"response") 无法捕获
    # WebSocket 流量，需要使用 page.on("websocket") 事件单独监听。
    #
    # WebSocket 消息特征：
    # - 发送方向 (send): 包含用户消息 + 模型参数
    # - 接收方向 (receive): 包含 AI 回复 + 可能的模型名/参数
    # - 消息格式: JSON（常见于结构化协议）或纯文本

    def on_websocket(self, ws: Any) -> None:
        """
        WebSocket 连接事件回调

        监听 WebSocket 连接的生命周期和消息收发。
        Playwright 的 websocket 事件提供：
        - ws.url: WebSocket URL
        - ws.on("framesent", handler): 发送消息
        - ws.on("framereceived", handler): 接收消息
        - ws.on("close", handler): 连接关闭
        """
        try:
            ws_url = ws.url
            if self._is_noise_url(ws_url):
                return

            conn_info: Dict[str, Any] = {
                "url": ws_url,
                "timestamp": time.time(),
                "messages_sent": 0,
                "messages_received": 0,
                "is_llm": False,
            }
            self.websocket_connections.append(conn_info)
            logger.info("WebSocket connection detected: %s", ws_url[:120])

            def on_frame_sent(payload: Any) -> None:
                """WebSocket 发送消息回调"""
                try:
                    conn_info["messages_sent"] += 1
                    payload_str = payload if isinstance(payload, str) else str(payload)
                    msg_info: Dict[str, Any] = {
                        "url": ws_url,
                        "direction": "send",
                        "payload": payload_str[:5000],
                        "timestamp": time.time(),
                    }
                    self.websocket_messages.append(msg_info)
                    self._analyze_websocket_message(msg_info, conn_info)
                except Exception as e:
                    logger.debug("WebSocket frame_sent handler error: %s", str(e))

            def on_frame_received(payload: Any) -> None:
                """WebSocket 接收消息回调"""
                try:
                    conn_info["messages_received"] += 1
                    payload_str = payload if isinstance(payload, str) else str(payload)
                    msg_info: Dict[str, Any] = {
                        "url": ws_url,
                        "direction": "receive",
                        "payload": payload_str[:5000],
                        "timestamp": time.time(),
                    }
                    self.websocket_messages.append(msg_info)
                    self._analyze_websocket_message(msg_info, conn_info)
                except Exception as e:
                    logger.debug("WebSocket frame_received handler error: %s", str(e))

            def on_close() -> None:
                """WebSocket 关闭回调"""
                try:
                    conn_info["closed"] = True
                    logger.info(
                        "WebSocket closed: %s (sent=%d, received=%d, is_llm=%s)",
                        ws_url[:80],
                        conn_info["messages_sent"],
                        conn_info["messages_received"],
                        conn_info["is_llm"],
                    )
                except Exception:
                    pass

            ws.on("framesent", on_frame_sent)
            ws.on("framereceived", on_frame_received)
            ws.on("close", on_close)

        except Exception as e:
            logger.debug("WebSocket handler error: %s", str(e))

    def _analyze_websocket_message(
        self, msg_info: Dict[str, Any], conn_info: Dict[str, Any]
    ) -> None:
        """
        分析 WebSocket 消息是否包含 LLM 相关信息

        检测策略：
        1. URL 包含聊天/AI 关键词（chat/ai/completions/llm 等）
        2. 消息体包含 LLM 特征字段（messages/model/prompt 等）
        3. 消息体包含聊天特征文本（role/content/assistant 等）

        如果检测到 LLM 特征，将 WebSocket 连接标记为 LLM 通道，
        并尝试从消息中提取模型名。
        """
        url = msg_info.get("url", "").lower()
        direction = msg_info.get("direction", "")
        payload = msg_info.get("payload", "")

        if not payload:
            return

        # 1. URL 关键词匹配
        url_llm = any(kw in url for kw in LLM_PATH_KEYWORDS)

        # 2. 消息体 JSON 解析 + LLM 字段检测
        parsed = None
        try:
            parsed = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            pass

        body_llm = False
        model_from_ws = None
        if isinstance(parsed, dict):
            body_fields = set(parsed.keys())
            overlap = body_fields & set(LLM_BODY_FIELDS)
            body_llm = len(overlap) >= 1

            # 提取模型名
            for field in ("model", "Model", "model_name", "modelName"):
                val = parsed.get(field)
                if val and isinstance(val, str) and len(val) > 1:
                    model_from_ws = val
                    break

            # 检查嵌套的 messages 中的 model
            if not model_from_ws:
                header = parsed.get("header") or parsed.get("Header")
                if isinstance(header, dict):
                    for field in ("model", "Model", "model_name"):
                        val = header.get(field)
                        if val and isinstance(val, str):
                            model_from_ws = val
                            break

        # 3. 消息体文本特征（role/content/assistant 等）
        text_llm = any(kw in payload.lower() for kw in (
            '"role"', '"content"', '"assistant"', '"messages"',
            'data:', 'event:',  # SSE-style in WebSocket
        ))

        # 综合判断
        is_llm_ws = url_llm or body_llm or text_llm

        if is_llm_ws and not conn_info.get("is_llm"):
            conn_info["is_llm"] = True
            logger.info(
                "LLM WebSocket detected: %s (direction=%s, url_match=%s, body_match=%s, text_match=%s)",
                msg_info.get("url", "")[:80], direction, url_llm, body_llm, text_llm,
            )

        # 如果检测到模型名，记录到 LLM API 调用列表
        if model_from_ws and not any(
            c.get("url") == msg_info.get("url") and c.get("model_extracted")
            for c in self.llm_api_calls
        ):
            self.llm_api_calls.append({
                "url": msg_info.get("url", ""),
                "path": urlparse(msg_info.get("url", "")).path,
                "method": "WS",
                "status": None,
                "content_type": "websocket",
                "is_streaming": True,
                "request_body": parsed if isinstance(parsed, dict) else None,
                "request_headers": {},
                "model_extracted": model_from_ws,
                "model_source": "websocket",
                "system_prompt_extracted": None,
                "messages_count": 0,
                "detection_signals": ["websocket"],
                "provider_inferred": self._infer_provider(model_from_ws, msg_info.get("url", "")),
                "auth_type": "websocket",
                "has_tools": False,
                "has_vision": False,
            })
            logger.info("Model extracted from WebSocket: %s", model_from_ws)

    @staticmethod
    def _infer_provider(model_name: Optional[str], api_url: str) -> Optional[str]:
        """
        从模型名称和 API 端点 URL 双重策略推断提供商（v2 全球覆盖版）

        推断策略（优先模型名，更精确）：
        1. 模型名称模式匹配（最可靠，直接反映底层模型）
           - 中国厂商：DeepSeek/阿里/智谱/百度/月之暗面/MiniMax/百川/讯飞/腾讯/零一/阶跃
           - 欧美厂商：OpenAI/Anthropic/Google/Meta/Mistral/Microsoft/Cohere/Amazon/IBM/Perplexity/Stability/AI21
        2. API 端点域名匹配（补充，适用于自建代理平台）
           - 中国域名：volcengineapi.com / dashscope.aliyuncs.com / api.deepseek.com 等
           - 欧美域名：api.openai.com / api.anthropic.com / generativelanguage.googleapis.com 等

        Args:
            model_name: 请求 body 中的 model 字段值
            api_url: API 端点 URL

        Returns:
            提供商名称（如 openai / anthropic / google / volcengine / deepseek 等）
        """
        import re as _re
        from urllib.parse import urlparse as _urlparse

        # 1. 模型名称模式匹配（优先，因为自建代理平台的域名不反映真实提供商）
        if model_name:
            name_lower = model_name.lower()

            # ── 精确模式优先（版本号后缀的 DeepSeek R1 通常是火山引擎托管）──
            model_rules = [
                # ═══ 中国厂商 ═══
                # DeepSeek（火山引擎托管的 R1 带版本号）
                (r"deepseek-r1-\d+", "volcengine"),      # deepseek-r1-250120 → 火山引擎
                (r"deepseek-r\d", "volcengine"),          # deepseek-r1 → 火山引擎
                (r"deepseek", "deepseek"),                  # DeepSeek 官方 API
                # 阿里通义千问
                (r"qwen|通义", "alibaba"),
                # 智谱 GLM
                (r"glm|chatglm", "zhipu"),
                # 百度文心
                (r"ernie|wenxin|文心", "baidu"),
                # 月之暗面 Kimi
                (r"moonshot|kimi", "moonshot"),
                # MiniMax
                (r"abab|minimax", "minimax"),
                # 百川
                (r"baichuan", "baichuan"),
                # 科大讯飞星火
                (r"spark|星火", "iflytek"),
                # 腾讯混元
                (r"hunyuan|混元", "tencent"),
                # 零一万物
                (r"yi[-_]", "lingyi"),
                # 阶跃星辰
                (r"step[-_]", "stepfun"),

                # ═══ 欧美厂商 ═══
                # OpenAI（GPT 系列 + o 系列推理模型 + DALL-E + Whisper + TTS）
                (r"gpt", "openai"),                         # gpt-4o, gpt-3.5-turbo
                (r"^o\d", "openai"),                        # o1, o3, o4-mini
                (r"dall[-_]?e", "openai"),                  # dall-e-3
                (r"whisper", "openai"),                     # whisper-1
                (r"tts[-_]?1", "openai"),                   # tts-1, tts-1-hd
                (r"text-embedding", "openai"),              # text-embedding-3
                (r"sora", "openai"),                        # sora
                # Anthropic Claude
                (r"claude", "anthropic"),                   # claude-3.5-sonnet
                # Google Gemini / Gemma / PaLM
                (r"gemini", "google"),                      # gemini-1.5-pro
                (r"gemma", "google"),                       # gemma-2
                (r"palm", "google"),                        # palm-2 (legacy)
                (r"bard", "google"),                        # bard (legacy)
                # Meta LLaMA
                (r"llama", "meta"),                         # llama-3.1-70b
                # Mistral AI / Ministral
                (r"ministral", "mistral"),                  # ministral-8b
                (r"mistral", "mistral"),                    # mistral-large
                (r"mixtral", "mistral"),                    # mixtral-8x7b
                (r"codestral", "mistral"),                  # codestral
                (r"pixtral", "mistral"),                    # pixtral
                # Microsoft Phi
                (r"phi[-_]?\d", "microsoft"),               # phi-3
                (r"^phi$", "microsoft"),                    # phi
                # Cohere Command
                (r"command", "cohere"),                     # command-r-plus
                (r"coral", "cohere"),                       # coral
                # Amazon Nova / Titan
                (r"nova", "amazon"),                        # nova-pro
                (r"titan", "amazon"),                       # titan-text
                # IBM Granite / Merlinite
                (r"granite", "ibm"),                        # granite-3b
                (r"merlinite", "ibm"),                      # merlinite-7b
                # Perplexity
                (r"pplx", "perplexity"),                    # pplx-7b-online
                (r"sonar", "perplexity"),                   # sonar-small
                # Stability AI
                (r"stable[-_]?lm", "stability"),            # stablelm-2
                (r"stable[-_]?code", "stability"),          # stablecode-3b
                # AI21 Labs
                (r"jamba", "ai21"),                         # jamba-instruct
                (r"jurassic", "ai21"),                      # jurassic-2
                # Reka
                (r"reka", "reka"),                          # reka-core
                # Databricks
                (r"dbrx", "databricks"),                    # dbrx-instruct
                # xAI Grok
                (r"grok", "xai"),                           # grok-2
                # Together AI / Anyscale / Fireworks（开源模型托管平台，保持平台名）
                # 这些通常通过模型名前缀识别，但域名更可靠，放域名规则中
            ]
            for pattern, provider in model_rules:
                if _re.search(pattern, name_lower, _re.IGNORECASE):
                    return provider

        # 2. API 端点域名匹配（补充）
        domain = (_urlparse(api_url).hostname or "").lower()
        domain_rules = [
            # ═══ 中国域名 ═══
            ("volcengineapi.com", "volcengine"),
            ("ark.volces.com", "volcengine"),
            ("api.deepseek.com", "deepseek"),
            ("open.bigmodel.cn", "zhipu"),
            ("qianfan.baidubce.com", "baidu"),
            ("api.moonshot.cn", "moonshot"),
            ("api.minimax.chat", "minimax"),
            ("dashscope.aliyuncs.com", "alibaba"),
            ("api.siliconflow.cn", "siliconflow"),
            ("api.lingyiwanwu.com", "lingyiwanwu"),
            ("api.01.ai", "lingyi"),
            ("api.stepfun.com", "stepfun"),

            # ═══ 欧美域名 ═══
            # OpenAI
            ("api.openai.com", "openai"),
            ("openai.azure.com", "openai"),                 # Azure OpenAI
            ("oai.azure.com", "openai"),                    # Azure OpenAI 短域名
            # Anthropic
            ("api.anthropic.com", "anthropic"),
            # Google
            ("generativelanguage.googleapis.com", "google"),
            ("aiplatform.googleapis.com", "google"),        # Vertex AI
            ("us-central1-aiplatform.googleapis.com", "google"),
            # Mistral AI
            ("api.mistral.ai", "mistral"),
            # Cohere
            ("api.cohere.ai", "cohere"),
            ("api.cohere.com", "cohere"),
            # Amazon Bedrock
            ("bedrock-runtime.", "amazon"),                 # bedrock-runtime.us-east-1.amazonaws.com
            ("amazonaws.com", "amazon"),                    # 兜底 AWS
            # IBM watsonx
            ("us-south.ml.cloud.ibm.com", "ibm"),
            ("ml.cloud.ibm.com", "ibm"),
            # Perplexity
            ("api.perplexity.ai", "perplexity"),
            # Stability AI
            ("api.stability.ai", "stability"),
            # AI21 Labs
            ("api.ai21.com", "ai21"),
            ("api.ai21.ai", "ai21"),
            # Reka
            ("api.reka.ai", "reka"),
            # xAI
            ("api.x.ai", "xai"),
            # Together AI
            ("api.together.xyz", "together"),
            # Fireworks AI
            ("api.fireworks.ai", "fireworks"),
            # Anyscale
            ("api.endpoints.anyscale.com", "anyscale"),
            # Groq
            ("api.groq.com", "groq"),
            # DeepInfra
            ("api.deepinfra.com", "deepinfra"),
            # Hugging Face
            ("api-inference.huggingface.co", "huggingface"),
            # OpenRouter
            ("openrouter.ai", "openrouter"),
            # 注意：appsharing-ai 等自建代理平台不映射为 custom，
            # 让模型名推断来决定真实提供商
        ]
        for pattern, provider in domain_rules:
            if pattern in domain:
                return provider

        return None

    def get_primary_llm_endpoint(self) -> Optional[Dict[str, Any]]:
        """获取主要的 LLM API 端点（调用次数最多的）"""
        if not self.llm_api_calls:
            return None

        # 按路径分组统计
        path_counts: Dict[str, int] = {}
        path_calls: Dict[str, Dict[str, Any]] = {}
        for call in self.llm_api_calls:
            p = call["path"]
            path_counts[p] = path_counts.get(p, 0) + 1
            path_calls[p] = call  # 保留最后一个

        # 选择调用次数最多的路径
        primary_path = max(path_counts, key=path_counts.get)
        return path_calls[primary_path]

    def get_summary(self) -> Dict[str, Any]:
        """获取流量捕获摘要"""
        primary = self.get_primary_llm_endpoint()
        # 统计 LLM WebSocket 连接
        llm_ws_conns = [c for c in self.websocket_connections if c.get("is_llm")]
        ws_llm_urls = list({c["url"] for c in llm_ws_conns})
        return {
            "total_requests": len(self.captured_requests),
            "total_responses": len(self.captured_responses),
            "llm_api_calls": len(self.llm_api_calls),
            "rag_api_calls": len(self.rag_api_calls),
            "noise_filtered": self._noise_filtered_count,
            "primary_llm_endpoint": primary["url"] if primary else None,
            "llm_endpoints": list({c["url"] for c in self.llm_api_calls}),
            "rag_endpoints": list({c["url"] for c in self.rag_api_calls}),
            # WebSocket 统计（v3 新增）
            "websocket_connections": len(self.websocket_connections),
            "websocket_messages": len(self.websocket_messages),
            "websocket_llm_endpoints": ws_llm_urls,
        }


