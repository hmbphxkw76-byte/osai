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

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .constants import (
    LLM_PATH_KEYWORDS,
    LLM_BODY_FIELDS,
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

    def on_request(self, request: Any) -> None:
        """请求事件回调"""
        try:
            url = request.url
            method = request.method
            headers = dict(request.headers)
            post_data = None

            # 尝试获取 POST body
            try:
                post_data = request.post_data
            except Exception:
                pass
            # post_data 可能为 None（流式/分块请求），确保为字符串
            if post_data is None:
                post_data = ""

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
            status = response.status
            headers = dict(response.headers)
            content_type = headers.get("content-type", "")

            resp_info: Dict[str, Any] = {
                "url": url,
                "status": status,
                "headers": headers,
                "content_type": content_type,
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
                            req_info["post_data"] = req_post_data
                            logger.debug("Post data captured in on_response (%d chars) for %s", len(req_post_data), url[:80])
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
        """分析请求/响应是否是 LLM API 调用"""
        url = req_info.get("url", "")
        path = req_info.get("path", "").lower()
        method = req_info.get("method", "")
        # post_data 可能为 None（Playwright 未捕获到 body）
        post_data = req_info.get("post_data") or ""
        content_type = resp_info.get("content_type", "").lower()

        # 1. 路径关键词匹配
        path_match = any(kw in path for kw in LLM_PATH_KEYWORDS)

        # 2. POST 请求 + JSON body 包含 LLM 字段
        body_match = False
        parsed_body: Optional[Dict[str, Any]] = None
        if post_data and method == "POST":
            try:
                parsed_body = json.loads(post_data)
                if isinstance(parsed_body, dict):
                    body_fields = set(parsed_body.keys())
                    overlap = body_fields & set(LLM_BODY_FIELDS)
                    body_match = len(overlap) >= 1
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. 响应 content-type 为 SSE 或 JSON
        is_sse = "text/event-stream" in content_type
        is_json = "application/json" in content_type

        # 4. 综合判断
        is_llm = (path_match and method == "POST") or body_match or is_sse

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
            }

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

    @staticmethod
    def _infer_provider(model_name: Optional[str], api_url: str) -> Optional[str]:
        """
        从模型名称和 API 端点 URL 推断提供商

        推断策略（优先模型名，更精确）：
        1. 模型名称模式匹配（最可靠，直接反映底层模型）
        2. API 端点域名匹配（补充，适用于自建代理平台）

        Args:
            model_name: 请求 body 中的 model 字段值
            api_url: API 端点 URL

        Returns:
            提供商名称（如 volcengine / openai / deepseek / zhipu 等）
        """
        import re as _re
        from urllib.parse import urlparse as _urlparse

        # 1. 模型名称模式匹配（优先，因为自建代理平台的域名不反映真实提供商）
        if model_name:
            name_lower = model_name.lower()
            # 精确模式优先（版本号后缀的 DeepSeek R1 通常是火山引擎托管）
            model_rules = [
                (r"deepseek-r1-\d+", "volcengine"),      # deepseek-r1-250120 → 火山引擎
                (r"deepseek-r\d", "volcengine"),          # deepseek-r1 → 火山引擎
                (r"deepseek", "deepseek"),                  # DeepSeek 官方 API
                (r"gpt", "openai"),
                (r"claude", "anthropic"),
                (r"qwen|通义", "alibaba"),
                (r"glm|chatglm", "zhipu"),
                (r"ernie|wenxin|文心", "baidu"),
                (r"moonshot|kimi", "moonshot"),
                (r"abab", "minimax"),
                (r"baichuan", "baichuan"),
                (r"spark|星火", "iflytek"),
                (r"hunyuan|混元", "tencent"),
                (r"gemini", "google"),
                (r"llama", "meta"),
                (r"mistral", "mistral"),
                (r"yi[-_]", "lingyi"),
                (r"phi", "microsoft"),
                (r"gemma", "google"),
            ]
            for pattern, provider in model_rules:
                if _re.search(pattern, name_lower, _re.IGNORECASE):
                    return provider

        # 2. API 端点域名匹配（补充）
        domain = (_urlparse(api_url).hostname or "").lower()
        domain_rules = [
            ("volcengineapi.com", "volcengine"),
            ("ark.volces.com", "volcengine"),
            ("api.deepseek.com", "deepseek"),
            ("api.openai.com", "openai"),
            ("open.bigmodel.cn", "zhipu"),
            ("qianfan.baidubce.com", "baidu"),
            ("api.moonshot.cn", "moonshot"),
            ("api.minimax.chat", "minimax"),
            ("dashscope.aliyuncs.com", "alibaba"),
            ("api.siliconflow.cn", "siliconflow"),
            ("api.lingyiwanwu.com", "lingyiwanwu"),
            ("api.01.ai", "lingyi"),
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
        return {
            "total_requests": len(self.captured_requests),
            "total_responses": len(self.captured_responses),
            "llm_api_calls": len(self.llm_api_calls),
            "rag_api_calls": len(self.rag_api_calls),
            "primary_llm_endpoint": primary["url"] if primary else None,
            "llm_endpoints": list({c["url"] for c in self.llm_api_calls}),
            "rag_endpoints": list({c["url"] for c in self.rag_api_calls}),
        }


