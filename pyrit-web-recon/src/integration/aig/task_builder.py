# -*- coding: utf-8 -*-
"""
AI-Infra-Guard Task Builder
===========================

根据 pyrit-web-recon 生成的 TargetProfile，
动态构造 AI-Infra-Guard（AIG）可接受的扫描任务 payload。

当前支持的任务类型：
- ai_infra_scan     : AI 基础设施扫描
- agent_scan        : Agent 应用扫描
- model_redteam_report: 模型红队报告
- mcp_scan          : MCP Server 扫描
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.recon.target_profile import TargetProfile


class AIGTaskBuilder:
    """AIG 任务构造器"""

    def __init__(self, profile: TargetProfile):
        """
        初始化构造器。

        Args:
            profile: pyrit-web-recon 输出的目标侦察 Profile
        """
        self.profile = profile

    def build_all(self) -> List[Dict[str, Any]]:
        """
        根据 Profile 内容，自动判断需要触发哪些 AIG 任务。

        Returns:
            任务列表，每个任务包含 type 和 content 字段
        """
        tasks: List[Dict[str, Any]] = []

        # 1. 只要有目标域名或 IP，就执行基础设施扫描
        tasks.append(self.build_ai_infra_scan())

        # 2. 如果检测到 Agent / Web UI / Copilot 特征，执行 Agent 扫描
        if self._has_agent_signal():
            tasks.append(self.build_agent_scan())

        # 3. 如果识别出 LLM API endpoint 和模型名，执行模型红队报告
        if self._has_model_signal():
            tasks.append(self.build_model_redteam_report())

        # 4. 如果检测到 MCP Server 信号，执行 MCP 扫描
        if self._has_mcp_signal():
            tasks.append(self.build_mcp_scan())

        return tasks

    def build_ai_infra_scan(self) -> Dict[str, Any]:
        """
        构造 AI 基础设施扫描任务。

        该任务让 AIG 从目标域名/IP 出发，
        发现暴露的 AI 服务端口、向量数据库、管理后台等。
        """
        # 提取目标主机列表：域名 + API endpoint 主机
        targets = self._collect_targets()

        content: Dict[str, Any] = {
            "target": targets,
            "scan_depth": self.profile.recon_depth,
            "tags": ["from_pyrit_web_recon"],
        }

        return {
            "type": "ai_infra_scan",
            "content": content,
        }

    def build_agent_scan(self) -> Dict[str, Any]:
        """
        构造 Agent 扫描任务。

        当目标呈现 Agent / Copilot / Dify / FastGPT 等特征时使用。
        """
        # 优先使用第一个 LLM API endpoint 作为 agent 入口
        api_endpoint = self._first_api_endpoint()

        # 构造 agent_config YAML 风格的字典
        agent_config: Dict[str, Any] = {
            "provider": self._infer_agent_provider(),
            "target": api_endpoint or self.profile.target,
        }

        # 如果提取到了认证凭据，写入配置（实际应从 Vault 读取，这里仅占位）
        auth = self._first_extracted_auth()
        if auth:
            agent_config["auth"] = auth

        content: Dict[str, Any] = {
            "agent_config": agent_config,
            "target": self.profile.target,
        }

        return {
            "type": "agent_scan",
            "content": content,
        }

    def build_model_redteam_report(self) -> Dict[str, Any]:
        """
        构造模型红队报告任务。

        对已知模型 endpoint 执行规模化 prompt 攻击测试，
        输出 ASR（Attack Success Rate）等量化指标。
        """
        models: List[Dict[str, Any]] = []

        for ep in self.profile.fingerprint.llm_api_endpoints:
            model_entry: Dict[str, Any] = {
                "model": ep.get("model_name") or self.profile.fingerprint.model_name or "unknown",
                "base_url": ep.get("url", ""),
            }
            # 如果 endpoint 元数据里有 API key/token，从 Vault 读取后注入
            auth = self._first_extracted_auth()
            if auth:
                model_entry["token"] = auth.get("token", "")
            models.append(model_entry)

        # 兜底：即使没有 endpoint，也尝试用目标 URL 作为 base_url
        if not models:
            models.append({
                "model": self.profile.fingerprint.model_name or "unknown",
                "base_url": self.profile.target,
            })

        content: Dict[str, Any] = {
            "model": models,
            "target": self.profile.target,
        }

        return {
            "type": "model_redteam_report",
            "content": content,
        }

    def build_mcp_scan(self) -> Dict[str, Any]:
        """
        构造 MCP Server 扫描任务。

        当 Profile 中发现 MCP Server URL 或相关配置时触发。
        """
        mcp_urls = self._collect_mcp_urls()

        content: Dict[str, Any] = {
            "prompt": mcp_urls[0] if mcp_urls else self.profile.target,
            "target": self.profile.target,
        }

        return {
            "type": "mcp_scan",
            "content": content,
        }

    # ------------------- 内部辅助方法 -------------------

    def _collect_targets(self) -> List[str]:
        """收集目标主机列表，去重"""
        targets: List[str] = []

        # 主目标域名
        if self.profile.target:
            targets.append(self.profile.target)

        # 从指纹中提取域名
        if self.profile.fingerprint.domain:
            targets.append(self.profile.fingerprint.domain)

        # 从 API endpoint 中提取主机
        for ep in self.profile.fingerprint.llm_api_endpoints:
            url = ep.get("url", "")
            if url and url not in targets:
                targets.append(url)

        return targets

    def _first_api_endpoint(self) -> str:
        """返回第一个 LLM API endpoint 的 URL"""
        endpoints = self.profile.fingerprint.llm_api_endpoints
        if endpoints:
            return endpoints[0].get("url", "")
        return ""

    def _collect_mcp_urls(self) -> List[str]:
        """从 agent_features 中提取 MCP Server URL"""
        urls: List[str] = []
        for feat in self.profile.fingerprint.agent_features:
            mcp_url = feat.get("mcp_server_url") or feat.get("url", "")
            if mcp_url and mcp_url not in urls:
                urls.append(mcp_url)
        return urls

    def _has_agent_signal(self) -> bool:
        """判断是否检测到 Agent / Copilot / 对话型 Web UI 信号"""
        features = self.profile.fingerprint.agent_features
        llm_features = self.profile.fingerprint.llm_features

        # 显式 Agent 特征
        if features:
            return True

        # LLM 特征中带有 agent/copilot/chat 字样
        for f in llm_features:
            if any(k in f.lower() for k in ("agent", "copilot", "chat")):
                return True

        # 目标类型为 spa 或 web_ui 且存在聊天入口
        if self.profile.target_type in ("spa", "web_ui") and self.profile.entry_points:
            return True

        return False

    def _has_model_signal(self) -> bool:
        """判断是否具备模型红队测试条件"""
        return bool(
            self.profile.fingerprint.llm_api_endpoints
            or self.profile.fingerprint.model_name
            or self.profile.fingerprint.model_family
        )

    def _has_mcp_signal(self) -> bool:
        """判断是否检测到 MCP Server 信号"""
        if self._collect_mcp_urls():
            return True
        for feat in self.profile.fingerprint.agent_features:
            if feat.get("type", "").lower() == "mcp":
                return True
            if "mcp" in str(feat).lower():
                return True
        return False

    def _infer_agent_provider(self) -> str:
        """根据模型族/提供商推断 Agent provider 类型"""
        family = (self.profile.fingerprint.model_family or "").lower()
        provider = (self.profile.fingerprint.provider or "").lower()

        # 常见映射
        if provider in ("openai", "azure_openai"):
            return "openai"
        if family in ("qwen", "tongyi"):
            return "openai"  # 通义千问通常提供 OpenAI 兼容接口
        if "dify" in provider:
            return "dify"
        if "fastgpt" in provider:
            return "fastgpt"

        return "http"

    def _first_extracted_auth(self) -> Optional[Dict[str, str]]:
        """返回第一个可用的认证凭据（token/api_key）"""
        for cred in self.profile.fingerprint.extracted_credentials:
            ctype = cred.get("type", "").lower()
            if ctype in ("bearer", "jwt", "api_key", "token"):
                return {
                    "type": ctype,
                    "token": cred.get("value", ""),
                }
        return None
