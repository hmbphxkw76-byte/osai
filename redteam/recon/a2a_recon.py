"""A2A 协议侦察（AI-300 Ch2.1/Ch2.3 Agent-to-Agent Protocol）。

实现 AI-300 课程中的 A2A 协议侦察技术，专门针对 Agent 侦察：
  - A2A 端点发现：探测 /.a2a/agent-card 等标准路径
  - Agent Card 提取：获取 Agent 能力描述、权限声明
  - 信任关系映射：识别 Agent 之间的信任链
  - 能力枚举：收集 Agent 支持的任务类型

A2A (Agent-to-Agent) 协议支持 Agent 之间的协作，
暴露能力发现和信任关系。

对齐 OWASP LLM Top 10: LLM06 (Excessive Agency)
"""
from __future__ import annotations

from typing import Any

import httpx

from redteam.core.models import AuthContext


def probe_a2a_endpoint(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 A2A (Agent-to-Agent) 端点（AI-300 Ch2.1）。

    A2A 协议支持 Agent 之间的协作，暴露能力发现和信任关系。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        A2A 端点信息和 Agent 能力列表
    """
    results = {
        "target": target,
        "a2a_detected": False,
        "agent_card": {},
        "capabilities": [],
        "trust_relationships": [],
        "endpoints_tested": [],
    }

    a2a_endpoints = [
        "/.a2a/agent-card",
        "/a2a/agent-card",
        "/api/a2a/agent-card",
        "/agent-card",
        "/.well-known/a2a/agent-card",
    ]

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        headers = auth.to_header_dict() if auth else {}

        for endpoint in a2a_endpoints:
            url = target.rstrip("/") + endpoint
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    results["a2a_detected"] = True
                    try:
                        data = resp.json()
                        results["agent_card"] = data
                        if "capabilities" in data:
                            results["capabilities"] = data.get("capabilities", [])
                        if "trusts" in data:
                            results["trust_relationships"] = data.get("trusts", [])
                    except Exception:
                        pass
            except Exception:
                continue

    return results


def enumerate_agent_capabilities(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """枚举 Agent 能力（AI-300 Ch2.3）。

    深入分析 Agent Card，提取：
      - 支持的任务类型
      - 可调用的工具
      - 权限级别
      - 信任的其他 Agent

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 单请求超时（秒）

    Returns:
        Agent 能力详情
    """
    a2a_info = probe_a2a_endpoint(target, auth, timeout)

    capabilities_detail = {
        "target": target,
        "agent_name": "",
        "agent_description": "",
        "supported_tasks": [],
        "available_tools": [],
        "permission_level": "",
        "trusted_agents": [],
        "excessive_permissions_detected": False,
    }

    agent_card = a2a_info.get("agent_card", {})
    if agent_card:
        capabilities_detail["agent_name"] = agent_card.get("name", "")
        capabilities_detail["agent_description"] = agent_card.get("description", "")

        capabilities = agent_card.get("capabilities", [])
        capabilities_detail["supported_tasks"] = capabilities

        # 提取权限信息
        permissions = agent_card.get("permissions", [])
        if permissions:
            capabilities_detail["permission_level"] = ", ".join(permissions)
            # 检测过度授权
            dangerous_perms = {"*", "admin", "root", "all_access", "override"}
            if any(p in dangerous_perms for p in permissions):
                capabilities_detail["excessive_permissions_detected"] = True

        # 提取工具列表
        tools = agent_card.get("tools", [])
        capabilities_detail["available_tools"] = tools

        # 提取信任关系
        trusts = agent_card.get("trusts", [])
        capabilities_detail["trusted_agents"] = trusts

    return capabilities_detail


def map_trust_relationships(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
    max_depth: int = 2,
) -> dict[str, Any]:
    """映射 Agent 之间的信任关系（AI-300 Ch2.3）。

    通过递归探测多个 Agent 的 A2A 端点，构建信任关系图。
    这有助于识别跨 Agent 攻击路径。

    Args:
        target: 起始 Agent URL
        auth: 认证上下文
        timeout: 单请求超时（秒）
        max_depth: 递归深度

    Returns:
        信任关系图
    """
    trust_graph: dict[str, Any] = {
        "root_agent": target,
        "nodes": [],
        "edges": [],
        "visited": set(),
    }

    def _probe_recursive(url: str, depth: int) -> None:
        if depth > max_depth or url in trust_graph["visited"]:
            return

        trust_graph["visited"].add(url)

        a2a_info = probe_a2a_endpoint(url, auth, timeout)
        if not a2a_info["a2a_detected"]:
            return

        agent_card = a2a_info["agent_card"]
        agent_name = agent_card.get("name", url)

        trust_graph["nodes"].append({
            "url": url,
            "name": agent_name,
            "capabilities": agent_card.get("capabilities", []),
            "permissions": agent_card.get("permissions", []),
        })

        # 探测信任的 Agent
        trusts = agent_card.get("trusts", [])
        for trusted in trusts:
            if isinstance(trusted, dict):
                trusted_url = trusted.get("url", "")
            elif isinstance(trusted, str):
                trusted_url = trusted
            else:
                continue

            if trusted_url:
                trust_graph["edges"].append({
                    "from": url,
                    "to": trusted_url,
                    "trust_type": trusted.get("type", "unknown") if isinstance(trusted, dict) else "unknown",
                })
                _probe_recursive(trusted_url, depth + 1)

    _probe_recursive(target, 0)

    # 移除 visited 集合（不可序列化）
    trust_graph["visited"] = list(trust_graph["visited"])

    return trust_graph


__all__ = [
    "probe_a2a_endpoint",
    "enumerate_agent_capabilities",
    "map_trust_relationships",
]