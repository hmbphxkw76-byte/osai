# -*- coding: utf-8 -*-
"""
AI-300 Framework - Protocol Interfaces (L5)
分层解耦：基于 typing.Protocol 的接口定义

L5 最佳实践：
1. 依赖反转：高层模块依赖 Protocol 接口，不依赖具体实现
2. 结构化子类型（Structural Subtyping）：鸭子类型 + 静态检查
3. 接口隔离：每个 Protocol 只定义最小必要方法集
4. 可替换性：任何满足 Protocol 的类都可注入，便于测试和扩展

Usage:
    # 在消费方（如 AttackOrchestrator）中声明依赖：
    def __init__(self, recon_engine: ReconEngineProtocol):
        ...

    # 测试时可注入任意满足 Protocol 的 Mock：
    class MockReconEngine:
        def run(self, target, tools=None):
            return TargetProfile()
"""

from __future__ import annotations

from typing import Any, Dict, Generator, List, Optional, Protocol, runtime_checkable

# ──────────────────────────────────────────────────────────────────────────────
# 侦察层接口
# ──────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class ReconEngineProtocol(Protocol):
    """侦察引擎接口"""

    def run(
        self,
        target: str,
        tools: Optional[List[str]] = None,
        depth: str = "standard",
        tracker: Optional[Any] = None,
        use_cache: Optional[bool] = None,
    ) -> Any:
        """执行侦察，返回 TargetProfile"""
        ...

    def run_streaming(
        self,
        target: str,
        tools: Optional[List[str]] = None,
        depth: str = "standard",
    ) -> Generator[tuple, None, None]:
        """流式侦察，逐步产出部分画像"""
        ...


@runtime_checkable
class ProfileMergerProtocol(Protocol):
    """画像合并器接口"""

    def merge(self, target: str, results: List[Any], depth: str = "standard") -> Any:
        """合并多个适配器结果为 TargetProfile"""
        ...

    def merge_incremental(
        self,
        target: str,
        existing_profile: Optional[Any],
        new_result: Any,
        depth: str = "standard",
    ) -> Any:
        """增量合并"""
        ...


@runtime_checkable
class BaseAdapterProtocol(Protocol):
    """侦察适配器接口"""

    @property
    def name(self) -> str:
        """工具名称标识"""
        ...

    def run(self, target: str, config: dict) -> Any:
        """执行侦察，返回 AdapterResult"""
        ...

    def check_available(self) -> bool:
        """检查工具是否可用"""
        ...


# ──────────────────────────────────────────────────────────────────────────────
# 攻击层接口
# ──────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class AttackOrchestratorProtocol(Protocol):
    """攻击编排器接口"""

    def execute_attacks(
        self,
        attacks: List[Dict[str, Any]],
        target: Any,
        scorers: Optional[List[Any]] = None,
        tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """执行攻击配置列表"""
        ...


@runtime_checkable
class SmartMatcherProtocol(Protocol):
    """智能策略匹配器接口"""

    def select_strategy(self, profile: Any, **kwargs: Any) -> Dict[str, Any]:
        """选择攻击策略"""
        ...

    def build_attack_plan(
        self,
        payloads: List[Any],
        converter_presets: Dict[str, List[str]],
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """构建攻击计划"""
        ...


@runtime_checkable
class ConverterBuilderProtocol(Protocol):
    """转换器构建器接口"""

    def build(
        self,
        converter_configs: List[Dict[str, Any]],
        converter_target: Optional[Any] = None,
        target_type: str = "",
    ) -> List[Any]:
        """构建转换器列表"""
        ...


@runtime_checkable
class ScorerBuilderProtocol(Protocol):
    """评分器构建器接口"""

    def build(
        self,
        scorer_configs: List[Dict[str, Any]],
        objective_target: Optional[Any] = None,
        asi_category: str = "",
        **kwargs: Any,
    ) -> List[Any]:
        """构建评分器列表"""
        ...


# ──────────────────────────────────────────────────────────────────────────────
# 流水线层接口
# ──────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class PipelineOrchestratorProtocol(Protocol):
    """流水线编排器接口"""

    def run(
        self,
        target_url: Optional[str] = None,
        spa_config: Optional[str] = None,
        attacks_file: Optional[str] = None,
        profile_path: Optional[str] = None,
        auto_recon: bool = False,
        phases: Optional[List[str]] = None,
    ) -> Any:
        """执行完整流水线"""
        ...


@runtime_checkable
class CredentialManagerProtocol(Protocol):
    """凭据管理器接口"""

    def resolve(self, target_url: str) -> Any:
        """解析目标 URL 的凭据"""
        ...


# ──────────────────────────────────────────────────────────────────────────────
# 速率控制接口
# ──────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class RateControllerProtocol(Protocol):
    """速率控制器接口"""

    @property
    def concurrency(self) -> int:
        """当前并发数"""
        ...

    async def acquire(self) -> None:
        """获取执行许可"""
        ...

    def release(self) -> None:
        """释放执行许可"""
        ...
