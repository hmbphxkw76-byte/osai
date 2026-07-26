"""
Registry Manager
================

PyRIT 1.0.0 Registry 统一管理器（L5 Expert Level）。

本模块是 PyRIT 原生 Registry 体系的适配层（Facade），统一管理 6 大领域注册表：
- ScorerRegistry     → 评分器类目录 + 预配置实例
- TargetRegistry     → 目标类目录 + 预配置实例
- ConverterRegistry  → 转换器类目录 + 预配置实例
- AttackTechniqueRegistry → 攻击技术工厂实例
- ScenarioRegistry   → 场景类目录
- InitializerRegistry → 初始化器类目录

核心能力：
1. 类目录操作：list_classes / get_class_metadata / list_all_metadata / create_instance
2. 实例注册表操作：register_instance / get_instance / list_instances / list_instance_metadata
3. 标签查询：query_by_tags / get_by_tag / find_dependents
4. 引用解析：resolve_reference（字符串名 → 实例查找）
5. 元数据过滤：include_filters / exclude_filters（AND 逻辑）
6. 容器协议：__contains__ / __len__ / __iter__

设计原则：
- 原生优先：委托 PyRIT 原生 Registry，不重新实现发现/验证/解析逻辑
- 懒发现：注册表创建时不触发重导入，首次访问时才执行子类枚举
- 验证前置：register_class 时验证构造函数可内省且引用参数可解析
- 名称引用：用字符串名引用其他注册表中的实例（如 chat_target="openai_chat"）
- 元数据投影：is_llm_based / supported_auth_modes 从参数契约派生，不手动维护
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# ============================================================
# 域标识常量
# ============================================================

DOMAIN_SCORER = "scorer"
DOMAIN_TARGET = "target"
DOMAIN_CONVERTER = "converter"
DOMAIN_TECHNIQUE = "technique"
DOMAIN_SCENARIO = "scenario"
DOMAIN_INITIALIZER = "initializer"

_ALL_DOMAINS = (
    DOMAIN_SCORER,
    DOMAIN_TARGET,
    DOMAIN_CONVERTER,
    DOMAIN_TECHNIQUE,
    DOMAIN_SCENARIO,
    DOMAIN_INITIALIZER,
)


class RegistryManager:
    """
    PyRIT 1.0.0 Registry 统一管理器

    作为 6 大领域注册表的 Facade，提供统一的类目录查询、实例注册、
    标签过滤和引用解析接口。

    用法示例::

        manager = RegistryManager()

        # 类目录操作
        scorer_names = manager.list_classes("scorer")
        metadata = manager.get_class_metadata("scorer", "SelfAskRefusalScorer")

        # 实例注册
        from pyrit.prompt_target import OpenAIChatTarget
        from pyrit.score import SelfAskRefusalScorer

        target = OpenAIChatTarget()
        manager.register_target_instance(target, name="judge_target", tags=["judge"])

        scorer = SelfAskRefusalScorer(chat_target=target)
        manager.register_scorer_instance(scorer, name="refusal_scorer", tags=["refusal"])

        # 标签查询
        from pyrit.registry import TagQuery
        q = TagQuery.all("refusal")
        results = manager.query_by_tags("scorer", q)

        # 引用解析
        resolved = manager.resolve_reference("target", "judge_target")
    """

    def __init__(self) -> None:
        """初始化注册表管理器（不立即触发发现）。"""
        self._registry_cache: Dict[str, Any] = {}

    # ============================================================
    # 内部：获取原生注册表单例
    # ============================================================

    def _get_registry(self, domain: str) -> Any:
        """
        获取指定域的原生注册表单例

        Args:
            domain: 域名（DOMAIN_SCORER / DOMAIN_TARGET / ...）

        Returns:
            PyRIT 原生 Registry 单例

        Raises:
            ValueError: 如果域名未知
        """
        if domain in self._registry_cache:
            return self._registry_cache[domain]

        if domain == DOMAIN_SCORER:
            from pyrit.registry import ScorerRegistry
            registry = ScorerRegistry.get_registry_singleton()
        elif domain == DOMAIN_TARGET:
            from pyrit.registry import TargetRegistry
            registry = TargetRegistry.get_registry_singleton()
        elif domain == DOMAIN_CONVERTER:
            from pyrit.registry import ConverterRegistry
            registry = ConverterRegistry.get_registry_singleton()
        elif domain == DOMAIN_TECHNIQUE:
            from pyrit.registry import AttackTechniqueRegistry
            registry = AttackTechniqueRegistry.get_registry_singleton()
        elif domain == DOMAIN_SCENARIO:
            from pyrit.registry import ScenarioRegistry
            registry = ScenarioRegistry.get_registry_singleton()
        elif domain == DOMAIN_INITIALIZER:
            from pyrit.registry import InitializerRegistry
            registry = InitializerRegistry.get_registry_singleton()
        else:
            raise ValueError(
                f"未知的注册表域: {domain}. 可用: {_ALL_DOMAINS}"
            )

        self._registry_cache[domain] = registry
        return registry

    def _ensure_has_instances(self, domain: str) -> bool:
        """检查域注册表是否持有实例容器（.instances 属性）。"""
        registry = self._get_registry(domain)
        return hasattr(registry, "instances")

    # ============================================================
    # 类目录操作
    # ============================================================

    def list_classes(self, domain: str) -> List[str]:
        """
        列出指定域的所有已注册类名

        Args:
            domain: 域名

        Returns:
            排序后的类名列表
        """
        registry = self._get_registry(domain)
        return registry.get_class_names()

    def get_class(self, domain: str, name: str) -> Any:
        """
        按名获取已注册的类（返回类本身，非实例）

        Args:
            domain: 域名
            name: 注册名

        Returns:
            类对象

        Raises:
            KeyError: 如果名称未注册
        """
        registry = self._get_registry(domain)
        return registry.get_class(name)

    def get_class_metadata(self, domain: str, name: str) -> Optional[Dict[str, Any]]:
        """
        获取指定类的元数据

        Args:
            domain: 域名
            name: 注册名

        Returns:
            元数据字典，包含 class_name / class_module / class_description /
            registry_name / parameters / class_attributes 等。
            对于 ScorerMetadata 额外包含 is_llm_based；
            对于 TargetMetadata 额外包含 supported_auth_modes；
            对于 ConverterMetadata 额外包含 supported_input_types /
            supported_output_types / is_llm_based。
            如果未找到则返回 None。
        """
        registry = self._get_registry(domain)
        metadata = registry.get_registered_class_metadata(name)
        if metadata is None:
            return None
        return self._metadata_to_dict(metadata)

    def list_all_metadata(
        self,
        domain: str,
        *,
        include_filters: Optional[Dict[str, Any]] = None,
        exclude_filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        列出指定域所有已注册类的元数据（支持过滤）

        过滤规则：
        - 简单类型（str/int/bool）：精确匹配
        - 序列类型（list/tuple）：成员检查
        - include_filters：ALL 必须匹配（AND 逻辑）
        - exclude_filters：ANY 匹配即排除

        Args:
            domain: 域名
            include_filters: 必须全部匹配的过滤条件
            exclude_filters: 匹配任一即排除的过滤条件

        Returns:
            元数据字典列表
        """
        registry = self._get_registry(domain)
        metadata_list = registry.get_all_registered_class_metadata(
            include_filters=include_filters,
            exclude_filters=exclude_filters,
        )
        return [self._metadata_to_dict(m) for m in metadata_list]

    def create_instance(self, domain: str, name: str, **kwargs: Any) -> Any:
        """
        按类名构建配置实例

        通过 resolve_constructor_args 解析参数：
- 引用参数（如 chat_target）可用字符串名引用其他注册表中的实例
        - 字符串值自动强制转换（"true" → True, "42" → 42）

        Args:
            domain: 域名
            name: 注册名
            **kwargs: 构造参数

        Returns:
            构造的实例

        Raises:
            KeyError: 如果名称未注册
            ValueError: 如果参数无效或引用无法解析
        """
        registry = self._get_registry(domain)
        return registry.create_instance(name, **kwargs)

    def has_class(self, domain: str, name: str) -> bool:
        """检查类名是否已注册。"""
        registry = self._get_registry(domain)
        return name in registry

    def class_count(self, domain: str) -> int:
        """获取已注册类数量。"""
        registry = self._get_registry(domain)
        return len(registry)

    # ============================================================
    # 实例注册表操作
    # ============================================================

    def register_instance(
        self,
        domain: str,
        instance: Any,
        *,
        name: Optional[str] = None,
        tags: Optional[Union[Dict[str, str], List[str]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        注册预配置实例到指定域的实例注册表

        实例必须实现 Identifiable 接口（具有 get_identifier() 方法）。
        如果未提供 name，则使用实例的 unique_name。

        Args:
            domain: 域名
            instance: 要注册的实例
            name: 注册名（None 则使用实例的 unique_name）
            tags: 标签（dict[str, str] 或 list[str]）
            metadata: 额外元数据

        Returns:
            注册名

        Raises:
            ValueError: 如果域不支持实例注册
            TypeError: 如果实例类型与域不匹配
        """
        if not self._ensure_has_instances(domain):
            raise ValueError(f"域 '{domain}' 不支持实例注册表")
        registry = self._get_registry(domain)
        registry.instances.register(
            instance,
            name=name,
            tags=tags,
            metadata=metadata,
        )
        registered_name = name or instance.get_identifier().unique_name
        logger.debug(f"注册 {domain} 实例: {registered_name}")
        return registered_name

    def get_instance(self, domain: str, name: str) -> Optional[Any]:
        """
        按名获取预配置实例

        Args:
            domain: 域名
            name: 注册名

        Returns:
            实例对象，如果未找到则返回 None
        """
        if not self._ensure_has_instances(domain):
            return None
        registry = self._get_registry(domain)
        return registry.instances.get(name)

    def list_instances(self, domain: str) -> List[str]:
        """
        列出指定域所有已注册实例名

        Args:
            domain: 域名

        Returns:
            排序后的实例名列表
        """
        if not self._ensure_has_instances(domain):
            return []
        registry = self._get_registry(domain)
        return registry.instances.get_names()

    def list_instance_metadata(
        self,
        domain: str,
        *,
        include_filters: Optional[Dict[str, Any]] = None,
        exclude_filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        列出指定域所有已注册实例的元数据（支持过滤）

        元数据来自实例的 ComponentIdentifier，包含：
        - class_name / scorer_type / score_aggregator / model_name 等
        - eval_hash（身份哈希）

        Args:
            domain: 域名
            include_filters: 必须全部匹配的过滤条件
            exclude_filters: 匹配任一即排除的过滤条件

        Returns:
            实例元数据字典列表
        """
        if not self._ensure_has_instances(domain):
            return []
        registry = self._get_registry(domain)
        identifiers = registry.instances.list_metadata(
            include_filters=include_filters,
            exclude_filters=exclude_filters,
        )
        return [self._identifier_to_dict(identifier) for identifier in identifiers]

    def has_instance(self, domain: str, name: str) -> bool:
        """检查实例名是否已注册。"""
        if not self._ensure_has_instances(domain):
            return False
        registry = self._get_registry(domain)
        return name in registry.instances

    def instance_count(self, domain: str) -> int:
        """获取已注册实例数量。"""
        if not self._ensure_has_instances(domain):
            return 0
        registry = self._get_registry(domain)
        return len(registry.instances)

    # ============================================================
    # 标签查询
    # ============================================================

    def get_by_tag(
        self,
        domain: str,
        tag: str,
        value: Optional[str] = None,
    ) -> List[Any]:
        """
        按标签获取实例

        Args:
            domain: 域名
            tag: 标签键
            value: 标签值（None 则匹配任意值）

        Returns:
            实例列表（按名排序）
        """
        if not self._ensure_has_instances(domain):
            return []
        registry = self._get_registry(domain)
        entries = registry.instances.get_by_tag(tag=tag, value=value)
        return [entry.instance for entry in entries]

    def query_by_tags(self, domain: str, query: Any) -> List[Any]:
        """
        使用 TagQuery 组合谓词查询实例

        Args:
            domain: 域名
            query: TagQuery 对象

        Returns:
            匹配的实例列表（按名排序）

        Example:
            >>> from pyrit.registry import TagQuery
            >>> q = TagQuery.all("core") & TagQuery.any_of("fast", "cheap")
            >>> results = manager.query_by_tags("scorer", q)
        """
        if not self._ensure_has_instances(domain):
            return []
        registry = self._get_registry(domain)
        entries = registry.instances.query_by_tags(query=query)
        return [entry.instance for entry in entries]

    def add_tags(
        self,
        domain: str,
        name: str,
        tags: Union[Dict[str, str], List[str]],
    ) -> None:
        """
        向已注册实例添加标签

        Args:
            domain: 域名
            name: 实例名
            tags: 要添加的标签

        Raises:
            KeyError: 如果实例名不存在
        """
        if not self._ensure_has_instances(domain):
            raise ValueError(f"域 '{domain}' 不支持实例注册表")
        registry = self._get_registry(domain)
        registry.instances.add_tags(name=name, tags=tags)

    def find_dependents(
        self,
        domain: str,
        tag: str,
    ) -> List[Any]:
        """
        发现依赖指定标签的实例

        扫描每个实例的 ComponentIdentifier 树，检查是否有子节点的
        eval_hash 匹配携带指定标签的实例。

        典型用途：标记基础评分器后，自动发现所有包装器（Inverter、Composite）。

        Args:
            domain: 域名
            tag: 标识"基础"实例的标签键

        Returns:
            依赖指定标签的实例列表（按名排序）
        """
        if not self._ensure_has_instances(domain):
            return []
        registry = self._get_registry(domain)
        entries = registry.instances.find_dependents_of_tag(tag=tag)
        return [entry.instance for entry in entries]

    # ============================================================
    # 引用解析
    # ============================================================

    def resolve_reference(
        self,
        component_type: str,
        name: str,
    ) -> Any:
        """
        解析注册表引用（字符串名 → 实例查找）

        将组件类型和名称解析为预配置实例。
        这是 PyRIT 1.0.0 resolve_constructor_args 的公共封装。

        Args:
            component_type: 组件类型（"target" / "converter" / "scorer"）
            name: 注册名

        Returns:
            解析的实例

        Raises:
            ValueError: 如果类型不支持或名称未注册
        """
        from pyrit.models.parameter import ComponentType
        from pyrit.registry.resolution import resolve_reference_value

        type_map = {
            "target": ComponentType.TARGET,
            "converter": ComponentType.CONVERTER,
            "scorer": ComponentType.SCORER,
        }

        ct = type_map.get(component_type.lower())
        if ct is None:
            raise ValueError(
                f"不支持的组件类型: {component_type}. 可用: {list(type_map.keys())}"
            )

        return resolve_reference_value(
            component_type=ct,
            value=name,
            owner="RegistryManager",
            name=component_type,
        )

    # ============================================================
    # 便捷方法：Scorer 实例注册
    # ============================================================

    def register_scorer_instance(
        self,
        scorer: Any,
        *,
        name: Optional[str] = None,
        tags: Optional[Union[Dict[str, str], List[str]]] = None,
    ) -> str:
        """注册预配置 Scorer 实例。"""
        return self.register_instance(DOMAIN_SCORER, scorer, name=name, tags=tags)

    def get_scorer_instance(self, name: str) -> Optional[Any]:
        """按名获取预配置 Scorer 实例。"""
        return self.get_instance(DOMAIN_SCORER, name)

    def list_scorer_instances(self) -> List[str]:
        """列出所有已注册的 Scorer 实例名。"""
        return self.list_instances(DOMAIN_SCORER)

    # ============================================================
    # 便捷方法：Target 实例注册
    # ============================================================

    def register_target_instance(
        self,
        target: Any,
        *,
        name: Optional[str] = None,
        tags: Optional[Union[Dict[str, str], List[str]]] = None,
    ) -> str:
        """注册预配置 Target 实例。"""
        return self.register_instance(DOMAIN_TARGET, target, name=name, tags=tags)

    def get_target_instance(self, name: str) -> Optional[Any]:
        """按名获取预配置 Target 实例。"""
        return self.get_instance(DOMAIN_TARGET, name)

    def list_target_instances(self) -> List[str]:
        """列出所有已注册的 Target 实例名。"""
        return self.list_instances(DOMAIN_TARGET)

    # ============================================================
    # 便捷方法：Converter 实例注册
    # ============================================================

    def register_converter_instance(
        self,
        converter: Any,
        *,
        name: Optional[str] = None,
        tags: Optional[Union[Dict[str, str], List[str]]] = None,
    ) -> str:
        """注册预配置 Converter 实例。"""
        return self.register_instance(DOMAIN_CONVERTER, converter, name=name, tags=tags)

    def get_converter_instance(self, name: str) -> Optional[Any]:
        """按名获取预配置 Converter 实例。"""
        return self.get_instance(DOMAIN_CONVERTER, name)

    def list_converter_instances(self) -> List[str]:
        """列出所有已注册的 Converter 实例名。"""
        return self.list_instances(DOMAIN_CONVERTER)

    # ============================================================
    # 便捷方法：元数据查询
    # ============================================================

    def list_llm_scorers(self) -> List[Dict[str, Any]]:
        """列出所有需要 LLM 目标的 Scorer 类。"""
        return self.list_all_metadata(
            DOMAIN_SCORER,
            include_filters={"is_llm_based": True},
        )

    def list_non_llm_scorers(self) -> List[Dict[str, Any]]:
        """列出所有不需要 LLM 目标的 Scorer 类。"""
        return self.list_all_metadata(
            DOMAIN_SCORER,
            include_filters={"is_llm_based": False},
        )

    def list_targets_by_auth_mode(self, auth_mode: str) -> List[Dict[str, Any]]:
        """按认证模式过滤 Target 类。"""
        return self.list_all_metadata(
            DOMAIN_TARGET,
            include_filters={"supported_auth_modes": auth_mode},
        )

    def list_converters_by_input_type(self, input_type: str) -> List[Dict[str, Any]]:
        """按输入类型过滤 Converter 类。"""
        return self.list_all_metadata(
            DOMAIN_CONVERTER,
            include_filters={"supported_input_types": input_type},
        )

    # ============================================================
    # 容器协议（代理到指定域）
    # ============================================================

    def __contains__(self, domain: str) -> bool:
        """检查域是否受管理。"""
        return domain in _ALL_DOMAINS

    def __len__(self) -> int:
        """返回受管理的域数量。"""
        return len(_ALL_DOMAINS)

    def __iter__(self):
        """迭代受管理的域名。"""
        return iter(_ALL_DOMAINS)

    # ============================================================
    # 内部：元数据转换
    # ============================================================

    @staticmethod
    def _metadata_to_dict(metadata: Any) -> Dict[str, Any]:
        """将 RegistryMetadata dataclass 转换为字典。"""
        result: Dict[str, Any] = {
            "class_name": metadata.class_name,
            "class_module": metadata.class_module,
            "class_description": metadata.class_description,
            "registry_name": metadata.registry_name,
        }

        # 参数契约
        if hasattr(metadata, "parameters"):
            params = []
            for param in metadata.parameters:
                param_dict: Dict[str, Any] = {
                    "name": param.name,
                    "description": param.description,
                    "default": param.default if param.default is not None else None,
                }
                if param.param_type is not None:
                    param_dict["param_type"] = str(param.param_type)
                if param.reference is not None:
                    param_dict["reference"] = str(param.reference.component_type)
                params.append(param_dict)
            result["parameters"] = params

        # 类属性
        if hasattr(metadata, "class_attributes"):
            result["class_attributes"] = dict(metadata.class_attributes)

        # 域特化投影属性
        if hasattr(metadata, "is_llm_based"):
            result["is_llm_based"] = metadata.is_llm_based
        if hasattr(metadata, "supported_auth_modes"):
            result["supported_auth_modes"] = list(metadata.supported_auth_modes)
        if hasattr(metadata, "supported_input_types"):
            result["supported_input_types"] = list(metadata.supported_input_types)
        if hasattr(metadata, "supported_output_types"):
            result["supported_output_types"] = list(metadata.supported_output_types)
        if hasattr(metadata, "default_technique"):
            result["default_technique"] = metadata.default_technique
        if hasattr(metadata, "all_techniques"):
            result["all_techniques"] = list(metadata.all_techniques)
        if hasattr(metadata, "default_datasets"):
            result["default_datasets"] = list(metadata.default_datasets)
        if hasattr(metadata, "required_env_vars"):
            result["required_env_vars"] = list(metadata.required_env_vars)

        return result

    @staticmethod
    def _identifier_to_dict(identifier: Any) -> Dict[str, Any]:
        """将 ComponentIdentifier 转换为字典。"""
        result: Dict[str, Any] = {
            "unique_name": identifier.unique_name,
            "class_name": identifier.__class__.__name__,
        }

        # eval_hash
        if hasattr(identifier, "eval_hash") and identifier.eval_hash:
            result["eval_hash"] = identifier.eval_hash

        # params（ComponentIdentifier 携带的参数）
        params = getattr(identifier, "params", None)
        if isinstance(params, dict):
            for key, value in params.items():
                # 只序列化简单类型
                if isinstance(value, (str, int, float, bool)):
                    result[key] = value
                elif isinstance(value, (list, tuple)):
                    result[key] = list(value)

        return result


# ============================================================
# 模块级单例
# ============================================================

_registry_manager: Optional[RegistryManager] = None


def get_registry_manager() -> RegistryManager:
    """
    获取 RegistryManager 单例

    Returns:
        RegistryManager 实例
    """
    global _registry_manager
    if _registry_manager is None:
        _registry_manager = RegistryManager()
    return _registry_manager


def reset_registry_manager() -> None:
    """重置 RegistryManager 单例（用于测试）。"""
    global _registry_manager
    _registry_manager = None
