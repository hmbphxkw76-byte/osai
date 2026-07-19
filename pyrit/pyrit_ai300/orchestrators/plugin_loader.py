# -*- coding: utf-8 -*-
"""
AI-300 Framework - Plugin Loader v1.0
插件加载器：动态加载第三方转换器/评分器/目标适配器

职责：
- 从 Python entry points 加载第三方组件
- 从 plugins/ 目录动态加载 Python 模块
- 从配置文件注册自定义组件
- 合并到 component_registry 的 CONVERTER_MAP / SCORER_MAP

设计原则：
- 插件注册是可选的，不影响核心功能
- 插件加载失败只记录警告，不中断主流程
- 支持热加载（运行时动态注册）

使用方式：
    from .plugin_loader import PluginLoader
    loader = PluginLoader()
    loader.load_all()
    # 之后 component_registry 的映射表已包含第三方组件

    # 手动注册
    loader.register_converter("my_custom_converter", MyConverterClass)
    loader.register_scorer("my_custom_scorer", MyScorerClass)

PyRIT 0.14.0 兼容
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 插件配置 schema
# ──────────────────────────────────────────────────────────────────────────────

# entry point 组名（遵循 Python 打包规范）
CONVERTER_ENTRY_POINT_GROUP = "pyrit_ai300.converters"
SCORER_ENTRY_POINT_GROUP = "pyrit_ai300.scorers"
TARGET_ENTRY_POINT_GROUP = "pyrit_ai300.targets"

# 插件目录（相对于项目根目录）
DEFAULT_PLUGIN_DIRS = ["plugins", "pyrit_ai300/plugins"]

# 插件配置文件名
PLUGIN_CONFIG_FILE = "plugin_config.yaml"


# ──────────────────────────────────────────────────────────────────────────────
# PluginLoader
# ──────────────────────────────────────────────────────────────────────────────

class PluginLoader:
    """
    插件加载器

    三层加载机制：
    1. Entry Points：通过 pip install 安装的第三方包自动注册
    2. Plugin Directories：从 plugins/ 目录加载 Python 文件
    3. Manual Registration：代码中手动调用 register_* 方法

    使用方式：
        loader = PluginLoader()
        loader.load_all()

        # 手动注册
        loader.register_converter("my_converter", MyConverter)
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Args:
            plugin_dirs: 插件目录列表（默认使用 DEFAULT_PLUGIN_DIRS）
        """
        self._plugin_dirs = plugin_dirs or list(DEFAULT_PLUGIN_DIRS)
        self._loaded_modules: Set[str] = set()
        self._registered_converters: Dict[str, Type] = {}
        self._registered_scorers: Dict[str, Type] = {}
        self._registered_targets: Dict[str, Type] = {}
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        """是否已加载"""
        return self._loaded

    @property
    def registered_converters(self) -> Dict[str, Type]:
        """已注册的转换器映射"""
        return dict(self._registered_converters)

    @property
    def registered_scorers(self) -> Dict[str, Type]:
        """已注册的评分器映射"""
        return dict(self._registered_scorers)

    @property
    def registered_targets(self) -> Dict[str, Type]:
        """已注册的目标映射"""
        return dict(self._registered_targets)

    # ── 主加载入口 ──

    def load_all(self) -> None:
        """
        执行全部加载流程

        顺序：
        1. 从 entry points 加载
        2. 从插件目录加载
        3. 合并到 component_registry
        """
        if self._loaded:
            logger.debug("Plugins already loaded, skipping")
            return

        logger.info("Loading plugins...")

        # 1. Entry points
        self._load_from_entry_points()

        # 2. Plugin directories
        for plugin_dir in self._plugin_dirs:
            self._load_from_directory(plugin_dir)

        # 3. 合并到 component_registry
        self._merge_to_registry()

        self._loaded = True

        total = len(self._registered_converters) + len(self._registered_scorers) + len(self._registered_targets)
        logger.info(
            "Plugins loaded: %d converters, %d scorers, %d targets",
            len(self._registered_converters),
            len(self._registered_scorers),
            len(self._registered_targets),
        )

    # ── Entry Points 加载 ──

    def _load_from_entry_points(self) -> None:
        """从 Python entry points 加载第三方组件"""
        try:
            # Python 3.10+ 使用 importlib.metadata
            from importlib.metadata import entry_points
        except ImportError:
            try:
                from importlib_metadata import entry_points
            except ImportError:
                logger.debug("importlib.metadata not available, skipping entry points")
                return

        for group, register_fn in [
            (CONVERTER_ENTRY_POINT_GROUP, self.register_converter),
            (SCORER_ENTRY_POINT_GROUP, self.register_scorer),
            (TARGET_ENTRY_POINT_GROUP, self.register_target),
        ]:
            try:
                # Python 3.12+ 返回SelectableGroups, 3.10返回dict
                try:
                    eps = entry_points(group=group)
                except TypeError:
                    eps = entry_points().get(group, [])

                for ep in eps:
                    try:
                        cls = ep.load()
                        name = ep.name
                        register_fn(name, cls)
                        logger.debug("Loaded entry point: %s.%s = %s", group, name, cls)
                    except Exception as e:
                        logger.warning("Failed to load entry point %s.%s: %s", group, ep.name, e)
            except Exception as e:
                logger.debug("No entry points found for group %s: %s", group, e)

    # ── 目录加载 ──

    def _load_from_directory(self, plugin_dir: str) -> None:
        """从目录加载插件模块"""
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            logger.debug("Plugin directory not found: %s", plugin_dir)
            return

        logger.debug("Scanning plugin directory: %s", plugin_dir)

        # 加载 YAML 配置文件
        config_file = plugin_path / PLUGIN_CONFIG_FILE
        if config_file.exists():
            self._load_from_config(config_file)

        # 加载 Python 文件
        for py_file in sorted(plugin_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            self._load_python_file(py_file)

    def _load_python_file(self, file_path: Path) -> None:
        """加载单个 Python 文件作为插件模块"""
        module_name = f"_pyrit_plugin_{file_path.stem}"

        if module_name in self._loaded_modules:
            return

        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None or spec.loader is None:
                logger.warning("Cannot load plugin file: %s", file_path)
                return

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            self._loaded_modules.add(module_name)

            # 自动发现：查找模块中带 register_ 前缀的属性
            self._auto_discover(module, file_path.stem)

            logger.debug("Loaded plugin file: %s", file_path.name)
        except Exception as e:
            logger.warning("Failed to load plugin file %s: %s", file_path, e)

    def _load_from_config(self, config_path: Path) -> None:
        """从 YAML 配置文件加载插件注册信息"""
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

            # 格式:
            # converters:
            #   my_converter: "module.path.ConverterClass"
            # scorers:
            #   my_scorer: "module.path.ScorerClass"

            for conv_name, class_path in (config.get("converters") or {}).items():
                cls = self._import_class(class_path)
                if cls:
                    self.register_converter(conv_name, cls)

            for scorer_name, class_path in (config.get("scorers") or {}).items():
                cls = self._import_class(class_path)
                if cls:
                    self.register_scorer(scorer_name, cls)

            for target_name, class_path in (config.get("targets") or {}).items():
                cls = self._import_class(class_path)
                if cls:
                    self.register_target(target_name, cls)

        except Exception as e:
            logger.warning("Failed to load plugin config %s: %s", config_path, e)

    def _auto_discover(self, module: Any, module_name: str) -> None:
        """自动发现模块中的转换器/评分器类"""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if not inspect.isclass(attr):
                continue

            # 检查类名后缀
            class_name = attr.__name__
            if class_name.endswith("Converter") and not class_name.startswith("_"):
                # 转换为 snake_case
                snake = self._to_snake_case(class_name)
                self.register_converter(snake, attr)
            elif class_name.endswith("Scorer") and not class_name.startswith("_"):
                snake = self._to_snake_case(class_name)
                self.register_scorer(snake, attr)
            elif class_name.endswith("Target") and not class_name.startswith("_"):
                snake = self._to_snake_case(class_name)
                self.register_target(snake, attr)

    # ── 手动注册 ──

    def register_converter(self, name: str, cls: Type) -> None:
        """注册自定义转换器"""
        self._registered_converters[name] = cls
        logger.debug("Registered converter: %s → %s", name, cls.__name__)

    def register_scorer(self, name: str, cls: Type) -> None:
        """注册自定义评分器"""
        self._registered_scorers[name] = cls
        logger.debug("Registered scorer: %s → %s", name, cls.__name__)

    def register_target(self, name: str, cls: Type) -> None:
        """注册自定义目标"""
        self._registered_targets[name] = cls
        logger.debug("Registered target: %s → %s", name, cls.__name__)

    # ── 合并到 component_registry ──

    def _merge_to_registry(self) -> None:
        """将已注册的插件合并到 component_registry"""
        try:
            from . import component_registry

            # 合并转换器
            for name, cls in self._registered_converters.items():
                if name not in component_registry.CONVERTER_MAP:
                    component_registry.CONVERTER_MAP[name] = cls
                    logger.info("Plugin converter registered: %s", name)

            # 合并评分器
            for name, cls in self._registered_scorers.items():
                if name not in component_registry.SCORER_MAP:
                    component_registry.SCORER_MAP[name] = cls
                    logger.info("Plugin scorer registered: %s", name)

        except ImportError:
            logger.warning("component_registry not available, plugins not merged")

    # ── 工具方法 ──

    def _import_class(self, class_path: str) -> Optional[Type]:
        """从字符串路径导入类（如 'mymodule.MyConverter'）"""
        try:
            parts = class_path.rsplit(".", 1)
            if len(parts) == 2:
                module_path, class_name = parts
                module = importlib.import_module(module_path)
                return getattr(module, class_name)
            else:
                # 只有模块名
                return importlib.import_module(class_path)
        except Exception as e:
            logger.warning("Failed to import class '%s': %s", class_path, e)
            return None

    @staticmethod
    def _to_snake_case(name: str) -> str:
        """将类名转换为 snake_case（如 Base64Converter → base64）"""
        # 移除常见后缀
        for suffix in ["Converter", "Scorer", "Target"]:
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break
        # CamelCase → snake_case
        import re
        snake = re.sub(r'([A-Z])', r'_\1', name).lower().lstrip("_")
        return snake or name.lower()


# ──────────────────────────────────────────────────────────────────────────────
# 全局单例
# ──────────────────────────────────────────────────────────────────────────────

_global_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    """获取全局插件加载器单例"""
    global _global_loader
    if _global_loader is None:
        _global_loader = PluginLoader()
    return _global_loader


def load_plugins() -> PluginLoader:
    """加载所有插件（便捷函数）"""
    loader = get_plugin_loader()
    loader.load_all()
    return loader
