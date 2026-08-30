# arXiv:2407.01232 — PyRIT, Initializer pattern
# arXiv:2302.12173 — Greshake et al., target capability fingerprint
"""动态 Initializer 注册器 — 借鉴 pyrit_scan 的 --add-initializer CLI 模式。

增量借鉴:
    pyrit_scan 通过 --add-initializer ClassName,arg1=val1 在运行时
    动态注册 PyRIT Initializer (Target/Scenario 的预配置组件)。

本模块提供:
    - register_initializers: 从 spec 列表反射实例化并注册 Initializer
    - _resolve_class: 从类名查找 PyRIT 模块中的类

Initializer 模式:
    PyRIT Initializer 是 Scenario 的预配置组件, 在 Scenario 启动前执行:
    1. 修改 Target (如设置 system_prompt, 注入 context)
    2. 修改 Scenario (如设置 max_turns, scoring_strategy)
    3. 注册 Cross-Session Memory (如注入已知成功的 prompt)

使用方式:
    python main.py --add-initializer SystemPromptInitializer,prompt="You are a helpful assistant"
    python main.py --config-file config/my_target.yaml  # add_initializer in YAML
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _resolve_class(class_name: str) -> type | None:
    """从 PyRIT 模块中查找类。

    搜索范围:
        1. pyrit.orchestrator.initializers (PyRIT 原生 Initializer 包)
        2. pyrit.scenario.initializers (备选路径)
        3. pyrit.setup.initializers (初始化器包)
        4. 用户的 strike/ 或 core/ 模块 (自定义 Initializer)

    Args:
        class_name: 类名 (不含包路径, 如 "SystemPromptInitializer")

    Returns:
        类对象, 或 None (未找到)
    """
    # 搜索路径列表
    search_paths = [
        "pyrit.orchestrator.initializers",
        "pyrit.scenario.initializers",
        "pyrit.setup.initializers",
        "pyrit.initializers",
        "strike",
        "core",
    ]

    for module_path in search_paths:
        try:
            import importlib

            module = importlib.import_module(module_path)
            if hasattr(module, class_name):
                cls = getattr(module, class_name)
                if isinstance(cls, type):
                    logger.debug("Resolved class %s from %s", class_name, module_path)
                    return cls
        except ImportError:
            continue
        except Exception as e:
            logger.debug("Error searching %s for %s: %s", module_path, class_name, e)
            continue

    logger.warning("Initializer class '%s' not found in any search path", class_name)
    return None


def register_initializers(
    specs: list[dict[str, Any]],
    *,
    ctx: Any | None = None,
) -> list[Any]:
    """从 spec 列表动态实例化并注册 Initializer。

    每个 spec 格式:
        {"class": "ClassName", "args": {"arg1": "val1", "arg2": "val2"}}

    实例化策略:
        1. 从 spec["class"] 查找 PyRIT 类
        2. 用 spec["args"] 作为 kwargs 调用构造函数
        3. 如果类有 async register(ctx) 方法, 调用它注册到 ctx
        4. 如果类有 register_sync(ctx) 方法, 调用它注册到 ctx
        5. 否则返回实例, 由调用方手动注册

    Args:
        specs: Initializer spec 列表 (来自 --add-initializer 解析)。
        ctx: PipelineContext (用于调用 register 方法, 可选)。

    Returns:
        成功创建的 Initializer 实例列表。
    """
    if not specs:
        return []

    instances: list[Any] = []
    for spec in specs:
        class_name = spec.get("class", "")
        kwargs = spec.get("args", {})

        if not class_name:
            logger.warning("Empty initializer class name in spec: %s", spec)
            continue

        cls = _resolve_class(class_name)
        if cls is None:
            logger.warning("Cannot resolve initializer class: %s, skipping", class_name)
            continue

        try:
            # 实例化
            instance = cls(**kwargs) if kwargs else cls()
            instances.append(instance)
            logger.info(
                "Initializer created: %s(args=%s)",
                class_name,
                kwargs,
            )

            # 注册到 ctx (如果类有 register 方法)
            if ctx is not None:
                if hasattr(instance, "register_async"):
                    # 异步注册由调用方在 event loop 中执行
                    logger.debug(
                        "Initializer %s has register_async, deferred to caller",
                        class_name,
                    )
                elif hasattr(instance, "register"):
                    try:
                        instance.register(ctx)
                        logger.info("Initializer %s registered to ctx", class_name)
                    except Exception as e:
                        logger.warning(
                            "Failed to register initializer %s: %s",
                            class_name,
                            e,
                        )

        except TypeError as e:
            logger.warning(
                "Failed to instantiate %s(%s): %s",
                class_name,
                kwargs,
                e,
            )
        except Exception as e:
            logger.error(
                "Unexpected error creating initializer %s: %s",
                class_name,
                e,
                exc_info=True,
            )

    return instances


async def register_initializers_async(
    specs: list[dict[str, Any]],
    ctx: Any,
) -> list[Any]:
    """异步注册 Initializer — 调用 register_async 方法。

    Args:
        specs: Initializer spec 列表。
        ctx: PipelineContext。

    Returns:
        成功创建的 Initializer 实例列表。
    """
    instances = register_initializers(specs, ctx=ctx)

    # 异步注册
    for instance in instances:
        if hasattr(instance, "register_async"):
            try:
                await instance.register_async(ctx)
                logger.info("Initializer %s registered async to ctx", type(instance).__name__)
            except Exception as e:
                logger.warning(
                    "Failed to async-register initializer %s: %s",
                    type(instance).__name__,
                    e,
                )

    return instances
