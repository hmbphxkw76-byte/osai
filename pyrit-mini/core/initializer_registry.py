"""Initializer registry - pyrit_scan --add-initializer CLI

Academic basis:
    - arXiv:2407.01232 (PyRIT): Initializer pattern
    - arXiv:2302.12173 (Greshake et al.): Target capability fingerprint

:
    pyrit_scan  --add-initializer ClassName,arg1=val1
     PyRIT Initializer (Target/Scenario )

:
    - register_initializers: imports spec  Initializer
    - _resolve_class: imports PyRIT

Initializer :
    PyRIT Initializer  Scenario ,  Scenario :
    1.  Target ( system_prompt,  context)
    2.  Scenario ( max_turns, scoring_strategy)
    3.  Cross-Session Memory ( prompt)

Usage:
    python main.py --add-initializer SystemPromptInitializer,prompt="You are a helpful assistant"
    python main.py --config-file config/my_target.yaml  # add_initializer in YAML
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

def _resolve_class(class_name: str) -> type | None:
    """imports PyRIT

    :
        1. pyrit.orchestrator.initializers (PyRIT  Initializer )
        2. pyrit.scenario.initializers ()
        3. pyrit.setup.initializers ()
        4.  strike/  core/  ( Initializer)

    Args:
        class_name:  (,  "SystemPromptInitializer")

    Returns:
        ,  None ()
    """
 #
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
    """imports spec Initializer

    converter(s) spec :
        {"class": "ClassName", "args": {"arg1": "val1", "arg2": "val2"}}

    :
        1. imports spec["class"]  PyRIT
        2.  spec["args"]  kwargs
        3.  async register(ctx) ,  ctx
        4.  register_sync(ctx) ,  ctx
        5. ,

    Args:
        specs: Initializer spec  ( --add-initializer )
        ctx: PipelineContext ( register , )

    Returns:
         Initializer
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
         #
            instance = cls(**kwargs) if kwargs else cls()
            instances.append(instance)
            logger.info(
                "Initializer created: %s(args=%s)",
                class_name,
                kwargs,
            )

 # ctx ( register )
            if ctx is not None:
                if hasattr(instance, "register_async"):
                 # event loop
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
    """ Initializer - register_async

    Args:
        specs: Initializer spec
        ctx: PipelineContext

    Returns:
         Initializer
    """
    instances = register_initializers(specs, ctx=ctx)

 #
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
