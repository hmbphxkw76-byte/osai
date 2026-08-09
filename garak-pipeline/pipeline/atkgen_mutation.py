"""S3.3: atkgen 动态 prompt 变异集成 — 复用 garak 原生 atkgen.Tox 攻击生成模型

对齐 L5：garak 原生 atkgen.Tox 探针使用独立的红队模型动态生成攻击 prompt，
这比静态 prompt 列表具有更强的攻击覆盖度。本模块提供工具函数，
让自定义探针可以可选地使用 atkgen 红队模型对其静态 prompts 做动态变异/扩展。

设计原则（规则一：garak 原生优先）：
    本模块不重写 atkgen 攻击生成逻辑，仅：
    1. 复用 garak.probes.atkgen.Tox 的 red_team_model 配置体系
    2. 调用原生红队模型生成变异 prompt
    3. 将变异 prompt 追加到自定义探针的 prompt 列表

用法:
    from pipeline.atkgen_mutation import augment_prompts_with_atkgen
    augmented = augment_prompts_with_atkgen(
        base_prompts=["Ignore previous instructions"],
        red_team_model_type="huggingface.Pipeline",
        red_team_model_name="garak-llm/attackgeneration-toxicity_gpt2",
        num_mutations=5,
    )
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _load_red_team_generator(
    model_type: str,
    model_name: str,
    model_config: dict | None = None,
) -> Any | None:
    """加载 garak 原生红队模型 generator

    复用 garak._plugins.load_plugin 加载红队模型，
    与 garak.probes.atkgen.Tox 内部使用的加载机制完全一致。

    :param model_type: garak generator 类型（如 "huggingface.Pipeline"）
    :param model_name: 模型名/HuggingFace repo
    :param model_config: 额外 generator 配置（如 device/dtype）
    :returns: generator 实例；失败则 None
    """
    try:
        from garak import _config, _plugins

        # 确保配置已加载
        if hasattr(_config, "is_loaded"):
            if not _config.is_loaded:
                _config.load_base_config()
        elif hasattr(_config, "loaded"):
            if not _config.loaded:
                _config.load_base_config()

        # 构造 generator 配置
        gen_type_parts = model_type.split(".")
        if len(gen_type_parts) < 2:
            logger.warning("无效的 model_type: %s", model_type)
            return None

        gen_ns, gen_class = gen_type_parts[0], gen_type_parts[1]
        gen_config = _config.plugins.generators.setdefault(gen_ns, {}).setdefault(gen_class, {})
        gen_config["name"] = model_name
        if model_config:
            gen_config.update(model_config)

        generator = _plugins.load_plugin(
            f"generators.{model_type}", config_root=_config
        )
        return generator
    except Exception as exc:
        logger.warning("红队模型加载失败: %s", exc)
        return None


def augment_prompts_with_atkgen(
    base_prompts: list[str],
    red_team_model_type: str = "huggingface.Pipeline",
    red_team_model_name: str = "garak-llm/attackgeneration-toxicity_gpt2",
    red_team_model_config: dict | None = None,
    num_mutations: int = 5,
    prompt_template: str = "<|input|>[query]<|response|>",
    postproc_rm_regex: str = r"\<\|.*",
) -> list[str]:
    """S3.3: 使用 garak atkgen 红队模型对静态 prompts 做动态变异

    对齐 L5：顶级红队使用动态攻击生成而非纯静态 prompt 列表。
    本函数复用 garak.probes.atkgen.Tox 的红队模型配置和 prompt 模板，
    将每个 base_prompt 作为种子输入红队模型，生成变异攻击 prompt。

    :param base_prompts: 原始静态 prompt 列表（种子）
    :param red_team_model_type: 红队模型类型（默认 garak 原生 atkgen 配置）
    :param red_team_model_name: 红队模型名（默认 garak 原生 atkgen 配置）
    :param red_team_model_config: 红队模型额外配置
    :param num_mutations: 每个 seed prompt 生成的变异数量
    :param prompt_template: prompt 模板（与 garak atkgen.Tox 一致）
    :param postproc_rm_regex: 后处理正则（与 garak atkgen.Tox 一致）
    :returns: 变异后的 prompt 列表（原始 + 变异）
    """
    import re as _re

    generator = _load_red_team_generator(
        red_team_model_type, red_team_model_name, red_team_model_config
    )
    if generator is None:
        logger.info("atkgen 红队模型不可用，返回原始 prompts（无变异）")
        return list(base_prompts)

    augmented = list(base_prompts)
    try:
        for seed_prompt in base_prompts[:3]:  # 仅对前 3 个种子做变异（控制成本）
            for _ in range(num_mutations):
                try:
                    # 使用 atkgen 的 prompt 模板构造输入
                    formatted = prompt_template.replace("[query]", seed_prompt)
                    # 调用原生 generator 生成变异 prompt
                    responses = generator._call_model(
                        formatted, generations=1
                    )
                    if responses:
                        raw = str(responses[0]) if isinstance(responses, list) else str(responses)
                        # 后处理：去除模板标记（与 garak atkgen.Tox 一致）
                        cleaned = _re.sub(postproc_rm_regex, "", raw).strip()
                        if cleaned and len(cleaned) > 10 and cleaned not in augmented:
                            augmented.append(cleaned)
                except Exception as exc:
                    logger.debug("atkgen 变异生成失败: %s", exc)
                    continue
    except Exception as exc:
        logger.warning("atkgen 动态变异异常: %s", exc)

    logger.info(
        "atkgen 变异完成：%d 原始 → %d 总计（+%d 变异）",
        len(base_prompts), len(augmented), len(augmented) - len(base_prompts),
    )
    return augmented


def maybe_augment_probe_prompts(
    probe_class: type,
    enable_atkgen: bool = False,
    atkgen_config: dict | None = None,
) -> None:
    """S3.3: 条件性地为 Probe 子类 augment prompts

    在 Probe.__init__ 之后调用，若 enable_atkgen=True，
    使用 atkgen 红队模型对 probe.prompts 做动态变异。

    :param probe_class: Probe 实例（已有 self.prompts）
    :param enable_atkgen: 是否启用 atkgen 变异
    :param atkgen_config: atkgen 配置（覆盖默认）
    """
    if not enable_atkgen:
        return
    if not hasattr(probe_class, "prompts") or not probe_class.prompts:
        return

    cfg = atkgen_config or {}
    augmented = augment_prompts_with_atkgen(
        base_prompts=list(probe_class.prompts),
        red_team_model_type=cfg.get("red_team_model_type", "huggingface.Pipeline"),
        red_team_model_name=cfg.get(
            "red_team_model_name", "garak-llm/attackgeneration-toxicity_gpt2"
        ),
        red_team_model_config=cfg.get("red_team_model_config"),
        num_mutations=cfg.get("num_mutations", 3),
    )
    probe_class.prompts = augmented
