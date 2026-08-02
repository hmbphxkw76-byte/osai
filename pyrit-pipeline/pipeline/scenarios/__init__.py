# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""多场景注册表 — 统一管理 PyRIT 原生场景类型。.

PyRIT 1.1.0.dev0 原生提供以下场景:
  - ``TextAdaptive``: 文本自适应 (epsilon-greedy, 当前默认)
  - ``AirtJailbreakScenario``: AIRT 越狱攻击
  - ``AirtCyberScenario``: AIRT 网络安全
  - ``AirtLeakageScenario``: AIRT 信息泄露
  - ``AirtPsychosocialScenario``: AIRT 心理社会攻击
  - ``AirtRapidResponseScenario``: AIRT 快速响应
  - ``AirtScamScenario``: AIRT 诈骗
  - ``EncodingScenario``: Garak 编码攻击
  - ``DoctorScenario``: Garak Doctor 探测
  - ``WebInjectionScenario``: Garak Web 注入
  - ``AdversarialBenchmark``: 对抗基准
  - ``RedTeamAgentScenario``: Foundry 自主红队代理

通过 ``--scenario`` CLI 参数选择场景，统一注入 ``set_params_from_args``。

学术依据:
  - PyRIT 官方 Scenario 文档
  - JailbreakBench (arXiv:2402.01135): 标准化场景评估

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pyrit.scenario.core.scenario import Scenario


# ============================================================
# 场景注册表
# ============================================================


def get_available_scenarios() -> dict[str, str]:
    """返回可用场景名称 → 描述映射。.

    Returns:
        dict[str, str]: 场景名称 → 描述。
    """
    return {
        "text_adaptive": "文本自适应 (epsilon-greedy, 默认, ASR 驱动技术选择)",
        "airt_jailbreak": "AIRT 越狱攻击场景 (jailbreak 模板 + 编码变体)",
        "airt_cyber": "AIRT 网络安全攻击场景",
        "airt_leakage": "AIRT 信息泄露场景 (首字母/图像泄露)",
        "airt_psychosocial": "AIRT 心理社会攻击场景",
        "airt_rapid_response": "AIRT 快速响应场景",
        "airt_scam": "AIRT 诈骗场景",
        "garak_encoding": "Garak 编码攻击场景 (Base64/ROT13/Morse 等)",
        "garak_doctor": "Garak Doctor 探测场景",
        "garak_web_injection": "Garak Web 注入场景",
        "benchmark_adversarial": "对抗基准场景 (跨对抗模型 ASR 对比)",
        "foundry_red_team": "Foundry 自主红队代理场景 (Azure AI Foundry)",
    }


def create_scenario(
    scenario_name: str,
    *,
    objective_scorer: Any = None,
    selector: Any = None,
    scenario_result_id: str | None = None,
) -> Scenario | None:
    """创建指定名称的场景实例。.

    所有场景均使用原生 PyRIT 场景类 (v7.0: ``text_adaptive`` 路径已迁移至
    ``stage_scenario.py`` 直接使用原生 ``TextAdaptive``, 本函数仅处理
    AIRT/Garak/Benchmark/Foundry 等原生场景)。

    Args:
        scenario_name: 场景名称 (见 ``get_available_scenarios``)。
        objective_scorer: 评分器实例。
        selector: 技术选择器 (仅 ``text_adaptive`` 使用, 此函数不处理)。
        scenario_result_id: 断点续跑的 ScenarioResult ID。

    Returns:
        场景实例，或 None (如果场景名称无效)。
    """
    # 原生场景映射
    native_scenarios = _get_native_scenario_map()

    scenario_cls = native_scenarios.get(scenario_name)
    if scenario_cls is None:
        logger.error(f"Unknown scenario: {scenario_name}")
        return None

    try:
        # 原生场景可能不接受 selector 参数
        kwargs: dict[str, Any] = {}
        if objective_scorer is not None:
            kwargs["objective_scorer"] = objective_scorer
        if scenario_result_id is not None:
            kwargs["scenario_result_id"] = scenario_result_id

        return scenario_cls(**kwargs)
    except (RuntimeError, OSError, ValueError) as e:
        logger.error(f"Failed to create scenario '{scenario_name}': {e}")
        return None


def _get_native_scenario_map() -> dict[str, type]:
    """返回原生场景名称 → 类映射。."""
    try:
        from pyrit.scenario.scenarios.airt.cyber import AirtCyberScenario
        from pyrit.scenario.scenarios.airt.jailbreak import AirtJailbreakScenario
        from pyrit.scenario.scenarios.airt.leakage import AirtLeakageScenario
        from pyrit.scenario.scenarios.airt.psychosocial import AirtPsychosocialScenario
        from pyrit.scenario.scenarios.airt.rapid_response import AirtRapidResponseScenario
        from pyrit.scenario.scenarios.airt.scam import AirtScamScenario
        from pyrit.scenario.scenarios.benchmark.adversarial import AdversarialBenchmark
        from pyrit.scenario.scenarios.foundry.red_team_agent import RedTeamAgentScenario
        from pyrit.scenario.scenarios.garak.doctor import DoctorScenario
        from pyrit.scenario.scenarios.garak.encoding import EncodingScenario
        from pyrit.scenario.scenarios.garak.web_injection import WebInjectionScenario

        return {
            "airt_jailbreak": AirtJailbreakScenario,
            "airt_cyber": AirtCyberScenario,
            "airt_leakage": AirtLeakageScenario,
            "airt_psychosocial": AirtPsychosocialScenario,
            "airt_rapid_response": AirtRapidResponseScenario,
            "airt_scam": AirtScamScenario,
            "garak_encoding": EncodingScenario,
            "garak_doctor": DoctorScenario,
            "garak_web_injection": WebInjectionScenario,
            "benchmark_adversarial": AdversarialBenchmark,
            "foundry_red_team": RedTeamAgentScenario,
        }
    except ImportError as e:
        logger.warning(f"Some native scenarios not available: {e}")
        return {}


def is_native_scenario(scenario_name: str) -> bool:
    """检查场景名称是否为原生场景 (非 text_adaptive)。."""
    return scenario_name != "text_adaptive" and scenario_name in get_available_scenarios()
