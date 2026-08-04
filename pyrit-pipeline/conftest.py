# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Pytest 全局 fixtures。.

为 pipeline 和 web_redteam 测试提供共享 fixture。
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock

import pytest

from pipeline.context import PipelineContext

# ──────────────────────────────────────────────────────────────────
#  Pipeline fixtures
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_args() -> argparse.Namespace:
    """模拟命令行参数。."""
    return argparse.Namespace(
        datasets=["harmbench", "jbb_behaviors"],
        max_dataset_size=10,
        local_datasets=None,
        techniques=None,
        max_attempts=3,
        epsilon=0.1,
        selector_scope="all_runs",
        max_concurrency=3,
        max_retries=3,
        rate_limit=3,
        rate_limit_retries=3,
        resume=None,
        no_baseline=False,
        converters=None,
        auto_converters=True,
        config_file="config/.pyrit_conf",
        output_dir=None,
        model="",
        skip_preflight=True,
        target_url=None,
        disable_json_mode=False,
        stream=False,
        recon_json=None,
        auth_state_file=None,
        mcp_attack=False,
        advanced_mcp_attack=False,
        crescendo_objective=None,
        crescendo_max_turns=10,
        tap_objective=None,
        tap_tree_width=4,
        tap_tree_depth=3,
        tap_branching=2,
        tap_success_threshold=8,
        assessment_framework=False,
        xpia_attack=False,
        asi03_attack=False,
        asi09_attack=False,
        asi10_attack=False,
        multi_agent_attack=False,
        # 高级攻击策略
        multi_turn_session=False,
        blind_inference=False,
        backdoor_probe=False,
        control_mode_aware=False,
        control_mode="detect",
        secret_validation=False,
        # 统一认证编排
        target_profile="",
        headless=False,
        cdp_port=9222,
        api_key="",
    )


@pytest.fixture
def pipeline_ctx(mock_args: argparse.Namespace) -> PipelineContext:
    """创建空的 PipelineContext (仅含 args)。."""
    return PipelineContext(args=mock_args)


@pytest.fixture
def mock_memory() -> MagicMock:
    """模拟 MemoryInterface。."""
    memory = MagicMock()
    memory.get_attack_results = MagicMock(return_value=[])
    return memory


@pytest.fixture
def mock_attack_result_success() -> MagicMock:
    """模拟成功的 AttackResult。."""
    from pyrit.models import AttackOutcome

    result = MagicMock()
    result.outcome = AttackOutcome.SUCCESS
    result.targeted_harm_categories = ["cybercrime"]
    result.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(class_name="many_shot"))
    return result


@pytest.fixture
def mock_attack_result_failure() -> MagicMock:
    """模拟失败的 AttackResult。."""
    from pyrit.models import AttackOutcome

    result = MagicMock()
    result.outcome = AttackOutcome.FAILURE
    result.targeted_harm_categories = ["illegal"]
    result.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(class_name="tap"))
    return result


@pytest.fixture
def mock_attack_result_error() -> MagicMock:
    """模拟错误的 AttackResult。."""
    from pyrit.models import AttackOutcome

    result = MagicMock()
    result.outcome = AttackOutcome.ERROR
    result.targeted_harm_categories = ["unknown"]
    result.get_attack_strategy_identifier = MagicMock(return_value=MagicMock(class_name="pair"))
    return result
