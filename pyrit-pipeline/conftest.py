# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Pytest 全局 fixtures。.

为 pipeline 和 web_bridge 测试提供共享 fixture。
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
        max_concurrency=5,
        max_retries=3,
        resume=None,
        no_baseline=False,
        converters=None,
        config_file="config/.pyrit_conf",
        output_dir=None,
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
