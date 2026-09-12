# -*- coding: utf-8 -*-
"""tests/test_roe.py — core/roe.py 单元测试（Rules of Engagement 授权闸门，REQ-163 / R-ROE-1）。

Constitution: RoE 是攻击执行的**前置授权闸门**（安全基线）。这些测试锁定
`ROEPolicy` 的 load / validate / merge 契约，确保授权边界不被静默放宽（fail-closed）。
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.roe import (
    ROEPolicy,
    load_roe_file,
    merge_authorized_targets,
    validate_roe,
)


def test_default_policy_is_empty():
    """默认策略无授权（fail-closed：未授权即禁止）。"""
    p = ROEPolicy()
    assert p.authorization_ref == ""
    assert p.targets == []
    assert p.valid_from == ""
    assert p.valid_until == ""


def test_load_roe_file_from_yaml(tmp_path: Path):
    """YAML 授权文件加载。"""
    p = tmp_path / "roe.yaml"
    p.write_text(
        "authorization_ref: ROE-2026-042\n"
        "targets:\n  - example.com\n  - '*.example.com'\n"
        "valid_from: 2026-09-01\nvalid_until: 2026-09-30\n",
        encoding="utf-8",
    )
    policy = load_roe_file(p)
    assert policy.authorization_ref == "ROE-2026-042"
    assert policy.targets == ["example.com", "*.example.com"]
    assert policy.valid_from == "2026-09-01"
    assert policy.valid_until == "2026-09-30"


def test_load_roe_file_json_equivalent():
    """JSON 形态与 YAML 等价。"""
    import json

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump({"authorization_ref": "R1", "targets": ["a.com"]}, f)
        path = f.name
    try:
        policy = load_roe_file(path)
        assert policy.authorization_ref == "R1"
        assert policy.targets == ["a.com"]
    finally:
        Path(path).unlink()


def test_load_roe_file_missing_raises():
    """文件不存在必须抛 FileNotFoundError（fail-closed，不静默回退空授权）。"""
    with pytest.raises(FileNotFoundError):
        load_roe_file("no/such/roe.yaml")


def test_validate_roe_rejects_missing_ref_and_targets():
    """缺授权编号或目标清单必须报告问题（不抛异常，返回问题清单）。"""
    problems = validate_roe(ROEPolicy())
    assert any("authorization_ref" in p for p in problems)
    assert any("targets" in p for p in problems)


def test_validate_roe_valid():
    """完整且未过期的策略返回空问题清单。"""
    policy = ROEPolicy(
        authorization_ref="R1",
        targets=["example.com"],
        valid_from="2020-01-01",
        valid_until="2999-12-31",
    )
    assert validate_roe(policy) == []


def test_validate_roe_expired():
    """过期授权被标记（R-ROE-1：时间窗失效即禁）。"""
    policy = ROEPolicy(
        authorization_ref="R1",
        targets=["example.com"],
        valid_from="2000-01-01",
        valid_until="2001-01-01",
    )
    assert any("过期" in p or "已过期" in p for p in validate_roe(policy))


def test_merge_authorized_targets_dedups_case_insensitive():
    """合并取并集且大小写/尾点归一去重（授权范围可见、可追溯）。"""
    merged = merge_authorized_targets(["Example.com", "x.com."], ROEPolicy(targets=["example.com", "y.com"]))
    assert merged == ["example.com", "x.com", "y.com"]


def test_merge_does_not_widen_unnecessarily():
    """仅在既有集合基础上**追加** RoE 目标，不修改既有项（不变量：授权可加不可随性删）。"""
    base = ["a.com"]
    merged = merge_authorized_targets(base, ROEPolicy(targets=["b.com"]))
    assert merged == ["a.com", "b.com"]
    # 原列表未被就地破坏语义
    assert base == ["a.com"]
