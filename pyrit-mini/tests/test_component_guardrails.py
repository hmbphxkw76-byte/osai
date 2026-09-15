"""REQ-177 组件一致性护栏（R-COMP-2 / R-COMP-3）单测。

闭环 c000075 遗留的 R-DELIVERY-2 缺口（新增护栏须有对应测试）。

测试策略：以 ``tmp_path`` 构造隔离的仓库根（``self.root``），并对 R-COMP-3
依赖的 ``git diff --cached`` 用 ``unittest.mock.patch`` 替换 ``subprocess.run``，
与真实仓库状态完全解耦。覆盖三态：violation / ok / exempt；REV-31 起 R-COMP-2 / R-COMP-3 均为
BLOCKING（R-COMP-2 由 WARNING 升级，依「P3 完成起 BLOCKING」条款）。
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tools.guard_extended as ge
from tools.guard import Severity


class _FakeGuard:
    """复刻 guard 实例的 ``root`` / ``violations`` 契约。"""

    def __init__(self, root: Path):
        self.root = root
        self.violations: list = []


def _write_component(root: Path, name: str, body: str) -> Path:
    d = root / "config" / "components"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


def _fake_git_diff(stdout: str) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout)


# ---------------------------------------------------------------------------
# R-COMP-2：组件–目录一致（I15）
# ---------------------------------------------------------------------------


def test_rcomp2_violation_when_no_dir(tmp_path):
    _write_component(tmp_path, "ghost.yaml", "id: ghost\n")
    g = _FakeGuard(tmp_path)
    ge.check_component_dir_consistency(g)
    assert len(g.violations) == 1
    v = g.violations[0]
    assert v.rule == "R-COMP-2"
    # REV-31：R-COMP-2 由 WARNING 升级 BLOCKING（P3 完成起条款已满足）
    assert v.severity == Severity.BLOCKING


def test_rcomp2_ok_when_strike_dir(tmp_path):
    _write_component(tmp_path, "ghost.yaml", "id: ghost\n")
    (tmp_path / "strike" / "ghost").mkdir(parents=True)
    g = _FakeGuard(tmp_path)
    ge.check_component_dir_consistency(g)
    assert g.violations == []


def test_rcomp2_ok_when_recon_dir(tmp_path):
    _write_component(tmp_path, "ghost.yaml", "id: ghost\n")
    (tmp_path / "recon" / "ghost").mkdir(parents=True)
    g = _FakeGuard(tmp_path)
    ge.check_component_dir_consistency(g)
    assert g.violations == []


def test_rcomp2_recon_only_exempt(tmp_path):
    _write_component(tmp_path, "ro.yaml", "id: ro\nrecon_only: true\n")
    g = _FakeGuard(tmp_path)
    ge.check_component_dir_consistency(g)
    assert g.violations == []


# ---------------------------------------------------------------------------
# R-COMP-3：recon_only 组件不得写入执行分支（ADR-011 / REQ-177）
# ---------------------------------------------------------------------------


def test_rcomp3_blocking_when_strike_module_added(tmp_path):
    _write_component(tmp_path, "emb.yaml", "id: emb\nrecon_only: true\n")
    diff = (
        "diff --git a/strike/emb/evil.py b/strike/emb/evil.py\n"
        "new file mode 100644\n"
        "--- a/strike/emb/evil.py\n"
        "+++ b/strike/emb/evil.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+def attack():\n"
        "+    pass\n"
    )
    g = _FakeGuard(tmp_path)
    with patch("tools.guard_extended.subprocess.run", return_value=_fake_git_diff(diff)):
        ge.check_recon_only_component(g)
    blocking = [v for v in g.violations if v.severity == Severity.BLOCKING]
    assert len(blocking) == 1
    assert blocking[0].rule == "R-COMP-3"


def test_rcomp3_init_py_exempt(tmp_path):
    _write_component(tmp_path, "emb.yaml", "id: emb\nrecon_only: true\n")
    diff = (
        "diff --git a/strike/emb/__init__.py b/strike/emb/__init__.py\n"
        "new file mode 100644\n"
        "--- a/strike/emb/__init__.py\n"
        "+++ b/strike/emb/__init__.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+from strike.emb.evil import run\n"
        "+from .internal import helper\n"
    )
    g = _FakeGuard(tmp_path)
    with patch("tools.guard_extended.subprocess.run", return_value=_fake_git_diff(diff)):
        ge.check_recon_only_component(g)
    assert g.violations == []


def test_rcomp3_yaml_strike_modules_blocking(tmp_path):
    _write_component(tmp_path, "emb.yaml", "id: emb\nrecon_only: true\n")
    diff = (
        "diff --git a/config/components/emb.yaml b/config/components/emb.yaml\n"
        "--- a/config/components/emb.yaml\n"
        "+++ b/config/components/emb.yaml\n"
        "@@ -10,3 +10,5 @@\n"
        "+strike_modules:\n"
        "+  - evil_attack\n"
    )
    g = _FakeGuard(tmp_path)
    with patch("tools.guard_extended.subprocess.run", return_value=_fake_git_diff(diff)):
        ge.check_recon_only_component(g)
    blocking = [v for v in g.violations if v.severity == Severity.BLOCKING]
    assert len(blocking) == 1
    assert blocking[0].rule == "R-COMP-3"


def test_rcomp3_no_diff_no_violation(tmp_path):
    _write_component(tmp_path, "emb.yaml", "id: emb\nrecon_only: true\n")
    g = _FakeGuard(tmp_path)
    with patch("tools.guard_extended.subprocess.run", return_value=_fake_git_diff("")):
        ge.check_recon_only_component(g)
    assert g.violations == []


# ---------------------------------------------------------------------------
# 纯函数单测（护栏核心判定逻辑）
# ---------------------------------------------------------------------------


def test_is_recon_only():
    assert ge._is_recon_only({"recon_only": "true"}) is True
    assert ge._is_recon_only({"attack_execution": "recon_only"}) is True
    assert ge._is_recon_only({"id": "x"}) is False
    assert ge._is_recon_only({}) is False


def test_component_yaml_fields():
    text = "id: model\nrecon_only: false\nrecon_dir: api\nstrike_dir: web\n"
    fields = ge._component_yaml_fields(text)
    assert fields["id"] == "model"
    assert fields["recon_dir"] == "api"
    assert fields["strike_dir"] == "web"


def test_field_adds_nonempty_list():
    assert ge._field_adds_nonempty_list("strike_modules: [a, b]", "strike_modules") is True
    assert ge._field_adds_nonempty_list("strike_modules: []", "strike_modules") is False
    assert ge._field_adds_nonempty_list("strike_modules:\n  - x\n", "strike_modules") is True
    assert ge._field_adds_nonempty_list("strike_modules:\n  # empty\n", "strike_modules") is False
