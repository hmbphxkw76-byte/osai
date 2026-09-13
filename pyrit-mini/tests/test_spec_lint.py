"""spec_lint 负例测试：验证整篇重写 BLOCKING / 大规模改动 WARNING / sid 唯一性。

对应工具：tools/spec_lint.py（AGENTS.md §2 S2/S3/S6 + README §5 D8 的机器校验）。
"""
from __future__ import annotations

import tools.spec_lint as sl


def test_rewrite_detected_as_blocking(monkeypatch):
    """删除行 ≥70% 总行 → BLOCKING（AGENTS.md S2 禁整文件覆盖）。"""
    monkeypatch.setattr(sl, "_git_diff_numstat", lambda: [(90, 90, "docs/specs/foo.md")])
    monkeypatch.setattr(sl, "_line_count", lambda _p: 100)
    blocking, warning = sl.check_diff_scale()
    assert blocking, "整篇覆盖重写应判 BLOCKING"
    assert not warning


def test_large_churn_warning(monkeypatch):
    """增+删 ≥50% 但 <70% → WARNING（疑似重排章节）。"""
    monkeypatch.setattr(sl, "_git_diff_numstat", lambda: [(30, 25, "docs/specs/foo.md")])
    monkeypatch.setattr(sl, "_line_count", lambda _p: 100)
    blocking, warning = sl.check_diff_scale()
    assert not blocking
    assert warning, "大规模改动应判 WARNING"


def test_normal_diff_passes(monkeypatch):
    """小幅增量编辑 → 无告警。"""
    monkeypatch.setattr(sl, "_git_diff_numstat", lambda: [(3, 2, "docs/specs/foo.md")])
    monkeypatch.setattr(sl, "_line_count", lambda _p: 100)
    blocking, warning = sl.check_diff_scale()
    assert not blocking
    assert not warning


def test_new_file_not_flagged(monkeypatch):
    """新增文件（del=0）→ 不判重写。"""
    monkeypatch.setattr(sl, "_git_diff_numstat", lambda: [(100, 0, "docs/specs/bar.md")])
    monkeypatch.setattr(sl, "_line_count", lambda _p: 100)
    blocking, warning = sl.check_diff_scale()
    assert not blocking


def test_sid_duplicate_blocking(tmp_path, monkeypatch):
    """重复 sid → BLOCKING。"""
    (tmp_path / "a.md").write_text("## 一 [sid:40-ch1]\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("## 二 [sid:40-ch1]\n", encoding="utf-8")
    monkeypatch.setattr(sl, "ROOT", tmp_path)
    monkeypatch.setattr(sl, "SPECS_DIR", tmp_path)
    blocking, _ = sl.check_sid_uniqueness()
    assert blocking, "重复 sid 应判 BLOCKING"


def test_sid_unique_passes(tmp_path, monkeypatch):
    """唯一 sid → 通过。"""
    (tmp_path / "a.md").write_text("## 一 [sid:40-ch1]\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("## 二 [sid:40-ch2]\n", encoding="utf-8")
    monkeypatch.setattr(sl, "ROOT", tmp_path)
    monkeypatch.setattr(sl, "SPECS_DIR", tmp_path)
    blocking, _ = sl.check_sid_uniqueness()
    assert not blocking


def test_sid_example_not_matched(tmp_path, monkeypatch):
    """规范说明里的 [sid:...] 示例（非标题行）→ 不计入。"""
    (tmp_path / "a.md").write_text("格式如 [sid:40-ch1] 尾标\n", encoding="utf-8")
    monkeypatch.setattr(sl, "ROOT", tmp_path)
    monkeypatch.setattr(sl, "SPECS_DIR", tmp_path)
    blocking, _ = sl.check_sid_uniqueness()
    assert not blocking
