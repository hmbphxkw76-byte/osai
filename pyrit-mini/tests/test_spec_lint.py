"""spec_lint 负例测试：验证整篇重写 BLOCKING / 大规模改动 WARNING / sid 锚点体系。

对应工具：tools/spec_lint.py（AGENTS.md [sid:agents-ch2] S2/S3/S6/S7 + README [sid:readme-ch5] D8
的机器校验）。锚点语法/入口唯一性用例守护"跨模型协作三基石"之稳定锚点与统一入口。
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


def _setup(tmp_path, monkeypatch, files: dict[str, str]):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    monkeypatch.setattr(sl, "ROOT", tmp_path)
    monkeypatch.setattr(sl, "SPECS_DIR", tmp_path)


def test_nested_sid_blocking(tmp_path, monkeypatch):
    """嵌套/未闭合 sid → BLOCKING（畸形锚点比无锚点更危险：看起来可解析）。"""
    _setup(tmp_path, monkeypatch, {"a.md": "## 一 [sid:40-ch1]\n\n见 [sid:30-c[sid:30-ch4]] 定位\n"})
    blocking, _ = sl.check_sid_syntax()
    assert blocking, "嵌套 sid 应判 BLOCKING"


def test_glued_sid_blocking(tmp_path, monkeypatch):
    """sid 吃掉正文（左侧紧邻 ASCII 字母）→ BLOCKING。"""
    _setup(tmp_path, monkeypatch, {"a.md": "## 一 [sid:40-ch1]\n\n见 `20-REQUIREM[sid:55-ref]S.md`\n"})
    blocking, _ = sl.check_sid_syntax()
    assert blocking, "粘连 sid 应判 BLOCKING"


def test_sid_inside_code_fence_ignored(tmp_path, monkeypatch):
    """代码块内的 sid 字样（示例/模板）→ 不判畸形、不计覆盖率。"""
    _setup(tmp_path, monkeypatch, {"a.md": "```markdown\n## STOP-REPORT\n[sid:40-ch1\n```\n"})
    blocking, _ = sl.check_sid_syntax()
    assert not blocking
    _, warning = sl.check_heading_sid_coverage()
    assert not warning


def test_unregistered_docnum_warns(tmp_path, monkeypatch):
    """sid 文档号不在登记簿 → WARNING。"""
    _setup(tmp_path, monkeypatch, {"a.md": "## 一 [sid:40-ch1]\n\n见 [sid:99-ch1]\n"})
    _, warning = sl.check_sid_docnum()
    assert warning, "未登记文档号应判 WARNING"


def test_crossdoc_mismatch_warns(tmp_path, monkeypatch):
    """同行点名 80 却引用 20 的 sid → WARNING（错指锚点）。"""
    _setup(
        tmp_path,
        monkeypatch,
        {"a.md": "## 一 [sid:90-ch1]\n\n| 组件归属 | 见 80 [sid:20-ch5] |\n"},
    )
    _, warning = sl.check_sid_crossdoc_coherence()
    assert warning, "跨文档错指应判 WARNING"


def test_docnum_alias_blueprint_is_recognized(tmp_path, monkeypatch):
    """中文专名"蓝图"必须等价于文档号 10（受控实验：缺它则别名型错指 2/6 全漏报）。"""
    _setup(tmp_path, monkeypatch, {"30-x.md": "## 一 [sid:30-ch1]\n\n引用 DEBT-ID（蓝图 [sid:40-ch8]）\n"})
    _, warning = sl.check_sid_crossdoc_coherence()
    assert warning, "'蓝图' 句里的错指锚点应被检出（别名集合不得擅自删减）"


def test_docnum_alias_set_is_measured(tmp_path, monkeypatch):
    """别名集合本身受保护：含"需求/组件"会把真错指判为相容（实验测得漏报），故禁止。"""
    assert "需求" not in sl._DOCNUM_ALIASES and "组件" not in sl._DOCNUM_ALIASES
    assert sl._DOCNUM_ALIASES.get("蓝图") == "10"


def test_crossdoc_self_reference_ok(tmp_path, monkeypatch):
    """本文件引用本文件章节 → 通过（自引用恒合法）。"""
    _setup(tmp_path, monkeypatch, {"90-x.md": "## 一 [sid:90-ch1]\n\n见 [sid:90-ch2]\n"})
    _, warning = sl.check_sid_crossdoc_coherence()
    assert not warning


def test_heading_sid_coverage_warns(tmp_path, monkeypatch):
    """活动规约一级标题缺 sid → WARNING。"""
    _setup(tmp_path, monkeypatch, {"a.md": "## 一 [sid:40-ch1]\n\n## 二 没有锚点\n"})
    _, warning = sl.check_heading_sid_coverage()
    assert warning, "缺 sid 的一级标题应判 WARNING"


def test_ai_entry_missing_agents_blocking(tmp_path, monkeypatch):
    """缺 AGENTS.md → BLOCKING（统一入口是跨模型协作前提）。"""
    _setup(tmp_path, monkeypatch, {"README.md": "## 一 [sid:readme-ch1]\n"})
    blocking, _ = sl.check_ai_entry_unified()
    assert blocking, "缺统一入口应判 BLOCKING"


def test_ai_entry_coldstart_without_pointer_warns(tmp_path, monkeypatch):
    """另立冷启动顺序且不指向 AGENTS.md → WARNING。"""
    _setup(
        tmp_path,
        monkeypatch,
        {
            "AGENTS.md": "## 1. 会话冷启动阅读顺序 [sid:agents-ch1]\n",
            "README.md": "## 一 [sid:readme-ch1]\n\n索引 [AGENTS.md](AGENTS.md)\n",
            "90-x.md": "### 3.1 会话冷启动阅读顺序\n\n1. 本文件第一\n",
        },
    )
    blocking, warning = sl.check_ai_entry_unified()
    assert not blocking
    assert warning, "冷启动顺序另立门户应判 WARNING"
