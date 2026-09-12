"""靶场端到端断言（REQ-156⑤：e2e 进 CI）。

设计约束：
    - **复用而非重写**：断言逻辑的唯一实现是 `tools.mock_range.run_check`（与
      `python -m tools.mock_range --check` 同一代码路径）。本文件只负责把它接入 pytest，
      禁止在测试内另写一套靶场断言（C3 / R-H3）。
    - R-S1：靶场只绑定回环地址，禁止暴露到非授权网段。
"""

from __future__ import annotations

import re

from tools.mock_range import PERSONAS, load_expected, run_check


def test_golden_range_assertions_pass() -> None:
    """5 类人格全部符合 `targets/mock/fixtures/expected.yaml`。

    这是 B3（Reproducible）/ B5（Regressible）判据的机器化落点：
    同一 commit + 同一 fixtures → 识别标签 / 响应契约 可断言。
    """
    ok, problems = run_check(host="127.0.0.1")
    assert ok, "靶场 golden 断言失败: " + "; ".join(problems)


def test_expected_covers_all_personas() -> None:
    """期望集必须覆盖全部人格（防止新增靶标忘记补期望 → 断言静默变弱）。"""
    specs = (load_expected() or {}).get("personas") or {}
    missing = [p for p in PERSONAS if p not in specs]
    assert not missing, f"expected.yaml 未覆盖人格: {missing}"


def test_range_cli_default_host_is_loopback() -> None:
    """R-S1 / RK-5：`--host` 默认值必须是回环地址（防止靶场暴露到非授权网段）。"""
    from pathlib import Path

    import tools.mock_range as mock_range

    source = Path(str(mock_range.__file__)).read_text(encoding="utf-8")
    assert re.search(r'add_argument\(\s*"--host"\s*,\s*default\s*=\s*"127\.0\.0\.1"', source), (
        "tools/mock_range.py 的 --host 默认值不再是回环地址 —— 靶场可能暴露到非授权网段（R-S1）"
    )
