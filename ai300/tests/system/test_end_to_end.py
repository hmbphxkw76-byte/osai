# -*- coding: utf-8 -*-
"""
端到端系统测试：recon → attack → eval

本测试在本地启动 Mock LLM 服务，真实执行 ai300-recon 侦察流水线，
然后使用生成的 TargetProfile / PyRIT target 分别运行 ai300-attack 和 ai300-eval 的 dry-run。

验证目标：
  1. 侦察阶段能成功导出 profile 和 PyRIT target。
  2. 攻击工具包能根据 profile 选择策略。
  3. 评估工具包能根据 profile 选择策略。
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

# 项目根目录（本文件位于 tests/system）
ROOT = Path(__file__).resolve().parents[2]
MOCK_SERVER_PORT = 18081
MOCK_SERVER_URL = f"http://127.0.0.1:{MOCK_SERVER_PORT}"


def _wait_for_server(url: str, timeout: float = 10.0) -> None:
    """轮询等待 Mock 服务就绪"""
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=1.0)
            if response.status_code == 200:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"Mock server did not start in {timeout}s: {last_error}")


def _start_mock_server(port: int):
    """在子进程中启动 Mock LLM 服务"""
    # 通过内联脚本指定端口，避免修改原 mock 服务文件
    # 使用 importlib 直接从文件路径加载模块，避免依赖 __init__.py
    server_path = ROOT / "ai300-recon" / "tests" / "integration" / "mock_llm_server.py"
    code = (
        "import importlib.util; "
        f"spec = importlib.util.spec_from_file_location('mock_llm_server', r'{server_path}'); "
        "mod = importlib.util.module_from_spec(spec); "
        "spec.loader.exec_module(mod); "
        f"mod.run_server('127.0.0.1', {port})"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _run_recon(target_url: str) -> None:
    """运行 ai300-recon 侦察流水线"""
    env = {
        **dict(subprocess.os.environ),
        "PYTHONPATH": f"{ROOT / 'ai300-recon' / 'src'}{subprocess.os.pathsep}{ROOT / 'ai300-schemas' / 'src'}",
    }
    cmd = [
        sys.executable,
        str(ROOT / "ai300-recon" / "main.py"),
        target_url,
        "--type",
        "spa",
        "--headless",
        "--no-template",
    ]
    result = subprocess.run(cmd, cwd=str(ROOT), env=env, text=True, capture_output=True, timeout=180)
    assert result.returncode == 0, f"recon failed: {result.stderr}\n{result.stdout}"


def _find_latest_recon_outputs() -> tuple[Path, Path]:
    """查找最新的侦察输出文件"""
    profile_dir = ROOT / "results" / "recon" / "profiles"
    pyrit_dir = ROOT / "results" / "recon" / "pyrit"
    assert profile_dir.exists(), f"profile dir not found: {profile_dir}"
    assert pyrit_dir.exists(), f"pyrit target dir not found: {pyrit_dir}"

    profiles = sorted(profile_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    targets = sorted(pyrit_dir.glob("*_pyrit_target.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    assert profiles, "no recon profile generated"
    assert targets, "no pyrit target generated"
    return profiles[0], targets[0]


def _run_attack_dry_run(profile: Path, target: Path) -> str:
    """运行 ai300-attack dry-run，返回 stdout"""
    cmd = [
        "ai300-attack",
        "--dry-run",
        "--profile",
        str(profile),
        "--pyrit-target",
        str(target),
    ]
    result = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, f"attack dry-run failed: {result.stderr}\n{result.stdout}"
    return result.stdout


def _run_eval_dry_run(profile: Path, target: Path) -> str:
    """运行 ai300-eval dry-run，返回 stdout"""
    cmd = [
        "ai300-eval",
        "--dry-run",
        "--profile",
        str(profile),
        "--pyrit-target",
        str(target),
    ]
    result = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, f"eval dry-run failed: {result.stderr}\n{result.stdout}"
    return result.stdout


@pytest.fixture(scope="module")
def mock_server():
    """模块级 fixture：启动 Mock LLM 服务，测试结束后关闭"""
    proc = _start_mock_server(MOCK_SERVER_PORT)
    try:
        _wait_for_server(MOCK_SERVER_URL)
        yield MOCK_SERVER_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_end_to_end_recon_attack_eval(mock_server):
    """端到端：侦察 → 攻击 dry-run → 评估 dry-run"""
    # 阶段 1：侦察
    _run_recon(mock_server)
    profile, pyrit_target = _find_latest_recon_outputs()

    # 阶段 2：攻击策略选择
    attack_output = _run_attack_dry_run(profile, pyrit_target)
    assert "Dry-run mode" in attack_output
    assert "jailbreak_direct" in attack_output

    # 阶段 3：评估策略选择
    eval_output = _run_eval_dry_run(profile, pyrit_target)
    assert "Dry-run mode" in eval_output
    assert "robustness" in eval_output
