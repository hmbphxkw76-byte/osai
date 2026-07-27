# -*- coding: utf-8 -*-
"""
端到端流水线示例
================

演示如何串联三个独立项目：
  1. ai300-recon：侦察目标 LLM Web 应用
  2. ai300-attack：根据侦察结果选择攻击策略
  3. ai300-eval-kit：根据侦察结果选择评估策略

本示例默认使用 dry-run 模式，不需要安装 Garak / Giskard 等重型依赖。

用法：
  python examples/end_to_end_pipeline.py --target http://127.0.0.1:18080
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import httpx

# 项目根目录（本文件位于 examples/）
ROOT = Path(__file__).resolve().parents[1]


def _run_command(cmd: list[str], cwd: Path = ROOT, env_extra: dict[str, str] | None = None) -> str:
    """运行子进程命令，返回 stdout；失败时抛出 RuntimeError"""
    env = dict(subprocess.os.environ)
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def _start_mock_server(port: int = 18080) -> subprocess.Popen:
    """启动本地 Mock LLM 服务（用于测试）"""
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


def _wait_for_server(url: str, timeout: float = 10.0) -> None:
    """轮询等待服务就绪"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=1.0)
            if response.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"Server not reachable within {timeout}s: {url}")


def run_recon(target_url: str) -> tuple[Path, Path]:
    """运行侦察并返回最新 profile 与 PyRIT target 路径"""
    print(f"[1/3] Running recon for {target_url} ...")
    env_extra = {
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
    _run_command(cmd, env_extra=env_extra)

    # 查找最新输出
    profile_dir = ROOT / "results" / "recon" / "profiles"
    pyrit_dir = ROOT / "results" / "recon" / "pyrit"
    profiles = sorted(profile_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    targets = sorted(pyrit_dir.glob("*_pyrit_target.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not profiles or not targets:
        raise RuntimeError("Recon did not generate profile or PyRIT target")
    return profiles[0], targets[0]


def run_attack_dry_run(profile: Path, target: Path) -> str:
    """运行攻击 dry-run 并返回输出"""
    print("[2/3] Running attack toolkit (dry-run) ...")
    cmd = [
        "ai300-attack",
        "--dry-run",
        "--profile",
        str(profile),
        "--pyrit-target",
        str(target),
    ]
    return _run_command(cmd)


def run_eval_dry_run(profile: Path, target: Path) -> str:
    """运行评估 dry-run 并返回输出"""
    print("[3/3] Running eval toolkit (dry-run) ...")
    cmd = [
        "ai300-eval",
        "--dry-run",
        "--profile",
        str(profile),
        "--pyrit-target",
        str(target),
    ]
    return _run_command(cmd)


def main() -> int:
    """示例入口"""
    parser = argparse.ArgumentParser(description="End-to-end recon → attack → eval pipeline example")
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:18080",
        help="Target LLM Web app URL (default: local mock server)",
    )
    parser.add_argument(
        "--start-mock",
        action="store_true",
        help="Start the local mock LLM server before running the pipeline",
    )
    args = parser.parse_args()

    mock_proc = None
    try:
        if args.start_mock:
            print("Starting mock LLM server ...")
            mock_proc = _start_mock_server()
            _wait_for_server(args.target)

        profile, pyrit_target = run_recon(args.target)
        print(f"  Profile: {profile}")
        print(f"  PyRIT target: {pyrit_target}")

        attack_output = run_attack_dry_run(profile, pyrit_target)
        print("\nAttack strategies selected:")
        for line in attack_output.splitlines():
            if " - " in line:
                print(f"  {line.strip()}")

        eval_output = run_eval_dry_run(profile, pyrit_target)
        print("\nEval strategies selected:")
        for line in eval_output.splitlines():
            if " - " in line:
                print(f"  {line.strip()}")

        print("\nPipeline completed successfully.")
        return 0
    finally:
        if mock_proc is not None:
            mock_proc.terminate()
            try:
                mock_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mock_proc.kill()


if __name__ == "__main__":
    sys.exit(main())
