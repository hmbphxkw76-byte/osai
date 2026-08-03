# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""验证流水线环境: 检查 .env / .pyrit_conf / PyRIT 安装 / Registry 状态。.

Usage:
  python scripts/verify_env.py
"""

from __future__ import annotations

import sys
from pathlib import Path


def check_file(path: Path, description: str) -> bool:
    """检查文件是否存在。."""
    exists = path.exists()
    status = "✓" if exists else "✗"
    print(f"  {status} {description}: {path}")
    return exists


def check_pyrit_import() -> bool:
    """检查 PyRIT 是否可导入。."""
    try:
        import pyrit  # noqa: F401

        version = getattr(pyrit, "__version__", "unknown")
        print(f"  ✓ PyRIT 已安装 (版本: {version})")
        return True
    except ImportError as e:
        print(f"  ✗ PyRIT 导入失败: {e}")
        return False


def check_registry() -> bool:
    """检查 Registry 初始化状态 (需先初始化)。."""
    try:
        from pyrit.memory import CentralMemory

        memory = CentralMemory.get_memory_instance()
        db_type = type(memory).__name__
        print(f"  ✓ CentralMemory: {db_type}")
        return True
    except Exception as e:
        print(f"  ✗ CentralMemory 未初始化: {e}")
        return False


def main() -> int:
    """入口, 返回退出码 (0=成功, 1=失败)。."""
    print("=" * 70)
    print("环境验证")
    print("=" * 70)

    cwd = Path.cwd()
    all_ok = True

    # 1. 配置文件
    print("\n--- 配置文件 ---")
    all_ok &= check_file(cwd / ".env", "API 密钥配置")
    all_ok &= check_file(cwd / ".env.example", "环境模板")
    all_ok &= check_file(cwd / "config" / ".pyrit_conf", "PyRIT 结构配置")
    all_ok &= check_file(cwd / ".gitignore", "Git 忽略规则")

    # 2. PyRIT 安装
    print("\n--- PyRIT 安装 ---")
    all_ok &= check_pyrit_import()

    # 3. 目录结构
    print("\n--- 目录结构 ---")
    all_ok &= check_file(cwd / "pipeline" / "__init__.py", "pipeline 模块")
    all_ok &= check_file(cwd / "web_redteam" / "__init__.py", "web_redteam 模块")
    all_ok &= check_file(cwd / "data", "数据集目录")
    all_ok &= check_file(cwd / "docs", "文档目录")
    all_ok &= check_file(cwd / "scripts", "脚本目录")
    all_ok &= check_file(cwd / "output", "输出目录")

    # 4. Registry (可选, 需先初始化)
    print("\n--- Registry 状态 (可选) ---")
    check_registry()  # 不影响 all_ok

    # 5. 测试
    print("\n--- 测试 ---")
    all_ok &= check_file(cwd / "conftest.py", "全局 conftest")
    all_ok &= check_file(cwd / "pipeline" / "tests", "pipeline 测试")
    all_ok &= check_file(cwd / "web_redteam" / "tests", "web_redteam 测试")

    print("\n" + "=" * 70)
    if all_ok:
        print("✓ 环境验证通过")
    else:
        print("✗ 环境验证失败, 请检查上述 ✗ 项")
    print("=" * 70)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
