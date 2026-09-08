"""
tools/ - CLI 开发/运维工具目录

存放所有带 `if __name__ == "__main__"` 的脚本/工具入口。
这些工具不属于攻击流水线运行时，而是面向开发者/红队操作员的辅助工具。

架构原则 (R-TOOLS-1):
    - `tools/` 集中管理所有 CLI 入口（宪法守卫、hooks 安装、场景列表、PoC 生成）
    - `core/` 禁止存放带 `__main__` 的脚本（纯业务逻辑）
    - `utils/` 禁止存放带 `__main__` 的脚本（纯运行时工具函数）

调用方式:
    py -m tools.guard              # 宪法守卫 (原 py -m core.architecture_guard)
    py -m tools.hooks              # Git hooks 安装 (原 py core/setup_hooks.py)
    py -m tools.scenarios          # 场景列表 (原 py -m core.scenario_router)
    py -m tools.poc                # PoC 生成器 (CLI 模式)

对应 entry_points (pyproject.toml):
    pyrit-guard = "tools.guard:main"
    pyrit-hooks = "tools.hooks:main"
    pyrit-scenarios = "tools.scenarios:main"
    pyrit-poc = "tools.poc:main"
"""
