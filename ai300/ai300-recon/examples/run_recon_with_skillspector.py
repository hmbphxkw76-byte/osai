# -*- coding: utf-8 -*-
"""
示例：先跑通 ai300-recon + SkillSpector（子进程模式）

使用方式：
  1. 确保已安装 SkillSpector：
     cd third_party/skillspector && pip install -e .

  2. 在项目根目录运行：
     python examples/run_recon_with_skillspector.py

  3. 查看 results/recon 和 results/skillspector 输出。

说明：
  - 本脚本默认不启动 AIG 和 RedAmon，因此无需 Docker。
  - SkillSpector 使用 --no-llm 静态扫描，无需配置 LLM API key。
  - 等本流程跑通后，再启用 enable_aig / enable_redamon 进行 Docker 集成。
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import List

# 把项目根目录加入 sys.path，确保能导入 src 包
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv

from src.orchestrator import JobConfig, JobScheduler
from src.integration.skillspector import SkillSpectorMode

# 加载根目录 .env
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def _discover_skill_fixtures(base_dir: str = "third_party/skillspector/tests/fixtures") -> List[str]:
    """自动发现 base_dir 下包含 SKILL.md 的 skill 目录。

    用于演示：一次性扫描多个测试 fixture，观察 SkillSpector 的聚合效果。
    """
    root = Path(_PROJECT_ROOT) / base_dir
    if not root.exists():
        return []

    skills: List[str] = []
    # 只扫描一层子目录（避免嵌套过深导致噪音过大）
    for item in sorted(root.iterdir()):
        if item.is_dir() and (item / "SKILL.md").exists():
            skills.append(str(item.relative_to(_PROJECT_ROOT)).replace("\\", "/"))
    return skills


async def main() -> None:
    """主流程"""
    # 显式读取 .env 中的配置
    target_url = os.getenv("RECON_TARGET_URL", "").strip()
    if not target_url:
        print("错误：未设置 RECON_TARGET_URL 环境变量。请检查 .env 文件。")
        return

    username = os.getenv("RECON_USERNAME", "").strip()
    password = os.getenv("RECON_PASSWORD", "").strip()

    # ------------------------------------------------------------------
    # SkillSpector 输入配置
    # ------------------------------------------------------------------
    # 模式 A（当前）：扫描多个内置测试 fixture，验证多 skill 聚合能力。
    # 模式 B：自动从 recon profile 中提取 skill 路径/URL，留空即可。
    # 模式 C：扫描你自己的 skill 目录，例如：
    #        skillspector_inputs=["path/to/your/skills"]
    # ------------------------------------------------------------------
    skillspector_inputs = _discover_skill_fixtures()
    if not skillspector_inputs:
        # 兜底：至少扫一个经典 fixture
        skillspector_inputs = ["third_party/skillspector/tests/fixtures/mcp_poisoned_tool"]

    print(f"本次将扫描 {len(skillspector_inputs)} 个 skill:")
    for s in skillspector_inputs:
        print(f"  - {s}")

    config = JobConfig(
        target_url=target_url,
        username=username,
        password=password,
        # 只启用 ai300-recon 和 SkillSpector
        enable_ai300_recon=True,
        enable_aig=False,
        enable_redamon=False,
        enable_skillspector=True,
        # SkillSpector 子进程模式
        skillspector_mode=SkillSpectorMode.SUBPROCESS,
        skillspector_no_llm=True,
        skillspector_timeout=300.0,
        skillspector_inputs=skillspector_inputs,
    )

    scheduler = JobScheduler(config)
    result = await scheduler.run()

    print("\n" + "=" * 60)
    print("作业执行结果")
    print("=" * 60)
    print(f"成功: {result.success}")
    print(f"消息: {result.message}")
    print(f"AIG 发现数: {len(result.aig_findings)}")
    print(f"RedAmon 发现数: {len(result.redamon_findings)}")
    print(f"SkillSpector 发现数: {len(result.skillspector_findings)}")
    print(f"统一去重后发现数: {len(result.all_findings)}")

    if result.profile:
        print(f"\n目标: {result.profile.target}")
        print(f"模型名: {result.profile.fingerprint.model_name or '未识别'}")
        print(f"模型族: {result.profile.fingerprint.model_family or '未识别'}")
        print(f"RAG 特征: {result.profile.fingerprint.rag_features}")
        print(f"Agent 特征: {result.profile.fingerprint.agent_features}")

    if result.skillspector_findings:
        print("\nSkillSpector 前 5 条发现:")
        for f in result.skillspector_findings[:5]:
            print(f"  - [{f.severity}] {f.title} ({f.owasp_llm_id})")


if __name__ == "__main__":
    asyncio.run(main())
