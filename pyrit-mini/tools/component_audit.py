#!/usr/bin/env python3
"""
tools/component_audit.py — 一键组件审计脚本 (Phase 1→6)

串联组件审计完整流程：
    Phase 1. Baseline Scan       — 基线扫描 (strike/recon/assess/report/tools 全模块组件目录清单)
    Phase 2. Purity Validation  — 组件纯净度验证 (component_purity.py AST+正则全审)
    Phase 3. T0 Coverage        — assess/component_router.py 分类模式 + T0 检查器覆盖
    Phase 4. Scorer/Report Coverage — scorers/ + report 组件感知章节覆盖
    Phase 5. Seed Inventory     — data/seeds/ 种子文件数量与组件类型匹配
    Phase 6. Validation Gate    — pytest + guard + architecture_validator

特性:
    任一步失败立即停止 (fail-fast)
    彩色终端输出 (PASS/FAIL 标记)
    最终汇总报告
    可跳过指定步骤 (--skip 2,3,4)
    支持 verbose 模式 (-v)
    支持单阶段执行 (--phase 3)

调用方式:
    py -m tools.component_audit              # 执行全组件审计 Phase 1→6
    py -m tools.component_audit --skip 4,5   # 跳过 Phase 4 和 5
    py -m tools.component_audit --phase 2    # 仅执行 Purity Validation
    py -m tools.component_audit -v           # 详细输出
    py -m tools.component_audit --no-fail-fast  # 失败继续执行

Academic basis:
    - Eidam et al. (arXiv:2407.16924) — A2A attack taxonomy completeness
    - Greshake et al. (arXiv:2302.12173) — MCP/RAG attack surface mapping
    - OWASP ASI Top 10 2025 — Component-specific technique requirements
"""

from __future__ import annotations

import argparse
import sys

from tools.component_audit_core import run_component_audit


def main() -> int:
    """CLI 入口"""
    parser = argparse.ArgumentParser(
        description="Component Audit Pipeline — Phase 1→6 全组件审计流程一键执行",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  py -m tools.component_audit                # 执行全组件审计 Phase 1→6
  py -m tools.component_audit --skip 4,5     # 跳过 Scorer/Report 和 Seed 阶段
  py -m tools.component_audit --phase 2      # 仅执行 Purity Validation
  py -m tools.component_audit --phase 3      # 仅执行 T0 Coverage 检查
  py -m tools.component_audit -v             # 详细输出 (显示完整命令输出)
  py -m tools.component_audit --no-fail-fast # 失败继续执行后续阶段

快捷词组映射:
  组件审计  ==  py -m tools.component_audit
  架构审计  ==  python tools/architecture_validator.py full  (同 架构体检)
  开发全审  ==  py -m tools.dev_audit_full    (同 全审)
  安全审计  ==  py -m tools.security_audit
  测试审计  ==  py -m tools.test_audit
  依赖审计  ==  py -m tools.dependency_audit
  发布审计  ==  py -m tools.release_audit
        """,
    )
    parser.add_argument(
        "--skip",
        type=str,
        default=None,
        help="跳过的阶段 (逗号分隔, 如: 4,5)",
    )
    parser.add_argument(
        "--phase",
        type=str,
        default=None,
        choices=["1", "2", "3", "4", "5", "6"],
        help="仅执行指定阶段",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="详细输出 (显示完整命令输出)",
    )
    parser.add_argument(
        "--no-fail-fast",
        action="store_true",
        help="失败不停止, 继续执行后续阶段",
    )

    args = parser.parse_args()

    skip_set = set(args.skip.split(",")) if args.skip else None

    return run_component_audit(
        skip=skip_set,
        only=args.phase,
        verbose=args.verbose,
        fail_fast=not args.no_fail_fast,
    )


if __name__ == "__main__":
    sys.exit(main())
