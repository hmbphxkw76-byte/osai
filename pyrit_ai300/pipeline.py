#!/usr/bin/env python3
"""
PyRIT 端到端全自动 AI 红队框架 - 主入口
============================================

本框架基于 PyRIT 0.14.0 构建，为 OffSec AI-300 考试和实际 AI 红队评估提供
数据驱动的端到端全自动提示词层面攻击流程。

流程:
  1. 加载配置（.env 环境变量）
  2. 初始化 PyRIT（SQLite Memory）
  3. 侦察阶段（端点发现 + AI 类型识别）
  4. 分析阶段（策略选择 + 优先级评估）
  5. 加载数据源（从 OWASP 目录批量加载提示词）
  6. 载荷规划（将提示词转化为攻击计划）
  7. 批量执行攻击（单轮/多轮/编码增强/顺序组合）
  8. 输出执行结果
  9. 报告生成（OWASP 映射 + 证据导出）

Usage:
  python pipeline.py
  python pipeline.py http://192.168.0.22:11434
"""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from pyrit.setup import initialize_pyrit_async
from pyrit.prompt_target import OpenAIChatTarget

# 导入框架模块
from src.core.config_loader import get_config_loader
from src.core.models import AuthResult, AuthStatus, AuthType
from src.recon import recon_target
from src.analysis import select_strategy, evaluate_priority
from src.payloads import load_payloads, plan_attacks
from src.orchestrators import execute_batch_attacks
from src.reporting import generate_report

# Fix Windows terminal Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ============================================================
# 顺序管道
# ============================================================


async def run_attack_pipeline(target_url: str, owasp_ids: list[str] | None = None):
    """
    执行完整的攻击流程（顺序管道）

    流程: 侦察 → 分析 → 加载数据源 → 载荷规划 → 批量攻击 → 输出 → 报告

    Args:
        target_url: 目标 URL (如 http://192.168.0.22:11434)
        owasp_ids: 指定 OWASP 分类列表 (如 ["llm01", "llm06"])，
                   None 表示加载全部
    """
    config_loader = get_config_loader()
    start_time = datetime.now()

    # 从环境变量读取配置
    target_endpoint = os.getenv("TARGET_ENDPOINT", f"{target_url.rstrip('/')}/v1")
    target_model = os.getenv("TARGET_MODEL", "qwen3:0.6b")
    target_api_key = os.getenv("TARGET_API_KEY", "ollama")

    judge_endpoint = os.getenv("JUDGE_ENDPOINT", target_endpoint)
    judge_model = os.getenv("JUDGE_MODEL", "qwen3:1.7b")
    judge_api_key = os.getenv("JUDGE_API_KEY", "ollama")

    print("\n" + "=" * 60)
    print("  PyRIT 端到端全自动 AI 红队框架 (批量多源攻击)")
    print("=" * 60)
    print(f"\n目标 URL: {target_url}")
    print(f"目标端点: {target_endpoint}")
    print(f"目标模型: {target_model}")
    print(f"评分器端点: {judge_endpoint}")
    print(f"评分器模型: {judge_model}")
    print(f"开始时间: {start_time.isoformat()}")

    # ---------------------------------------------------------
    # 1. 初始化 PyRIT
    # ---------------------------------------------------------
    print("\n[1/9] 初始化 PyRIT...")
    db_path = Path(os.getenv("MEMORY_DB_PATH", "output/exam_results.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    await initialize_pyrit_async(
        memory_db_type=config_loader.get_memory_db_type(),
        db_path=str(db_path),
        silent=False,
    )
    print(f"  [OK] Memory 后端: {config_loader.get_memory_db_type()}")
    print(f"  [OK] 数据库路径: {db_path}")

    # ---------------------------------------------------------
    # 2. 侦察阶段（端点发现 + AI 类型识别）
    # ---------------------------------------------------------
    print("\n[2/9] 执行侦察...")
    recon_result = await recon_target(target_url)
    print(f"  [OK] 检测端点: {recon_result.detected_endpoint}")
    print(f"  [OK] 认证类型: {recon_result.auth_type.value}")
    print(f"  [OK] AI 系统类型: {recon_result.ai_system_type.value}")

    # 检查是否为 PyRIT 可攻击类型
    if not recon_result.ai_system_type.is_pyrit_attackable():
        print(f"\n  [!] 该类型 ({recon_result.ai_system_type.value}) 非提示词攻击领域")
        print(f"  [!] 推荐外部工具: {', '.join(recon_result.external_tools or [])}")
        print("\n  跳过 PyRIT 攻击")
        return None

    # ---------------------------------------------------------
    # 3. 分析阶段（策略选择 + 优先级评估）
    # ---------------------------------------------------------
    print("\n[3/9] 执行分析（策略选择 + 优先级评估）...")

    # 构造认证结果（Ollama 无需认证）
    auth_result = AuthResult(
        target_url=target_url,
        auth_type=AuthType.NONE,
        status=AuthStatus.SUCCESS,
        auth_headers={"Content-Type": "application/json"},
    )

    # 策略选择
    strategy_selection = select_strategy(auth_result, recon_result)
    print(f"  [OK] 选择 Scenario: {strategy_selection.scenario_name}")
    print(f"  [OK] 攻击技术: {', '.join(strategy_selection.attack_techniques)}")

    # 优先级评估
    priority_score = evaluate_priority(recon_result)
    print(f"  [OK] 目标优先级: {priority_score}/100")

    # ---------------------------------------------------------
    # 4. 加载数据源（从 OWASP 目录批量加载提示词）
    # ---------------------------------------------------------
    print("\n[4/9] 加载数据源...")

    # CLI 参数优先于配置文件
    config_owasp_ids = owasp_ids if owasp_ids else config_loader.get_owasp_source_ids()
    exclude_ids = config_loader.get_owasp_exclude_ids()
    include_custom = config_loader.is_custom_source_enabled()

    if config_owasp_ids:
        print(f"  [OK] OWASP 筛选: {', '.join(config_owasp_ids)}")

    prompt_batches = load_payloads(
        owasp_ids=config_owasp_ids if config_owasp_ids else None,
        exclude_ids=exclude_ids if exclude_ids else None,
        include_custom=include_custom,
    )

    total_prompts = sum(len(batch.prompts) for batch in prompt_batches)
    print(f"  [OK] 加载批次: {len(prompt_batches)} 个")
    print(f"  [OK] 提示词总数: {total_prompts} 个")

    # 统计各攻击模式的数量
    from src.payloads.models import AttackMode
    mode_counts = {}
    for batch in prompt_batches:
        for item in batch.prompts:
            mode_counts[item.attack_mode.value] = mode_counts.get(item.attack_mode.value, 0) + 1
    for mode, count in sorted(mode_counts.items()):
        print(f"    - {mode}: {count} 个")

    if not prompt_batches:
        print("  [!] 未加载到任何提示词数据，跳过攻击")
        return None

    # ---------------------------------------------------------
    # 5. 载荷规划（将提示词转化为攻击计划）
    # ---------------------------------------------------------
    print("\n[5/9] 载荷规划...")
    attack_plans = plan_attacks(prompt_batches, strategy_selection)
    print(f"  [OK] 生成攻击计划: {len(attack_plans)} 个")

    # 按攻击模式统计计划数
    plan_mode_counts = {}
    for plan in attack_plans:
        mode = plan.prompt_item.attack_mode.value
        plan_mode_counts[mode] = plan_mode_counts.get(mode, 0) + 1
    for mode, count in sorted(plan_mode_counts.items()):
        print(f"    - {mode}: {count} 个计划")

    # 统计攻击技术分布（回归 PyRIT 原生 Attack 类）
    technique_counts = {}
    scorer_counts = {}
    for plan in attack_plans:
        technique_counts[plan.attack_technique] = technique_counts.get(plan.attack_technique, 0) + 1
        scorer_counts[plan.scorer_type] = scorer_counts.get(plan.scorer_type, 0) + 1
    print(f"  [OK] 攻击技术分布:")
    for tech, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
        print(f"    - {tech}: {count} 个")
    print(f"  [OK] 评分器类型分布:")
    for s_type, count in sorted(scorer_counts.items(), key=lambda x: -x[1]):
        print(f"    - {s_type}: {count} 个")

    # ---------------------------------------------------------
    # 6. 创建攻击组件 + 批量执行攻击
    # ---------------------------------------------------------
    print("\n[6/9] 创建攻击组件并批量执行...")

    # 创建目标 Target
    objective_target = OpenAIChatTarget(
        endpoint=target_endpoint,
        api_key=target_api_key,
        model_name=target_model,
    )
    print(f"  [OK] 目标 Target: OpenAIChatTarget ({target_model})")

    # 创建评分器 Target
    judge_target = OpenAIChatTarget(
        endpoint=judge_endpoint,
        api_key=judge_api_key,
        model_name=judge_model,
    )
    print(f"  [OK] 评分器 Target: OpenAIChatTarget ({judge_model})")
    print(f"  [OK] 评分器同时用作 adversarial chat (多轮攻击)")

    # 批量执行（CLI 环境变量可覆盖配置文件值）
    max_concurrency = int(os.getenv("BATCH_MAX_CONCURRENCY", config_loader.get_batch_max_concurrency()))
    fail_fast = config_loader.is_batch_fail_fast()
    per_attack_timeout = int(os.getenv("BATCH_PER_ATTACK_TIMEOUT", config_loader.get_batch_per_attack_timeout()))

    print(f"  [OK] 最大并发: {max_concurrency}")
    print(f"  [OK] 单次超时: {per_attack_timeout}s")
    print(f"  [OK] 开始执行 {len(attack_plans)} 个攻击计划...\n")

    batch_result = await execute_batch_attacks(
        attack_plans=attack_plans,
        objective_target=objective_target,
        judge_target=judge_target,
        max_concurrency=max_concurrency,
        fail_fast=fail_fast,
        per_attack_timeout=per_attack_timeout,
    )

    print(f"\n  [OK] 批量攻击完成")
    print(f"  [OK] 总计划: {batch_result.total_plans}")
    print(f"  [OK] 已执行: {batch_result.executed}")
    print(f"  [OK] 成功: {batch_result.succeeded}")
    print(f"  [OK] 失败: {batch_result.failed}")
    print(f"  [OK] 错误: {batch_result.errored}")
    print(f"  [OK] 成功率: {batch_result.success_rate * 100:.1f}%")

    if batch_result.errors:
        print(f"\n  [!] 错误详情 ({len(batch_result.errors)} 个):")
        for err in batch_result.errors[:5]:
            print(f"    - {err.get('plan_id', 'N/A')}: {err.get('error', 'N/A')}")
        if len(batch_result.errors) > 5:
            print(f"    ... 还有 {len(batch_result.errors) - 5} 个错误")

    # ---------------------------------------------------------
    # 7. 输出执行结果
    # ---------------------------------------------------------
    print("\n[7/9] 输出执行结果...")

    from pyrit.output import output_attack_async
    # 输出前 5 个成功的结果
    success_results = [r for r in batch_result.results if r is not None]
    for i, result in enumerate(success_results[:5]):
        print(f"\n  --- 结果 {i + 1}/{min(5, len(success_results))} ---")
        try:
            await output_attack_async(result, format="pretty")
        except Exception:
            print(f"  [!] 输出结果 {i + 1} 时出错")

    if len(success_results) > 5:
        print(f"\n  ... 还有 {len(success_results) - 5} 个结果未显示")

    print("\n  [OK] 执行结果输出完成")

    # ---------------------------------------------------------
    # 8. 报告生成（OWASP 映射 + 证据导出）
    # ---------------------------------------------------------
    print("\n[8/9] 生成报告...")
    end_time = datetime.now()
    exam_id = f"exam_{start_time.strftime('%Y%m%d_%H%M%S')}"

    # 生成报告
    report_result = await generate_report(
        scenario_result=batch_result.results,
        exam_id=exam_id,
        start_time=start_time,
        end_time=end_time,
    )

    print(f"  [OK] 报告路径: {report_result.report_path}")
    print(f"  [OK] 证据包: {report_result.evidence_archive}")
    print(f"  [OK] 发现漏洞: {len(report_result.owasp_findings)} 个")
    print(f"  [OK] 攻击总数: {report_result.summary.total_attacks}")
    print(f"  [OK] 成功攻击: {report_result.summary.successful_attacks}")
    print(f"  [OK] 成功率: {report_result.summary.success_rate * 100:.1f}%")

    # ---------------------------------------------------------
    # 9. 总结
    # ---------------------------------------------------------
    print("\n[9/9] Pipeline 总结")
    print("\n" + "=" * 60)
    print("  Pipeline 完成")
    print("=" * 60)
    print(f"总用时: {end_time - start_time}")
    print(f"数据源: {len(prompt_batches)} 批次, {total_prompts} 提示词")
    print(f"攻击计划: {batch_result.total_plans} 个")
    print(f"执行结果: {batch_result.succeeded}/{batch_result.executed} 成功")
    print(f"报告: {report_result.report_path}")
    print(f"证据: {report_result.evidence_archive}")

    return report_result


# ============================================================
# 主入口
# ============================================================


def main():
    """主入口（简易模式，完整 CLI 见 cli.py）"""
    # 加载环境变量 (从项目根目录的 .env 文件)
    project_root = Path(__file__).parent
    env_path = project_root / ".env"
    load_dotenv(env_path)

    print(f"加载环境变量: {env_path}")

    # 获取目标 URL (从环境变量或命令行参数)
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        # 从环境变量读取目标端点，提取基础 URL
        target_endpoint = os.getenv("TARGET_ENDPOINT", "http://localhost:11434/v1")
        # 去掉 /v1 后缀得到基础 URL
        if target_endpoint.endswith("/v1"):
            target_url = target_endpoint[:-3]
        else:
            target_url = target_endpoint

    # 运行管道
    asyncio.run(run_attack_pipeline(target_url))


if __name__ == "__main__":
    main()
