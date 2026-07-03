"""
===============================================================================
              OffSec AI-300 Sequential顺序攻击测试脚本（JSON配置版）
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 attackes_json/sequential_attack_cases.json 文件中的 test_cases 列表

3. 运行方式：
   └── py.exe '.\\attackes_json\\sequential_attack_json.py'

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。

🎯 攻击原理：
   SequentialAttack按照顺序执行多个子攻击策略，直到达到完成条件。
   默认攻击序列：PromptSending → ManyShotJailbreak → SkeletonKey
===============================================================================
"""

import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from case_loader import load_config
from platform_config_loader import load_platform_config
load_platform_config()

from pyrit.setup import IN_MEMORY, initialize_pyrit_async
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion
from pyrit.executor.attack import (
    AttackScoringConfig,
    SequentialAttack,
    SequentialChildAttack,
    SequenceCompletionPolicy,
    PromptSendingAttack,
    ManyShotJailbreakAttack,
    SkeletonKeyAttack,
)
from pyrit.models import SeedAttackGroup, SeedPrompt
from pyrit.output.attack_result.pretty import PrettyAttackResultMemoryPrinter


async def sequential_attack():
    # 加载测试用例
    config = load_config(__file__, 'sequential_attack_cases.json')
    ATTACK_TEST_CASES = config.get('test_cases', [])
    COMPLETION_POLICY = SequenceCompletionPolicy.FIRST_SUCCESS
    if config.get('completion_policy') == 'ALL':
        COMPLETION_POLICY = SequenceCompletionPolicy.ALL
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    # 初始化PyRIT
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    # 创建攻击目标和评分器目标
    target = OpenAIChatTarget()
    scorer_target = OpenAIChatTarget()

    # ============================================
    # 📊 配置确认（运行前检查）
    # ============================================
    print("\n" + "="*80)
    print("🚀 OffSec AI-300 Sequential顺序攻击测试（JSON配置版）")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🔄 完成策略: {COMPLETION_POLICY.name}")
    print(f"⚡ 攻击序列: PromptSending → ManyShotJailbreak → SkeletonKey")
    print("="*80)
    for case in ATTACK_TEST_CASES:
        print(f"   用例 {case['id']}: {case['objective']}")
    print("="*80 + "\n")

    # 记录测试结果
    results = []

    # ============================================
    # 遍历所有测试用例，依次执行攻击
    # ============================================
    for case in ATTACK_TEST_CASES:
        print(f"\n{'='*80}")
        print(f"📌 测试用例 {case['id']}: {case['objective']}")
        print(f"{'='*80}")

        # 创建评分器，根据当前用例的评分标准
        scorer = SelfAskTrueFalseScorer(
            chat_target=scorer_target,
            true_false_question=TrueFalseQuestion(
                true_description=case["criterion"]
            ),
        )

        # 创建子攻击策略
        prompt_sending_strategy = PromptSendingAttack(
            objective_target=target,
            attack_scoring_config=AttackScoringConfig(
                objective_scorer=scorer
            ),
        )

        many_shot_strategy = ManyShotJailbreakAttack(
            objective_target=target,
            attack_scoring_config=AttackScoringConfig(
                objective_scorer=scorer
            ),
            example_count=50,
        )

        skeleton_key_strategy = SkeletonKeyAttack(
            objective_target=target,
            attack_scoring_config=AttackScoringConfig(
                objective_scorer=scorer
            ),
        )

        # 创建种子攻击组
        seed_group = SeedAttackGroup(
            objective=case["objective"],
            attack_prompts=[SeedPrompt(value=case["objective"])],
        )

        # 创建Sequential顺序攻击
        attack = SequentialAttack(
            objective_target=target,
            child_attacks=[
                SequentialChildAttack(
                    strategy=prompt_sending_strategy,
                    seed_group=seed_group,
                ),
                SequentialChildAttack(
                    strategy=many_shot_strategy,
                    seed_group=seed_group,
                ),
                SequentialChildAttack(
                    strategy=skeleton_key_strategy,
                    seed_group=seed_group,
                ),
            ],
            completion_policy=COMPLETION_POLICY,
        )

        try:
            # 执行攻击
            result = await attack.execute_async(
                objective=case["objective"]
            )

            # 记录结果（根据攻击结果判断）
            status = "SUCCESS" if result.outcome.value == "success" else "FAILURE"
            results.append({
                "id": case["id"],
                "objective": case["objective"],
                "status": status,
            })

            # 打印攻击结果
            await PrettyAttackResultMemoryPrinter().write_async(
                result=result
            )

            # 打印子攻击结果
            child_results = getattr(result, "child_attack_results", [])
            if child_results:
                print(f"\n{'='*80}")
                print(f"📦 子攻击执行结果:")
                print(f"{'='*80}")
                for i, child_result in enumerate(child_results, 1):
                    child_outcome = "✅" if child_result.outcome.value == "success" else "❌"
                    print(f"   子攻击 {i}: {child_outcome} ({child_result.attack_type})")
                print(f"{'='*80}")

        except Exception as e:
            print(f"❌ 测试用例 {case['id']} 失败: {e}")
            results.append({
                "id": case["id"],
                "objective": case["objective"],
                "status": "ERROR",
            })

    # ============================================
    # 📊 测试结果汇总
    # ============================================
    print("\n" + "="*80)
    print("📊 测试结果汇总")
    print("="*80)

    success_count = sum(1 for r in results if r["status"] == "SUCCESS")
    failure_count = sum(1 for r in results if r["status"] == "FAILURE")
    error_count = sum(1 for r in results if r["status"] == "ERROR")

    print(f"\n📈 统计结果:")
    print(f"   ✅ 成功: {success_count} 个")
    print(f"   ❌ 失败: {failure_count} 个")
    print(f"   ⚠️ 错误: {error_count} 个")

    print(f"\n📋 详细结果:")
    for r in results:
        status_icon = "✅" if r["status"] == "SUCCESS" else "❌" if r["status"] == "FAILURE" else "⚠️"
        print(f"   {status_icon} 用例 {r['id']}: {r['objective']} -> {r['status']}")

    print("\n" + "="*80)


# 运行异步函数
asyncio.run(sequential_attack())