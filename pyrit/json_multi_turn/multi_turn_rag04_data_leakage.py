"""
===============================================================================
                    OffSec AI-300 Multi-Turn RAG04 攻击脚本
===============================================================================
漏洞类型：RAG04 - Data Leakage
攻击策略：多轮对话逐步获取泄露的数据，包括PII、商业机密、内部文档等

📋 使用说明：
1. 配置 .env 文件（PLATFORM_SELECTOR 及对应平台 API Key）
2. 修改 JSON 文件配置测试用例（无需修改 .py）
3. 运行方式：py.exe '.\\json_multi_turn\\multi_turn_rag04_data_leakage.py'

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。
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
    AttackAdversarialConfig,
    AttackScoringConfig,
    RedTeamingAttack,
    RTASystemPromptPaths,
)
from pyrit.output.attack_result.pretty import PrettyAttackResultMemoryPrinter

async def multi_turn_rag04_attack():
    config = load_config(__file__, 'multi_turn_rag04_data_leakage_cases.json')
    ATTACK_TEST_CASES = config.get('test_cases', [])
    MAX_TURNS = config.get('max_turns', 5)
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    print("\n" + "="*80)
    print("🚀 OffSec AI-300 Multi-Turn RAG04 - Data Leakage")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🔄 最大对话轮数: {MAX_TURNS}")
    print("="*80)
    for case in ATTACK_TEST_CASES:
        print(f"   用例 {case['id']}: {case['objective']}")
    print("="*80 + "\n")

    results = []

    for case in ATTACK_TEST_CASES:
        print(f"\n{'='*80}")
        print(f"📌 测试用例 {case['id']}: {case['objective']}")
        print(f"{'='*80}")

        adversarial_chat = OpenAIChatTarget()
        objective_target = OpenAIChatTarget()

        adversarial_config = AttackAdversarialConfig(
            target=adversarial_chat,
            system_prompt_path=RTASystemPromptPaths.TEXT_GENERATION.value,
        )

        scoring_config = AttackScoringConfig(
            objective_scorer=SelfAskTrueFalseScorer(
                chat_target=OpenAIChatTarget(),
                true_false_question=TrueFalseQuestion(
                    true_description=case["criterion"]
                ),
            ),
        )

        attack = RedTeamingAttack(
            objective_target=objective_target,
            attack_adversarial_config=adversarial_config,
            attack_scoring_config=scoring_config,
            max_turns=MAX_TURNS,
        )

        try:
            result = await attack.execute_async(objective=case["objective"])

            status = "SUCCESS" if result.outcome.value == "success" else "FAILURE"
            results.append({
                "id": case["id"],
                "objective": case["objective"],
                "status": status,
            })

            await PrettyAttackResultMemoryPrinter().write_async(result=result)

        except Exception as e:
            print(f"❌ 测试用例 {case['id']} 失败: {e}")
            results.append({
                "id": case["id"],
                "objective": case["objective"],
                "status": "ERROR",
            })

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

asyncio.run(multi_turn_rag04_attack())
