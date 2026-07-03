"""
===============================================================================
            OffSec AI-300 综合红队演练模块（Crescendo版本）
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 json_crescendo/crescendo_capstone_red_team_engagement_cases.json 文件中的 test_cases 列表

3. 运行方式：
   └── py.exe '.\\json_crescendo\\crescendo_capstone_red_team_engagement.py'

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
    CrescendoAttack,
)
from pyrit.output.attack_result.pretty import PrettyAttackResultMemoryPrinter

async def crescendo_capstone_red_team_engagement():
    config = load_config(__file__, 'crescendo_capstone_red_team_engagement_cases.json')
    ATTACK_TEST_CASES = config.get('test_cases', [])
    MAX_TURNS = config.get('max_turns', 10)
    MAX_BACKTRACKS = config.get('max_backtracks', 4)
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    print("\n" + "="*80)
    print("🚀 OffSec AI-300 综合红队演练（Crescendo版本）")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🔄 最大对话轮数: {MAX_TURNS}")
    print(f"↩️  最大回溯次数: {MAX_BACKTRACKS}")
    print("="*80)
    for case in ATTACK_TEST_CASES:
        print(f"   用例 {case['id']}: {case['objective']}")
    print("="*80 + "\n")

    results = []

    for case in ATTACK_TEST_CASES:
        print(f"\n{'='*80}")
        print(f"📌 测试用例 {case['id']}: {case['objective']}")
        print(f"{'='*80}")

        scorer = SelfAskTrueFalseScorer(
            chat_target=OpenAIChatTarget(),
            true_false_question=TrueFalseQuestion(
                true_description=case["criterion"]
            ),
        )

        attack = CrescendoAttack(
            objective_target=OpenAIChatTarget(),
            attack_adversarial_config=AttackAdversarialConfig(
                target=OpenAIChatTarget()
            ),
            attack_scoring_config=AttackScoringConfig(
                objective_scorer=scorer
            ),
            max_turns=MAX_TURNS,
            max_backtracks=MAX_BACKTRACKS,
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

asyncio.run(crescendo_capstone_red_team_engagement())