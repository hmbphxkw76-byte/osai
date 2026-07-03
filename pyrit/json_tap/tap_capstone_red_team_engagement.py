"""
===============================================================================
              OffSec AI-300 综合红队演练 TAP攻击脚本（并行尝试多种攻击路径）
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 json_tap/tap_capstone_red_team_engagement_cases.json 文件中的 test_cases 列表

3. 运行方式：
   └── py.exe '.\\json_tap\\tap_capstone_red_team_engagement.py'

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
from pyrit.score import FloatScaleThresholdScorer
from pyrit.score.float_scale.self_ask_scale_scorer import SelfAskScaleScorer
from pyrit.executor.attack import (
    AttackAdversarialConfig,
    AttackScoringConfig,
    TAPAttack,
)
from pyrit.output.attack_result.pretty import PrettyAttackResultMemoryPrinter

async def tap_capstone_red_team_engagement():
    config = load_config(__file__, 'tap_capstone_red_team_engagement_cases.json')
    ATTACK_TEST_CASES = config.get('test_cases', [])
    TREE_WIDTH = config.get('tree_width', 4)
    TREE_DEPTH = config.get('tree_depth', 5)
    ON_TOPIC_CHECKING = config.get('on_topic_checking', True)
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    print("\n" + "="*80)
    print("🚀 OffSec AI-300 综合红队演练 TAP攻击扫描（并行尝试多种攻击路径）")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🌳 树宽度(Tree Width): {TREE_WIDTH}")
    print(f"📏 树深度(Tree Depth): {TREE_DEPTH}")
    print(f"🎯 主题检查: {'开启' if ON_TOPIC_CHECKING else '关闭'}")
    print("="*80)
    for case in ATTACK_TEST_CASES:
        print(f"   用例 {case['id']}: {case['objective']}")
    print("="*80 + "\n")

    results = []

    for case in ATTACK_TEST_CASES:
        print(f"\n{'='*80}")
        print(f"📌 测试用例 {case['id']}: {case['objective']}")
        print(f"{'='*80}")

        scorer = FloatScaleThresholdScorer(
            scorer=SelfAskScaleScorer(
                chat_target=OpenAIChatTarget(),
            ),
            threshold=0.7,
        )

        attack = TAPAttack(
            objective_target=OpenAIChatTarget(),
            attack_adversarial_config=AttackAdversarialConfig(
                target=OpenAIChatTarget(temperature=1.0)
            ),
            attack_scoring_config=AttackScoringConfig(
                objective_scorer=scorer
            ),
            on_topic_checking_enabled=ON_TOPIC_CHECKING,
            tree_width=TREE_WIDTH,
            tree_depth=TREE_DEPTH,
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

asyncio.run(tap_capstone_red_team_engagement())