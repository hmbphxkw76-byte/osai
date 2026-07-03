"""
===============================================================================
                    OffSec AI-300 多轮攻击测试脚本（JSON配置版）
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 json/multi_turn_attack_cases.json 文件中的 test_cases 列表

3. 运行方式：
   └── py.exe '.\\json\\multi_turn_attack_json.py'

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

async def multi_turn_attack():
    # 加载测试用例
    config = load_config(__file__, 'multi_turn_attack_cases.json')
    ATTACK_TEST_CASES = config.get('test_cases', [])
    MAX_TURNS = config.get('max_turns', 5)
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    # 初始化PyRIT
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    # ============================================
    # 📊 配置确认（运行前检查）
    # ============================================
    print("\n" + "="*80)
    print("🚀 OffSec AI-300 多轮攻击测试（JSON配置版）")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🔄 最大对话轮数: {MAX_TURNS}")
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

        # 创建对抗性聊天目标和目标目标
        adversarial_chat = OpenAIChatTarget()
        objective_target = OpenAIChatTarget()

        # 创建对抗性配置
        adversarial_config = AttackAdversarialConfig(
            target=adversarial_chat,
            system_prompt_path=RTASystemPromptPaths.TEXT_GENERATION.value,
        )

        # 创建评分配置
        scoring_config = AttackScoringConfig(
            objective_scorer=SelfAskTrueFalseScorer(
                chat_target=OpenAIChatTarget(),
                true_false_question=TrueFalseQuestion(
                    true_description=case["criterion"]
                ),
            ),
        )

        # 创建多轮攻击
        attack = RedTeamingAttack(
            objective_target=objective_target,
            attack_adversarial_config=adversarial_config,
            attack_scoring_config=scoring_config,
            max_turns=MAX_TURNS,
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
asyncio.run(multi_turn_attack())
