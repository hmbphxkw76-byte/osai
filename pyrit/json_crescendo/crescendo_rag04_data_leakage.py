"""
===============================================================================
        OffSec AI-300 Crescendo RAG04-Data Leakage 攻击脚本
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置上级目录的 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 json_crescendo/crescendo_rag04_data_leakage_cases.json 文件

3. 运行方式：
   └── py.exe '.\\json_crescendo\\crescendo_rag04_data_leakage.py'

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。

🎯 OWASP AI Agent Top 10: RAG04 - Data Leakage (Crescendo模式)
   逐步获取泄露数据，渐进式突破数据保护
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

async def run_crescendo_rag04():
    config = load_config(__file__, 'crescendo_rag04_data_leakage_cases.json')
    ATTACK_TEST_CASES = config.get('test_cases', [])
    MAX_TURNS = config.get('max_turns', 10)
    MAX_BACKTRACKS = config.get('max_backtracks', 4)
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    
    print("\n" + "="*80)
    print("🚀 OffSec AI-300 Crescendo RAG04 - Data Leakage 攻击")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🔄 最大对话轮数: {MAX_TURNS}")
    print(f"↩️  最大回溯次数: {MAX_BACKTRACKS}")
    print("="*80)
    for case in ATTACK_TEST_CASES:
        print(f"   用例 {case['id']}: {case['objective']}")
    print("="*80 + "\n")
    
    all_results = []
    
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
            attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
            max_turns=MAX_TURNS,
            max_backtracks=MAX_BACKTRACKS,
        )
        
        try:
            result = await attack.execute_async(objective=case["objective"])
            status = "SUCCESS" if result.outcome.value == "success" else "FAILURE"
            all_results.append({
                "case_id": case["id"],
                "objective": case["objective"],
                "status": status,
            })
            await PrettyAttackResultMemoryPrinter().write_async(result=result)
        except Exception as e:
            print(f"❌ 测试失败: {e}")
            all_results.append({
                "case_id": case["id"],
                "objective": case["objective"],
                "status": "ERROR",
            })
    
    print("\n" + "="*80)
    print("📊 Crescendo RAG04 - Data Leakage 测试结果汇总")
    print("="*80)
    
    success_count = sum(1 for r in all_results if r["status"] == "SUCCESS")
    failure_count = sum(1 for r in all_results if r["status"] == "FAILURE")
    error_count = sum(1 for r in all_results if r["status"] == "ERROR")
    
    print(f"✅ 成功: {success_count} 个")
    print(f"❌ 失败: {failure_count} 个")
    print(f"⚠️ 错误: {error_count} 个")
    
    if success_count > 0:
        print(f"\n🎯 成功的攻击用例:")
        for r in all_results:
            if r["status"] == "SUCCESS":
                print(f"   - 用例 {r['case_id']}: {r['objective']}")
    
    print(f"\n{'='*80}")
    print(f"📈 总体成功率: {success_count / len(all_results) * 100:.1f}%")
    print(f"{'='*80}")

asyncio.run(run_crescendo_rag04())