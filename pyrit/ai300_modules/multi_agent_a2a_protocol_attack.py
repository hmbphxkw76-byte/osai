"""
===============================================================================
              OffSec AI-300 多代理系统与A2A协议攻击模块（JSON配置版）
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 ai300_modules/multi_agent_a2a_protocol_attack_cases.json 文件中的 test_cases 列表

3. 运行方式：
   └── py.exe '.\\ai300_modules\\multi_agent_a2a_protocol_attack.py'

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。
===============================================================================
"""

import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from case_loader import load_test_cases
from platform_config_loader import load_platform_config
load_platform_config()

from pyrit.setup import IN_MEMORY, initialize_pyrit_async
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion
from pyrit.executor.attack import (
    AttackScoringConfig,
    PromptSendingAttack,
)
from pyrit.output.attack_result.pretty import PrettyAttackResultMemoryPrinter

from pyrit.executor.attack import AttackConverterConfig
from pyrit.prompt_converter import (
    Base64Converter,
    ZeroWidthConverter,
    UnicodeConfusableConverter,
)
from pyrit.prompt_normalizer import PromptConverterConfiguration

ATTACK_CONVERTER_CONFIGS = [
    {
        "name": "Base64编码",
        "description": "使用Base64编码隐藏攻击意图",
        "converter_config": PromptConverterConfiguration.from_converters(
            converters=[Base64Converter()]
        ),
    },
    {
        "name": "Base64 + ZeroWidth",
        "description": "Base64编码后添加零宽字符",
        "converter_config": PromptConverterConfiguration.from_converters(
            converters=[Base64Converter(), ZeroWidthConverter()]
        ),
    },
    {
        "name": "Unicode混淆",
        "description": "使用相似字符替换进行混淆",
        "converter_config": PromptConverterConfiguration.from_converters(
            converters=[UnicodeConfusableConverter()]
        ),
    },
    {
        "name": "零宽字符注入",
        "description": "使用零宽字符进行隐写",
        "converter_config": PromptConverterConfiguration.from_converters(
            converters=[ZeroWidthConverter()]
        ),
    },
]

async def multi_agent_a2a_attack():
    ATTACK_TEST_CASES = load_test_cases(__file__, 'multi_agent_a2a_protocol_attack_cases.json')
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    target = OpenAIChatTarget()
    scorer_target = OpenAIChatTarget()

    print("\n" + "="*80)
    print("🚀 OffSec AI-300 多代理系统与A2A协议攻击模块（JSON配置版）")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
    print(f"🔄 攻击转换器: {len(ATTACK_CONVERTER_CONFIGS)} 种")
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
            chat_target=scorer_target,
            true_false_question=TrueFalseQuestion(
                true_description=case["criterion"]
            ),
        )

        for converter_config in ATTACK_CONVERTER_CONFIGS:
            print(f"\n{'='*70}")
            print(f"攻击方式: {converter_config['name']}")
            print(f"描述: {converter_config['description']}")
            print(f"{'='*70}")

            attack = PromptSendingAttack(
                objective_target=target,
                attack_scoring_config=AttackScoringConfig(
                    objective_scorer=scorer
                ),
                attack_converter_config=AttackConverterConfig(
                    request_converters=converter_config["converter_config"]
                ),
            )

            try:
                result = await attack.execute_async(
                    objective=case["objective"]
                )

                status = "SUCCESS" if result.outcome.value == "success" else "FAILURE"
                all_results.append({
                    "case_id": case["id"],
                    "objective": case["objective"],
                    "attack_method": converter_config["name"],
                    "status": status,
                })

                await PrettyAttackResultMemoryPrinter().write_async(
                    result=result
                )

            except Exception as e:
                print(f"❌ 测试失败: {e}")
                all_results.append({
                    "case_id": case["id"],
                    "objective": case["objective"],
                    "attack_method": converter_config["name"],
                    "status": "ERROR",
                })

    print("\n" + "="*80)
    print("📊 测试结果汇总")
    print("="*80)

    for case in ATTACK_TEST_CASES:
        case_results = [r for r in all_results if r["case_id"] == case["id"]]
        success_count = sum(1 for r in case_results if r["status"] == "SUCCESS")
        failure_count = sum(1 for r in case_results if r["status"] == "FAILURE")
        error_count = sum(1 for r in case_results if r["status"] == "ERROR")

        print(f"\n--- 用例 {case['id']}: {case['objective']} ---")
        print(f"   ✅ 成功: {success_count} 个")
        print(f"   ❌ 失败: {failure_count} 个")
        print(f"   ⚠️ 错误: {error_count} 个")

        if success_count > 0:
            print(f"\n   🎯 成功的攻击方式:")
            for r in case_results:
                if r["status"] == "SUCCESS":
                    print(f"      - {r['attack_method']}")

    total_success = sum(1 for r in all_results if r["status"] == "SUCCESS")
    total_failure = sum(1 for r in all_results if r["status"] == "FAILURE")
    total_error = sum(1 for r in all_results if r["status"] == "ERROR")

    print(f"\n{'='*80}")
    print(f"📈 总体统计: 成功 {total_success} / 失败 {total_failure} / 错误 {total_error}")
    print(f"{'='*80}")

asyncio.run(multi_agent_a2a_attack())