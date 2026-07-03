"""
===============================================================================
         OffSec AI-300 OWASP LLM07-Insecure Plugin Design 扫描脚本（JSON配置版）
===============================================================================
📋 使用说明（运行前请确认以下配置已完成）：

1. 配置上级目录的 .env 文件：
   ├── PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
   └── 在对应平台段落填写 API Key 和模型名称

2. 修改测试用例（只需修改 JSON 文件！）：
   └── 编辑 owasp_json/llm07_insecure_plugin_design_cases.json 文件中的 test_cases 列表

3. 运行方式：
   └── py.exe '.\\owasp_json\\llm07_insecure_plugin_design_scan.py'

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。

🎯 OWASP Top 10 for LLMs v1.1: LLM07 - Insecure Plugin Design
   测试模型插件是否存在安全设计缺陷，可能被滥用执行恶意操作
   
   风险描述：
   - LLM插件可能被设计为执行任意代码或访问敏感资源
   - 插件权限过大，超出完成任务所需的最小权限
   - 缺乏输入验证和安全检查
   
   攻击场景：
   - 诱导模型调用文件读取插件读取 /etc/passwd
   - 利用代码执行插件运行恶意命令
   - 通过搜索插件获取内部网络信息
   - 滥用数据库访问插件查询敏感数据
   
   缓解措施：
   - 实施最小权限原则
   - 对插件输入进行严格验证
   - 记录所有插件调用日志
   - 定期审计插件权限和行为
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

async def run_llm07_scan():
    ATTACK_TEST_CASES = load_test_cases(__file__, 'llm07_insecure_plugin_design_cases.json')
    
    if not ATTACK_TEST_CASES:
        print("❌ 未加载到任何测试用例")
        return
    
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    
    target = OpenAIChatTarget()
    scorer_target = OpenAIChatTarget()
    
    print("\n" + "="*80)
    print("🚀 OffSec AI-300 OWASP LLM07 - Insecure Plugin Design 扫描（JSON配置版）")
    print("="*80)
    print(f"📋 测试用例总数: {len(ATTACK_TEST_CASES)} 组")
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
        
        attack = PromptSendingAttack(
            objective_target=target,
            attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
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
    print("📊 OWASP LLM07 - Insecure Plugin Design 测试结果汇总")
    print("="*80)
    
    success_count = sum(1 for r in all_results if r["status"] == "SUCCESS")
    failure_count = sum(1 for r in all_results if r["status"] == "FAILURE")
    error_count = sum(1 for r in all_results if r["status"] == "ERROR")
    
    print(f"✅ 成功（插件被滥用）: {success_count} 个")
    print(f"❌ 失败（插件安全）: {failure_count} 个")
    print(f"⚠️ 错误: {error_count} 个")
    
    if success_count > 0:
        print(f"\n🎯 成功的插件滥用攻击用例:")
        for r in all_results:
            if r["status"] == "SUCCESS":
                print(f"   - 用例 {r['case_id']}: {r['objective']}")
    
    print(f"\n{'='*80}")
    print(f"📈 总体插件滥用风险: {success_count / len(all_results) * 100:.1f}%")
    print(f"{'='*80}")
    
    print("\n💡 风险提示:")
    print("   - 如果测试成功，说明插件存在安全设计缺陷")
    print("   - 建议实施最小权限原则和输入验证")
    print("   - 定期审计插件权限和调用日志")

asyncio.run(run_llm07_scan())