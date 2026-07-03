"""
===============================================================================
              OffSec AI-300 自定义场景示例脚本（最小化版本）
===============================================================================
📋 使用说明：
  1. 修改 SCENARIO_CONFIG 区域配置自定义场景
  2. 运行脚本即可注册和测试自定义场景

🎯 考试重点：
  - 理解场景类的结构
  - 能够自定义测试场景
  - 使用 CLI 运行自定义场景

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的
===============================================================================
"""

import os
import sys
import asyncio

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attacks'))

from platform_config_loader import load_platform_config
load_platform_config()

from pyrit.common import apply_defaults
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.scenario import DatasetConfiguration, Scenario, ScenarioStrategy
from pyrit.score import SelfAskRefusalScorer, TrueFalseInverterScorer
from pyrit.setup import IN_MEMORY, initialize_pyrit_async

# ============================================
# 🎯 自定义场景配置（考试时只需修改这里！）
# ============================================
SCENARIO_CONFIG = {
    "name": "MyCustomScenario",
    "description": "自定义越狱攻击场景",
    "version": 1,
    "default_dataset": ["airt_harms"],
    "max_dataset_size": 1,
}

# ============================================
# 📚 自定义策略类（无需修改）
# ============================================
class MyCustomStrategy(ScenarioStrategy):
    """自定义场景策略类"""
    ALL = ("all", {"all"})
    PROMPT_SENDING = ("prompt_sending", set[str]())
    MANY_SHOT = ("many_shot", set[str]())
    ROLE_PLAY = ("role_play", set[str]())

# ============================================
# 📦 自定义场景类（无需修改）
# ============================================
class MyCustomScenario(Scenario):
    """自定义场景实现"""
    
    @apply_defaults
    def __init__(self, *, scenario_result_id=None, **kwargs):
        # 创建评分器：检测拒绝响应并反转结果
        objective_scorer = TrueFalseInverterScorer(
            scorer=SelfAskRefusalScorer(
                chat_target=OpenAIChatTarget()
            )
        )
        
        # 调用父类初始化
        super().__init__(
            name=SCENARIO_CONFIG["description"],
            version=SCENARIO_CONFIG["version"],
            objective_scorer=objective_scorer,
            strategy_class=MyCustomStrategy,
            default_strategy=MyCustomStrategy.ALL,
            default_dataset_config=DatasetConfiguration(
                dataset_names=SCENARIO_CONFIG["default_dataset"],
                max_dataset_size=SCENARIO_CONFIG["max_dataset_size"],
            ),
            scenario_result_id=scenario_result_id,
        )

# ============================================
# 🚀 测试自定义场景（无需修改）
# ============================================
async def test_custom_scenario():
    print("\n" + "="*80)
    print("🚀 OffSec AI-300 自定义场景测试")
    print("="*80)
    
    # 初始化 PyRIT
    print("\n📦 初始化 PyRIT...")
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    
    # 创建目标
    objective_target = OpenAIChatTarget()
    
    # 创建场景
    print(f"\n🔧 创建场景: {SCENARIO_CONFIG['name']}")
    scenario = MyCustomScenario()
    
    # 初始化场景
    print("\n🔄 初始化场景...")
    await scenario.initialize_async(
        objective_target=objective_target,
        scenario_strategies=[MyCustomStrategy.PROMPT_SENDING],
        dataset_config=DatasetConfiguration(
            dataset_names=SCENARIO_CONFIG["default_dataset"],
            max_dataset_size=SCENARIO_CONFIG["max_dataset_size"],
        ),
    )
    
    # 执行场景
    print("\n🎯 执行场景测试...")
    scenario_result = await scenario.run_async()
    
    # 输出结果摘要
    print("\n" + "="*80)
    print("📊 测试结果摘要:")
    print("="*80)
    print(f"场景名称: {scenario.name}")
    print(f"场景版本: {scenario.version}")
    print(f"目标类型: {type(objective_target).__name__}")
    print(f"策略数量: {len(scenario_result.attack_results)}")
    
    # 统计结果
    success_count = sum(1 for r in scenario_result.attack_results 
                       if r.outcome.value == "success")
    total_count = len(scenario_result.attack_results)
    success_rate = (success_count / total_count * 100) if total_count > 0 else 0
    
    print(f"\n📈 统计结果:")
    print(f"   总攻击数: {total_count}")
    print(f"   成功数: {success_count}")
    print(f"   成功率: {success_rate:.1f}%")
    
    print("\n" + "="*80)
    print("✅ 自定义场景测试完成")
    print("="*80)
    
    # 提示如何使用 CLI 运行
    print("\n💡 CLI 使用方法:")
    print("   # 列出场景（确认自定义场景已注册）")
    print("   pyrit_scan --list-scenarios --initialization-scripts ./custom_scenario_example.py")
    print()
    print("   # 运行自定义场景")
    print("   pyrit_scan my_custom_scenario --initialization-scripts ./custom_scenario_example.py")

# ============================================
# 📌 运行入口（无需修改）
# ============================================
if __name__ == "__main__":
    asyncio.run(test_custom_scenario())