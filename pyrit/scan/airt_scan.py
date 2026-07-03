"""
===============================================================================
              OffSec AI-300 AIRT 场景测试脚本（最小化版本）
===============================================================================
📋 使用说明：
  1. 修改 CONFIG 区域选择要测试的场景和策略
  2. 运行脚本即可执行 AIRT 场景测试

🎯 AIRT 场景说明：
  - RapidResponse: 快速响应场景，测试多类别有害内容
  - Psychosocial: 心理社会危害场景，测试危机处理能力
  - Cyber: 网络安全场景，测试恶意软件生成
  - Jailbreak: 越狱攻击场景，测试模板式越狱

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的
===============================================================================
"""

import asyncio
import os
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attacks'))

from platform_config_loader import load_platform_config
load_platform_config()

from pyrit.output import output_scenario_async
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.scenario import DatasetConfiguration
from pyrit.setup import IN_MEMORY, initialize_pyrit_async
from pyrit.setup.initializers import LoadDefaultDatasets, ScorerInitializer, TargetInitializer

# ============================================
# 🎯 配置区域（考试时只需修改这里！）
# ============================================
SCENARIO_TYPE = "rapid_response"  # 可选: rapid_response, psychosocial, cyber, jailbreak
STRATEGIES = ["role_play"]        # 策略列表
DATASET_NAMES = ["airt_hate"]     # 数据集名称
MAX_DATASET_SIZE = 1              # 数据集大小（快速测试用1）

# ============================================
# 📚 场景映射（无需修改）
# ============================================
SCENARIO_MAP = {
    "rapid_response": {
        "class": "RapidResponse",
        "strategy_class": "RapidResponseStrategy",
        "module": "pyrit.scenario.scenarios.airt",
        "description": "快速响应场景",
    },
    "psychosocial": {
        "class": "Psychosocial",
        "strategy_class": "PsychosocialStrategy",
        "module": "pyrit.scenario.scenarios.airt",
        "description": "心理社会危害场景",
    },
    "cyber": {
        "class": "Cyber",
        "strategy_class": "CyberStrategy",
        "module": "pyrit.scenario.scenarios.airt",
        "description": "网络安全场景",
    },
    "jailbreak": {
        "class": "Jailbreak",
        "strategy_class": "JailbreakStrategy",
        "module": "pyrit.scenario.scenarios.airt",
        "description": "越狱攻击场景",
    },
}

# ============================================
# 🚀 执行 AIRT 场景测试（无需修改）
# ============================================
async def run_airt_scenario():
    # 获取场景配置
    scenario_config = SCENARIO_MAP.get(SCENARIO_TYPE)
    if not scenario_config:
        print(f"❌ 未知场景类型: {SCENARIO_TYPE}")
        print(f"   可选场景: {', '.join(SCENARIO_MAP.keys())}")
        return
    
    print("\n" + "="*80)
    print(f"🚀 OffSec AI-300 AIRT {scenario_config['description']}测试")
    print("="*80)
    
    # 初始化 PyRIT
    print("\n📦 初始化 PyRIT...")
    await initialize_pyrit_async(
        memory_db_type=IN_MEMORY,
        initializers=[
            TargetInitializer(),
            ScorerInitializer(),
            LoadDefaultDatasets(),
        ],
    )
    
    # 创建目标
    objective_target = OpenAIChatTarget()
    
    # 打印配置信息
    print(f"\n📋 配置信息:")
    print(f"   场景: {scenario_config['description']}")
    print(f"   策略: {', '.join(STRATEGIES)}")
    print(f"   数据集: {', '.join(DATASET_NAMES)}")
    print(f"   数据集大小: {MAX_DATASET_SIZE}")
    print(f"   目标类型: {type(objective_target).__name__}")
    
    # 动态导入场景类
    print("\n🔧 加载场景模块...")
    try:
        module = __import__(scenario_config["module"], fromlist=[""])
        scenario_class = getattr(module, scenario_config["class"])
        strategy_class = getattr(module, scenario_config["strategy_class"])
    except ImportError as e:
        print(f"❌ 导入场景模块失败: {e}")
        return
    except AttributeError as e:
        print(f"❌ 获取场景类失败: {e}")
        return
    
    # 创建数据集配置
    dataset_config = DatasetConfiguration(
        dataset_names=DATASET_NAMES,
        max_dataset_size=MAX_DATASET_SIZE,
    )
    
    # 创建策略列表
    scenario_strategies = []
    for strategy_name in STRATEGIES:
        if hasattr(strategy_class, strategy_name.upper()):
            scenario_strategies.append(getattr(strategy_class, strategy_name.upper()))
        elif hasattr(strategy_class, strategy_name):
            scenario_strategies.append(getattr(strategy_class, strategy_name))
        else:
            print(f"⚠️ 未知策略: {strategy_name}，跳过")
    
    if not scenario_strategies:
        print("❌ 未找到有效的策略")
        return
    
    # 初始化场景
    print("\n🔄 初始化场景...")
    scenario = scenario_class()
    await scenario.initialize_async(
        objective_target=objective_target,
        scenario_strategies=scenario_strategies,
        dataset_config=dataset_config,
    )
    
    # 执行场景
    print("\n🎯 执行场景测试...")
    scenario_result = await scenario.run_async()
    
    # 输出结果
    print("\n" + "="*80)
    print("📊 测试结果:")
    print("="*80)
    await output_scenario_async(scenario_result)
    
    print("\n" + "="*80)
    print("✅ AIRT 场景测试完成")
    print("="*80)

# ============================================
# 📌 运行入口（无需修改）
# ============================================
if __name__ == "__main__":
    asyncio.run(run_airt_scenario())