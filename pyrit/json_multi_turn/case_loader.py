"""
===============================================================================
                    OffSec AI-300 Multi-Turn 测试用例加载器（公共模块）
===============================================================================
用途：统一加载 JSON 格式的测试用例配置文件，支持 max_turns 参数

使用方式：
    from case_loader import load_config
    config = load_config(__file__, 'multi_turn_llm02_insecure_output_cases.json')
    test_cases = config.get('test_cases', [])
    max_turns = config.get('max_turns', 5)

参数说明：
    caller_file: 调用者的 __file__ 属性（用于确定 JSON 文件的相对路径）
    json_filename: JSON 配置文件名（不含路径）

返回值：
    dict: 完整配置字典，包含 test_cases 和 max_turns 等字段
===============================================================================
"""

import json
import os


def load_config(caller_file, json_filename):
    """
    从 JSON 文件加载完整配置（适用于需要额外参数的场景）
    
    Args:
        caller_file: 调用脚本的 __file__ 属性
        json_filename: JSON 配置文件名
    
    Returns:
        dict: 完整配置字典，加载失败返回空字典
    """
    caller_dir = os.path.dirname(os.path.abspath(caller_file))
    json_path = os.path.join(caller_dir, json_filename)
    
    if not os.path.exists(json_path):
        print(f"❌ JSON配置文件不存在: {json_path}")
        return {}
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    except json.JSONDecodeError as e:
        print(f"❌ JSON配置文件解析错误: {e}")
        return {}
    
    except Exception as e:
        print(f"❌ 加载配置时发生错误: {e}")
        return {}
