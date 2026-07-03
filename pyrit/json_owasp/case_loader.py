"""
===============================================================================
                    OffSec AI-300 测试用例加载器（公共模块）
===============================================================================
用途：统一加载 JSON 格式的测试用例配置文件，避免每个脚本重复实现加载逻辑

使用方式：
    from case_loader import load_test_cases
    test_cases = load_test_cases(__file__, 'single_turn_attack_cases.json')

参数说明：
    caller_file: 调用者的 __file__ 属性（用于确定 JSON 文件的相对路径）
    json_filename: JSON 配置文件名（不含路径）

返回值：
    test_cases 列表，如果加载失败则返回空列表
===============================================================================
"""

import json
import os


def load_test_cases(caller_file, json_filename):
    """
    从 JSON 文件加载测试用例
    
    Args:
        caller_file: 调用脚本的 __file__ 属性
        json_filename: JSON 配置文件名
    
    Returns:
        list: 测试用例列表，加载失败返回空列表
    """
    # 获取调用脚本所在目录
    caller_dir = os.path.dirname(os.path.abspath(caller_file))
    
    # 构建 JSON 文件的完整路径
    json_path = os.path.join(caller_dir, json_filename)
    
    # 检查文件是否存在
    if not os.path.exists(json_path):
        print(f"❌ JSON配置文件不存在: {json_path}")
        return []
    
    try:
        # 读取并解析 JSON 文件
        with open(json_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            return config.get('test_cases', [])
    
    except json.JSONDecodeError as e:
        print(f"❌ JSON配置文件解析错误: {e}")
        return []
    
    except Exception as e:
        print(f"❌ 加载测试用例时发生错误: {e}")
        return []


def load_config(caller_file, json_filename):
    """
    从 JSON 文件加载完整配置（适用于需要额外参数的场景）
    
    Args:
        caller_file: 调用脚本的 __file__ 属性
        json_filename: JSON 配置文件名
    
    Returns:
        dict: 完整配置字典，加载失败返回空字典
    """
    # 获取调用脚本所在目录
    caller_dir = os.path.dirname(os.path.abspath(caller_file))
    
    # 构建 JSON 文件的完整路径
    json_path = os.path.join(caller_dir, json_filename)
    
    # 检查文件是否存在
    if not os.path.exists(json_path):
        print(f"❌ JSON配置文件不存在: {json_path}")
        return {}
    
    try:
        # 读取并解析 JSON 文件
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    except json.JSONDecodeError as e:
        print(f"❌ JSON配置文件解析错误: {e}")
        return {}
    
    except Exception as e:
        print(f"❌ 加载配置时发生错误: {e}")
        return {}
