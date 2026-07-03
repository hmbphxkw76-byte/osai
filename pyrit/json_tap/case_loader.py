"""
===============================================================================
                    OffSec AI-300 TAP攻击测试用例加载器（公共模块）
===============================================================================
用途：统一加载 JSON 格式的测试用例配置文件

使用方式：
    from case_loader import load_config
    config = load_config(__file__, 'tap_llm01_cases.json')

参数说明：
    caller_file: 调用者的 __file__ 属性
    json_filename: JSON 配置文件名

返回值：
    dict: 完整配置字典，加载失败返回空字典
===============================================================================
"""

import json
import os


def load_config(caller_file, json_filename):
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


def load_test_cases(caller_file, json_filename):
    config = load_config(caller_file, json_filename)
    return config.get('test_cases', [])