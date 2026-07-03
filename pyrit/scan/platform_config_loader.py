"""
===============================================================================
              OffSec AI-300 平台配置加载器（scan目录专用）
===============================================================================
📋 使用说明：
  1. 配置上级目录的 .env 文件
  2. 修改 PLATFORM_SELECTOR 选择平台
  3. 在对应平台段落填写 API Key 和模型名称

⚠️ 注意：本文件仅用于授权的安全测试和学习目的
===============================================================================
"""

import os
import sys

def load_platform_config():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    
    if not os.path.exists(env_path):
        print(f"❌ 未找到 .env 文件: {env_path}")
        return
    
    with open(env_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    platform = "ZHIPU"
    current_platform = None
    config = {}
    
    for line in lines:
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current_platform = line[1:-1].strip()
            continue
        
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            if current_platform == "DEFAULT":
                if key == "PLATFORM_SELECTOR":
                    platform = value.strip().upper()
            elif current_platform == platform:
                config[key.strip()] = value.strip()
    
    for key, value in config.items():
        os.environ[key] = value
    
    print(f"✅ 已加载平台配置: {platform}")

if __name__ == "__main__":
    load_platform_config()