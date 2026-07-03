"""
===============================================================================
                  OffSec AI-300 PyRIT Scan 代码封装脚本（最小化版本）
===============================================================================
📋 使用说明：
  1. 修改 CONFIG 区域的配置参数
  2. 运行脚本即可执行扫描

🎯 考试重点：
  - 理解场景、策略、初始化器的概念
  - 能够快速配置和运行扫描任务
  - 分析扫描结果

⚠️ 注意：本脚本仅用于授权的安全测试和学习目的
===============================================================================
"""

import os
import sys
import subprocess

# ============================================
# 🎯 配置区域（考试时只需修改这里！）
# ============================================
SCENARIO = "airt.rapid_response"    # 场景名称
TARGET = "openai_chat"               # 目标名称
INITIALIZERS = ["target", "load_default_datasets"]  # 初始化器列表
STRATEGIES = ["role_play", "many_shot"]  # 攻击策略列表
DATASET_NAMES = ["airt_hate"]        # 数据集名称
MAX_DATASET_SIZE = 1                 # 数据集大小（快速测试用1）
MAX_CONCURRENCY = 1                  # 并发数
MAX_RETRIES = 1                      # 重试次数

# ============================================
# 🔧 构建命令（无需修改）
# ============================================
def build_command():
    """构建 pyrit_scan 命令"""
    cmd = ["pyrit_scan", SCENARIO]
    
    # 添加目标
    if TARGET:
        cmd.extend(["--target", TARGET])
    
    # 添加初始化器
    if INITIALIZERS:
        cmd.extend(["--initializers"] + INITIALIZERS)
    
    # 添加策略
    if STRATEGIES:
        cmd.extend(["--strategies"] + STRATEGIES)
    
    # 添加数据集
    if DATASET_NAMES:
        cmd.extend(["--dataset-names"] + DATASET_NAMES)
    
    # 添加数据集大小限制
    if MAX_DATASET_SIZE > 0:
        cmd.extend(["--max-dataset-size", str(MAX_DATASET_SIZE)])
    
    # 添加并发数
    if MAX_CONCURRENCY > 0:
        cmd.extend(["--max-concurrency", str(MAX_CONCURRENCY)])
    
    # 添加重试次数
    if MAX_RETRIES > 0:
        cmd.extend(["--max-retries", str(MAX_RETRIES)])
    
    return cmd

# ============================================
# 🚀 执行扫描（无需修改）
# ============================================
def run_scan():
    """执行扫描任务"""
    print("\n" + "="*80)
    print("🚀 OffSec AI-300 PyRIT Scan 扫描任务")
    print("="*80)
    
    # 打印配置信息
    print(f"\n📋 配置信息:")
    print(f"   场景: {SCENARIO}")
    print(f"   目标: {TARGET}")
    print(f"   初始化器: {', '.join(INITIALIZERS)}")
    print(f"   策略: {', '.join(STRATEGIES)}")
    print(f"   数据集: {', '.join(DATASET_NAMES)}")
    print(f"   数据集大小: {MAX_DATASET_SIZE}")
    print(f"   并发数: {MAX_CONCURRENCY}")
    print(f"   重试次数: {MAX_RETRIES}")
    
    # 构建命令
    cmd = build_command()
    print(f"\n🔧 执行命令: {' '.join(cmd)}")
    
    print("\n" + "="*80)
    print("📊 扫描结果:")
    print("="*80)
    
    # 执行命令
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(f"\n⚠️ 错误输出:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ 扫描失败: {e}")
        print(f"错误输出:\n{e.stderr}")
    except FileNotFoundError:
        print("\n❌ 未找到 pyrit_scan 命令，请确保 PyRIT 已正确安装")
    
    print("\n" + "="*80)
    print("✅ 扫描任务完成")
    print("="*80)

# ============================================
# 📌 运行入口（无需修改）
# ============================================
if __name__ == "__main__":
    run_scan()