"""
===============================================================================
PyRIT Red Team — 路径和配置辅助函数
===============================================================================
包含:
- ensure_results_dir(): 确保 outputs/results 输出目录存在
- results_path(): 拼接 outputs/results 目录下的文件路径
- DEFAULT_MODEL_NAME: 默认模型名称
===============================================================================
"""
import os

RESULTS_DIR = "outputs/results"


def get_default_model_name() -> str:
    """获取默认模型名称，优先从环境变量 DEFAULT_MODEL_NAME 读取。"""
    default_name = os.getenv("DEFAULT_MODEL_NAME", "default")
    return default_name


DEFAULT_MODEL_NAME = get_default_model_name()


def ensure_results_dir() -> str:
    """确保 outputs/results 目录存在，并创建 outputs/logs 目录。"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs("outputs/logs", exist_ok=True)
    return RESULTS_DIR


def results_path(filename: str) -> str:
    """拼接 outputs/results 目录下的文件路径。"""
    return os.path.join(RESULTS_DIR, filename)
