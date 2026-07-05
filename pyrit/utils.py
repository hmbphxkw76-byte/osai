"""
===============================================================================
OffSec AI-300 — 通用工具函数
===============================================================================
包含:
- _ensure_results_dir(): 确保 results 输出目录存在
- _results_path(): 拼接 results 目录下的文件路径
===============================================================================
"""
import os

RESULTS_DIR = "results"


def ensure_results_dir() -> str:
    """确保 results 目录存在，返回绝对路径。"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return RESULTS_DIR


def results_path(filename: str) -> str:
    """拼接 results 目录下的文件路径。"""
    return os.path.join(RESULTS_DIR, filename)
