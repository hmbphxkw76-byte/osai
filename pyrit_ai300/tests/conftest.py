"""
Pytest 公共 fixture
==============

为所有测试提供公共的 fixture 和配置。
"""

import sys
from pathlib import Path

import pytest

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def config_dir():
    """返回配置文件目录路径"""
    return PROJECT_ROOT / "config"


@pytest.fixture
def owasp_mapping_file(config_dir):
    """返回 OWASP 映射配置文件路径"""
    return config_dir / "owasp_mapping.yaml"
