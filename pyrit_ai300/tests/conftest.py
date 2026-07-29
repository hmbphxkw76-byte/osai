"""
Pytest 公共 fixture
==============

为所有测试提供公共的 fixture 和配置。
"""

import sys
import warnings
from pathlib import Path

# 抑制第三方包 confusables 的 SyntaxWarning（无效转义序列 \* 等）
# confusables 被 PyRIT unicode_confusable_converter 间接导入，非我们可控代码
# 注意: module= 参数对编译时 SyntaxWarning 无效（Python 编译源码时 __name__ 尚未设置），
# 必须使用 message= 参数匹配警告消息文本
warnings.filterwarnings("ignore", category=SyntaxWarning, message=r"invalid escape sequence")

import pytest  # noqa: E402

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def pytest_configure(config):
    """pytest 启动时注册警告过滤器。

    conftest.py 顶部的 warnings.filterwarnings 对 pytest 的
    catch_warnings() 上下文无效，必须通过 addinivalue_line
    注册到 pytest 的 filterwarnings ini 选项才能在测试执行期间生效。
    """
    config.addinivalue_line(
        "filterwarnings",
        "ignore:invalid escape sequence:SyntaxWarning",
    )


@pytest.fixture
def config_dir():
    """返回配置文件目录路径"""
    return PROJECT_ROOT / "config"


@pytest.fixture
def owasp_mapping_file():
    """返回 OWASP 映射配置文件路径（系统默认在 src/core/defaults/）"""
    from src.core.config_loader import ConfigLoader
    return ConfigLoader().owasp_file
