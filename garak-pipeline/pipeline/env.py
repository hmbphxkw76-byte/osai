"""环境变量加载 — 统一从项目根 .env 读取默认参数

提供：
  - load_env()              : 在程序入口调用一次，加载 .env（幂等）
  - get_env()               : 带默认值的读取（优先真实环境变量，其次 .env，最后 default）
  - configure_hf_mirror()   : 智能选择 HuggingFace 端点（官方 3 次失败后切换国内镜像）

设计：
  - 不强制依赖 python-dotenv；若未安装则静默跳过（环境变量仍可从 shell 继承）
  - 加载路径：项目根目录的 .env（相对本文件向上两级）
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

_LOADED = False
_HF_CONFIGURED = False
_GARAK_SRC_INJECTED = False
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# garak 原生源码目录：相对项目根（garak-pipeline/）的路径 = ../src/garak-0.15.1
# 目录采用相对路径策略：运行期解析为绝对路径，保证跨开发环境一致（无需改代码）
_GARAK_SRC_REL = "../src/garak-0.15.1"


def load_env() -> None:
    """加载项目根 .env（幂等，多次调用仅生效一次）"""
    global _LOADED
    if _LOADED:
        return
    try:
        from dotenv import load_dotenv

        env_path = _PROJECT_ROOT / ".env"
        # override=False: 不覆盖已存在的真实环境变量（shell 优先）
        load_dotenv(dotenv_path=env_path, override=False)
    except Exception:
        # python-dotenv 未安装或 .env 不存在：静默跳过
        pass
    _LOADED = True


def ensure_garak_src_path() -> Path:
    """将相对路径 garak 源码目录注入 sys.path，优先于 site-packages 加载

    对齐 L5 原则（规则一：garak 原生框架优先，不重复造轮子）：
    自定义探针/Buff/Detector 必须继承 `..\\src\\garak-0.15.1` 中的 garak 基类。
    开发环境下直接读取原生源码便于调试，而 site-packages 中的 garak 副本仅作
    安装态兜底。调用时机：必须在 `import garak` 之前执行。

    相对路径策略：本文件在 pipeline/env.py，项目根为向上两级。
    ../src/garak-0.15.1 与 garak-pipeline 同属 Music/ 源码集。

    :returns: 解析后的 garak 源码根绝对路径对象
    """
    global _GARAK_SRC_INJECTED
    garak_src = (_PROJECT_ROOT / _GARAK_SRC_REL).resolve()
    if not garak_src.exists():
        import logging as _log
        _log.getLogger(__name__).warning(
            "garak 源码目录不存在: %s（继续使用 site-packages 中安装的 garak）",
            garak_src,
        )
        return garak_src
    garak_src_str = str(garak_src)
    if not _GARAK_SRC_INJECTED:
        # sys.path[0] 通常是项目根（入口脚本所在目录，用于 import pipeline），
        # 插入到索引 1 保证用户脚本目录优先，但源码 garak 仍优先于 site-packages
        insert_pos = 1 if len(sys.path) >= 1 and sys.path[0] == "" else 0
        if garak_src_str not in sys.path:
            sys.path.insert(insert_pos, garak_src_str)
        # 若 garak 已被导入（从 site-packages），刷新其 __path__ 避免 stale imports
        if "garak" in sys.modules:
            import importlib
            importlib.reload(sys.modules["garak"])
        _GARAK_SRC_INJECTED = True
    return garak_src


def get_env(key: str, default: str = "") -> str:
    """读取环境变量，带默认值

    :param key: 变量名
    :param default: 未设置时的默认值
    :returns: 字符串值
    """
    load_env()
    return os.getenv(key, default)


def configure_hf_mirror(max_retries: int | None = None) -> str:
    """智能选择 HuggingFace 端点：默认官方，3 次失败后切换国内镜像

    策略：
    1. 若用户已显式设置 HF_ENDPOINT 环境变量，直接沿用（不覆盖）
    2. 否则尝试连接官方端点（socket TCP 握手，5s 超时）
    3. 官方端点连续 max_retries 次失败后，尝试国内镜像
    4. 若镜像也不可用，设置 HF_HUB_OFFLINE=1 使所有 HF 下载立即失败
       （避免每个文件 5 次重试 × 多文件的长时间挂起）
    5. 必须在 garak / huggingface_hub 导入之前调用，确保 HF_ENDPOINT 生效

    端点 URL 与重试次数可由 .env 配置：
        HF_OFFICIAL_ENDPOINT  (默认 https://huggingface.co)
        HF_MIRROR_ENDPOINT    (默认 https://hf-mirror.com)
        HF_ENDPOINT_MAX_RETRIES (默认 3)

    :param max_retries: 每个端点最大重试次数；None 则读 .env 的
                        HF_ENDPOINT_MAX_RETRIES，再回退默认 3
    :returns: 最终使用的 HF_ENDPOINT URL（或 "offline" 表示离线模式）
    """
    global _HF_CONFIGURED
    if _HF_CONFIGURED:
        return os.environ.get("HF_ENDPOINT", "https://huggingface.co")
    _HF_CONFIGURED = True

    import logging
    from urllib.parse import urlparse

    logger = logging.getLogger(__name__)

    # 确保 .env 已加载（幂等），使 HF_OFFICIAL_ENDPOINT 等可读
    load_env()

    # 若用户已显式设置 HF_ENDPOINT，直接沿用
    existing = os.environ.get("HF_ENDPOINT")
    if existing:
        logger.info("HF 端点: 沿用已设置的 HF_ENDPOINT=%s", existing)
        return existing

    # 从 .env 读取端点配置（支持运维侧不改代码即可调整）
    official_url = os.environ.get(
        "HF_OFFICIAL_ENDPOINT", "https://huggingface.co"
    ).rstrip("/")
    mirror_url = os.environ.get(
        "HF_MIRROR_ENDPOINT", "https://hf-mirror.com"
    ).rstrip("/")
    if max_retries is None:
        max_retries = int(os.environ.get("HF_ENDPOINT_MAX_RETRIES", "3"))

    def _host_of(url: str) -> str:
        """从 URL 提取主机名（用于 TCP 连通性探测）"""
        parsed = urlparse(url)
        return parsed.hostname or url

    official_host = _host_of(official_url)
    mirror_host = _host_of(mirror_url)

    def _test_endpoint(host: str, port: int = 443) -> bool:
        """测试端点 TCP 连通性（5s 超时）"""
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            return True
        except (TimeoutError, OSError):
            return False

    # 阶段 1：测试官方端点（默认从官方下载）
    for i in range(max_retries):
        if _test_endpoint(official_host):
            os.environ["HF_ENDPOINT"] = official_url
            logger.info(
                "HF 端点: 官方端点可用 (第 %d/%d 次尝试成功)", i + 1, max_retries
            )
            return official_url
        logger.warning(
            "HF 官方端点连接失败 (%d/%d)", i + 1, max_retries
        )

    # 阶段 2：官方失败，切换国内镜像站
    logger.warning(
        "HF 官方端点 %d 次均失败，尝试国内镜像: %s", max_retries, mirror_url
    )
    for i in range(max_retries):
        if _test_endpoint(mirror_host):
            os.environ["HF_ENDPOINT"] = mirror_url
            logger.info(
                "HF 端点: 国内镜像可用 (第 %d/%d 次尝试成功)", i + 1, max_retries
            )
            return mirror_url
        logger.warning(
            "HF 国内镜像连接失败 (%d/%d)", i + 1, max_retries
        )

    # 阶段 3：官方和镜像均不可用，启用离线模式
    # 避免 huggingface_hub 对每个文件重试 5 次 × 多文件的长时间挂起
    logger.warning(
        "HF 官方端点和国内镜像均不可用，启用离线模式 (HF_HUB_OFFLINE=1)。\n"
        "  → 所有 HF 模型下载将立即失败，由 garak 降级机制 + "
        "stage3 逐探针错误处理接管。"
    )
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    return "offline"
