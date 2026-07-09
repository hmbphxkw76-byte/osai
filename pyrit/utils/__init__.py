"""
===============================================================================
PyRIT Red Team — 通用工具函数包 (Utils)
===============================================================================
从根目录 utils.py 模块转化为 utils/ 包。

子模块:
  helpers.py               — 路径工具 (ensure_results_dir, results_path, RESULTS_DIR)
  retry.py                 — 重试逻辑 (is_retryable_error, backoff_delay)
  target_url.py            — URL 标准化工具 (normalize_target_url, to_openai_base_url, ...)
  js_endpoint_extractor.py — JS 端点提取 (LinkFinder-style, extract_script_sources, crawl_js_endpoints)
  http_transport.py        — HTTP 传输层工厂 (httpx 核心 + curl_cffi TLS 伪装降级)
  token_manager.py         — PyJWT Token 管理器 (JWT 解码/过期检测/刷新回调)

使用方式:
  from utils import ensure_results_dir, results_path, RESULTS_DIR
  from utils import is_retryable_error, backoff_delay
  from utils import DEFAULT_MODEL_NAME, get_default_model_name
  from utils import normalize_target_url, to_openai_base_url, validate_target_url
  from utils.js_endpoint_extractor import extract_script_sources, crawl_js_endpoints
  from utils.http_transport import create_http_client, is_tls_block_error, TransportConfig
  from utils.token_manager import inspect_token, TokenInspector, is_jwt_format
===============================================================================
"""
from utils.helpers import (
    DEFAULT_MODEL_NAME,
    get_default_model_name,
    ensure_results_dir,
    results_path,
    RESULTS_DIR,
)
from utils.retry import (
    is_retryable_error,
    backoff_delay,
)
from utils.target_url import (
    NormalizedURL,
    normalize_target_url,
    validate_target_url,
    is_ip_address,
    join_target_path,
    extract_base_origin,
    to_openai_base_url,
    derive_test_base_url,
    DEFAULT_OPEN_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
)

__all__ = [
    "DEFAULT_MODEL_NAME",
    "get_default_model_name",
    "ensure_results_dir",
    "results_path",
    "RESULTS_DIR",
    "is_retryable_error",
    "backoff_delay",
    "NormalizedURL",
    "normalize_target_url",
    "validate_target_url",
    "is_ip_address",
    "join_target_path",
    "extract_base_origin",
    "to_openai_base_url",
    "derive_test_base_url",
    "DEFAULT_OPEN_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
    "DEFAULT_MAX_REDIRECTS",
]
