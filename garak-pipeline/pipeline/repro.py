"""结果可复现性哈希 — 保证扫描结果可审计、可复现

对齐 L5 专家水平：顶级红队报告需在产物中写 repro_hash，下游可校验
同一 (target + probe_list + buff + garak_version + plugin_cache_version) 是否复现一致。

用法:
    from pipeline.repro import compute_repro_hash, verify_repro_hash
    h = compute_repro_hash(target, probe_names, buff_spec, garak_version)
    verify_repro_hash(h, target, probe_names, buff_spec, garak_version)  # → True/False
"""

from __future__ import annotations

import hashlib
import json
import logging

logger = logging.getLogger(__name__)


def compute_repro_hash(
    target: dict,
    probe_names: list[str],
    buff_spec: str | None,
    garak_version: str,
    generations: int = 1,
    plugin_cache_version: str | None = None,
) -> str:
    """计算扫描结果可复现性哈希（SHA256 前 16 位）

    哈希输入（按字典序排序保证稳定性）:
    - target.endpoint + target.model（不含 api_key，避免敏感泄漏）
    - probe_names 排序列表
    - buff_spec
    - garak_version
    - generations
    - S3.1: plugin_cache_version（插件缓存版本，影响探针行为）

    :param plugin_cache_version: garak PluginCache 版本标识（S3.1 新增）
    :returns: 16 字符 hex 哈希
    """
    # S3.1: 自动获取 plugin_cache_version（若未显式传入）
    if plugin_cache_version is None:
        try:
            from garak._plugins import PluginCache

            cache = PluginCache.instance()
            plugin_cache_version = cache.get("version", "unknown")
        except Exception:
            plugin_cache_version = "unknown"

    payload = json.dumps(
        {
            "endpoint": target.get("endpoint", ""),
            "model": target.get("model", ""),
            "probes": sorted(probe_names),
            "buff": buff_spec or "",
            "garak_version": garak_version,
            "generations": generations,
            "plugin_cache_version": plugin_cache_version,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def verify_repro_hash(
    expected_hash: str,
    target: dict,
    probe_names: list[str],
    buff_spec: str | None,
    garak_version: str,
    generations: int = 1,
    plugin_cache_version: str | None = None,
) -> bool:
    """S3.2: 验证可复现性哈希是否匹配

    对齐 L5：下游审计时校验产物中的 repro_hash 是否与当前环境参数一致，
    若不一致则说明扫描环境已变更（如 garak 版本升级、探针列表修改），
    需重新扫描以保持结果可比性。

    :param expected_hash: 产物中记录的 repro_hash
    :returns: True 如果哈希匹配（可复现），False 如果不匹配
    """
    actual_hash = compute_repro_hash(
        target=target,
        probe_names=probe_names,
        buff_spec=buff_spec,
        garak_version=garak_version,
        generations=generations,
        plugin_cache_version=plugin_cache_version,
    )
    if actual_hash == expected_hash:
        logger.info("repro_hash 验证通过：扫描环境一致，结果可复现")
        return True
    logger.warning(
        "repro_hash 不匹配：expected=%s actual=%s，扫描环境已变更，结果不可直接比较",
        expected_hash,
        actual_hash,
    )
    return False
