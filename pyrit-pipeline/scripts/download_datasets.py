#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""远程数据集全量预下载工具 — 官方优先 + 国内镜像兜底 + 月度更新。.

设计目标:
  1. 全量下载: 将 PyRIT 原生 61+ 远程数据集全部缓存为本地 .prompt 文件
  2. 双源策略: 优先官方源 (HuggingFace/GitHub), 失败后切换国内镜像 (hf-mirror.com)
  3. 月度更新: 每月底/月初执行一次, 刷新数据集和 ASR 先验
  4. 离线运行: 下载后流水线 100% 本地加载, 不依赖网络

下载策略:
  Round 1: 官方源直连, 3 次重试 (超时 30s) — 充分尝试官方源
  Round 2: 国内镜像 (hf-mirror.com), 3 次重试 (超时 60s) — 镜像兜底
  Round 3: 跳过 (记录失败, 下次重试)

使用方式:
    python scripts/download_datasets.py                    # 下载核心数据集
    python scripts/download_datasets.py --all              # 下载全部 61+ 数据集
    python scripts/download_datasets.py --update           # 月度更新 (覆盖已有)
    python scripts/download_datasets.py --list             # 列出可用数据集
    python scripts/download_datasets.py --check            # 检查本地缓存状态

月度更新 (推荐 cron 配置):
    # 每月1日凌晨3点自动更新
    0 3 1 * * cd /path/to/pyrit-pipeline && python scripts/download_datasets.py \
        --update --all >> logs/dataset_update.log 2>&1

学术依据:
  - HarmBench (arXiv:2402.04249): 标准化数据集元数据
  - JailbreakBench (arXiv:2402.01135): ASR baseline 数据

> **日期**: 2026-8-1
> **更新记录**: 2026-8-1 22:30 — 修复 4 个关键 Bug:
>   1. fetch_datasets_async (全量) → fetch_dataset_async (单个)
>   2. __subclasses__() → get_all_providers() + dataset_name 属性匹配
>   3. 官方源也设置 HF 超时环境变量, 避免等待 HF 库内部 5 次重试
>   4. 官方源 3 次重试 → 全部失败后切换镜像 (国内网络优化)
"""

from __future__ import annotations

import argparse
import asyncio
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

#: 项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 输出目录 (远程基准数据集本地缓存)
_OUTPUT_DIR = _PROJECT_ROOT / "data" / "seed_datasets" / "benchmarks"

#: 下载日志文件
_DOWNLOAD_LOG = _OUTPUT_DIR / "_download_log.yaml"

#: HuggingFace 国内镜像
_HF_MIRROR = "https://hf-mirror.com"

#: 官方源单次超时 (秒) — 给足时间让 HuggingFace 完成下载
_OFFICIAL_TIMEOUT = 30

#: 镜像源单次超时 (秒) — 镜像更稳定, 给更充裕时间
_MIRROR_TIMEOUT = 60

#: 官方源最大重试次数 (3 次 = 充分尝试官方源, 全部失败后切镜像)
_OFFICIAL_RETRIES = 3

#: 镜像源最大重试次数
_MIRROR_RETRIES = 3

#: 核心数据集 (优先下载, 对齐 OWASP + ASR 驱动)
_CORE_DATASETS = [
    "harmbench",
    "jbb_behaviors",
    "strong_reject",
    "forbidden_questions",
    "xstest",
    "adv_bench",
    "decoding_trust",
    "pku_saferlhf",
]

#: HuggingFace 环境变量备份键
_HF_ENV_KEYS = (
    "HF_ENDPOINT",
    "HF_HUB_ENDPOINT",
    "HF_HUB_DOWNLOAD_TIMEOUT",
    "HF_HUB_ETAG_TIMEOUT",
    "HF_HUB_DISABLE_TELEMETRY",
)


# ============================================================
# HuggingFace 环境变量管理
# ============================================================


def _save_hf_env() -> dict[str, str | None]:
    """保存当前 HF 环境变量, 返回备份字典。."""
    return {key: os.environ.get(key) for key in _HF_ENV_KEYS}


def _restore_hf_env(backup: dict[str, str | None]) -> None:
    """恢复 HF 环境变量。."""
    for key, val in backup.items():
        if val is not None:
            os.environ[key] = val
        else:
            os.environ.pop(key, None)


def _set_hf_env_for_official() -> None:
    """设置官方源 HF 环境变量 (官方源超时, 充分尝试)。."""
    # 不修改 HF_ENDPOINT (使用默认 https://huggingface.co)
    os.environ["HF_HUB_DOWNLOAD_TIMEOUT"] = str(_OFFICIAL_TIMEOUT)
    os.environ["HF_HUB_ETAG_TIMEOUT"] = str(_OFFICIAL_TIMEOUT)
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    _force_update_hf_constants("https://huggingface.co")


def _set_hf_env_for_mirror() -> None:
    """设置镜像源 HF 环境变量。."""
    os.environ["HF_ENDPOINT"] = _HF_MIRROR
    os.environ["HF_HUB_ENDPOINT"] = _HF_MIRROR
    os.environ["HF_HUB_DOWNLOAD_TIMEOUT"] = str(_MIRROR_TIMEOUT)
    os.environ["HF_HUB_ETAG_TIMEOUT"] = str(_MIRROR_TIMEOUT)
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    _force_update_hf_constants(_HF_MIRROR)


def _force_update_hf_constants(endpoint: str) -> None:
    """强制更新 HuggingFace hub + datasets 库的模块级常量。.

    HuggingFace hub 和 datasets 库在 import 时将 HF_ENDPOINT 读取到
    模块级变量, 后续请求使用这些变量而非 os.environ['HF_ENDPOINT']。
    仅设置环境变量无法在运行时切换端点。

    本函数直接 patch 所有相关模块级变量, 确保镜像端点立即生效:

    huggingface_hub.constants:
      - ENDPOINT
      - HUGGINGFACE_CO_URL_TEMPLATE (下载 URL 模板)
      - HUGGINGFACE_CO_URL_HOME (主页 URL)

    datasets.config:
      - HF_ENDPOINT
      - HF_DATASETS_ENDPOINT
      - HF_DATASETS_CACHE (不修改, 仅记录)
    """
    # Patch huggingface_hub.constants
    try:
        import huggingface_hub.constants as hf_constants

        hf_constants.ENDPOINT = endpoint
        # URL 模板: "{endpoint}/{repo_id}/resolve/{revision}/{filename}"
        if hasattr(hf_constants, "HUGGINGFACE_CO_URL_TEMPLATE"):
            hf_constants.HUGGINGFACE_CO_URL_TEMPLATE = (
                endpoint + "/{repo_id}/resolve/{revision}/{filename}"
            )
        # 主页 URL: "{endpoint}/"
        if hasattr(hf_constants, "HUGGINGFACE_CO_URL_HOME"):
            hf_constants.HUGGINGFACE_CO_URL_HOME = endpoint + "/"
    except ImportError:
        pass

    # Patch datasets.config (datasets 库有自己的 endpoint 缓存)
    try:
        import datasets.config as ds_config

        ds_config.HF_ENDPOINT = endpoint
        if hasattr(ds_config, "HF_DATASETS_ENDPOINT"):
            ds_config.HF_DATASETS_ENDPOINT = endpoint
    except ImportError:
        pass


# ============================================================
# 数据集发现 (Bug 修复: 使用 get_all_providers 而非 __subclasses__)
# ============================================================


async def list_available_datasets() -> list[str]:
    """列出所有可用的远程数据集名称 (通过 dataset_name 属性)。.

    修复说明:
      旧代码使用 ``SeedDatasetProvider.__subclasses__()`` 返回的是
      ``_RemoteDatasetLoader`` / ``_LocalDatasetLoader`` 等抽象基类,
      而非实际数据集 Provider。

      正确方式是使用 ``get_all_providers()`` 获取已注册的具体 Provider,
      再通过 ``dataset_name`` 属性获取数据集名称。
    """
    try:
        from pyrit.datasets import SeedDatasetProvider

        registry = SeedDatasetProvider.get_all_providers()
        names: list[str] = []
        for cls in registry.values():
            try:
                provider = cls()
                names.append(provider.dataset_name)
            except Exception:
                continue
        return sorted(names) if names else sorted(_CORE_DATASETS)
    except Exception:
        return sorted(_CORE_DATASETS)


def _find_provider_class(dataset_name: str):
    """根据 dataset_name 属性查找 Provider 类。.

    修复说明:
      旧代码用 ``cls.__name__.replace("Provider", "").lower()`` 匹配,
      但实际类名是 ``_HarmBenchDataset`` (不是 ``HarmbenchProvider``)。
      正确方式是实例化后检查 ``dataset_name`` 属性 (返回 "harmbench")。
    """
    from pyrit.datasets import SeedDatasetProvider

    registry = SeedDatasetProvider.get_all_providers()
    for cls in registry.values():
        try:
            provider = cls()
            if provider.dataset_name == dataset_name:
                return cls
        except Exception:
            continue
    return None


def list_local_cached_datasets() -> list[dict[str, Any]]:
    """列出已缓存的本地数据集。."""
    results: list[dict[str, Any]] = []
    if not _OUTPUT_DIR.exists():
        return results
    for f in sorted(_OUTPUT_DIR.glob("*.prompt")):
        stat = f.stat()
        results.append(
            {
                "name": f.stem,
                "path": str(f),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        )
    return results


def load_download_log() -> dict[str, Any]:
    """加载下载日志。."""
    if not _DOWNLOAD_LOG.exists():
        return {"downloads": [], "last_update": None}
    try:
        with open(_DOWNLOAD_LOG, encoding="utf-8") as f:
            return yaml.safe_load(f) or {"downloads": [], "last_update": None}
    except Exception:
        return {"downloads": [], "last_update": None}


def save_download_log(log: dict[str, Any]) -> None:
    """保存下载日志。."""
    _DOWNLOAD_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(_DOWNLOAD_LOG, "w", encoding="utf-8") as f:
        yaml.dump(log, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


# ============================================================
# 双源下载: 官方优先 → 镜像兜底
# ============================================================


async def _try_fetch_single_dataset(
    dataset_name: str,
    *,
    use_mirror: bool = False,
    timeout: int = 30,
) -> Any | None:
    """通过 PyRIT 原生 Provider 拉取单个数据集 (单次尝试, 带超时)。.

    修复说明:
      1. 旧代码调用 ``provider.fetch_datasets_async()`` (classmethod, 拉取全部 61+ 数据集),
         应该调用 ``provider.fetch_dataset_async()`` (instance method, 拉取单个)。
      2. 旧代码仅在 ``use_mirror=True`` 时设置 ``HF_HUB_DOWNLOAD_TIMEOUT``,
         官方源使用 HF 默认超时 (~10 分钟), 导致长时间等待。
      3. ``asyncio.wait_for`` 超时后, ``asyncio.to_thread`` 中的线程仍在运行,
         但我们不等待它, 直接返回 None 切换到镜像源。

    Args:
        dataset_name: 数据集名称 (与 Provider 的 dataset_name 属性匹配)
        use_mirror: True=使用国内镜像, False=官方源
        timeout: asyncio.wait_for 超时秒数

    Returns:
        SeedDataset 对象, 失败/超时返回 None
    """
    # 在调用前设置 HF 环境变量 (对官方源和镜像源都设置)
    env_backup = _save_hf_env()
    if use_mirror:
        _set_hf_env_for_mirror()
    else:
        _set_hf_env_for_official()

    try:
        provider_cls = _find_provider_class(dataset_name)
        if provider_cls is None:
            print(f"    [错误] 未找到 dataset_name='{dataset_name}' 的 Provider")
            return None

        provider = provider_cls()

        # Bug 修复: 调用 fetch_dataset_async (单个) 而非 fetch_datasets_async (全部)
        dataset = await asyncio.wait_for(
            provider.fetch_dataset_async(cache=True),
            timeout=timeout,
        )
        return dataset if dataset else None

    except asyncio.TimeoutError:
        source = "mirror" if use_mirror else "official"
        print(f"    [{source}] {dataset_name}: 超时 ({timeout}s)")
        return None
    except Exception as e:
        source = "mirror" if use_mirror else "official"
        # 截断过长的错误信息
        err_msg = str(e)
        if len(err_msg) > 200:
            err_msg = err_msg[:200] + "..."
        print(f"    [{source}] {dataset_name}: 失败 - {type(e).__name__}: {err_msg}")
        return None
    finally:
        _restore_hf_env(env_backup)


def _dataset_to_prompt(
    dataset: Any,
    dataset_name: str,
) -> dict[str, Any] | None:
    """将单个 SeedDataset 转换为 .prompt YAML 字典。."""
    all_seeds: list[dict[str, Any]] = []
    dataset_meta: dict[str, Any] = {}

    ds_name = getattr(dataset, "dataset_name", dataset_name)
    ds_source = getattr(dataset, "source", "")
    ds_groups = getattr(dataset, "groups", [])
    ds_desc = getattr(dataset, "description", "")

    dataset_meta = {
        "dataset_name": ds_name,
        "source": ds_source,
        "groups": "/".join(ds_groups) if ds_groups else "",
        "description": ds_desc,
    }

    for seed in getattr(dataset, "seeds", []):
        value = getattr(seed, "value", str(seed))
        metadata = getattr(seed, "metadata", None) or {}
        seed_entry: dict[str, Any] = {"value": value}
        if metadata:
            seed_entry["metadata"] = metadata
        all_seeds.append(seed_entry)

    if not all_seeds:
        return None

    return {
        "dataset_name": dataset_meta.get("dataset_name", dataset_name),
        "harm_categories": "",
        "source": dataset_meta.get("source", ""),
        "groups": dataset_meta.get("groups", ""),
        "data_type": "text",
        "description": dataset_meta.get("description", f"Pre-downloaded: {dataset_name}"),
        "seed_type": "objective",
        "seeds": all_seeds,
    }


async def fetch_dataset_as_prompt(
    dataset_name: str,
    output_dir: Path,
    *,
    force_update: bool = False,
) -> dict[str, Any] | None:
    """双源拉取单个远程数据集并保存为本地 .prompt 文件。.

    下载策略 (优化后):
      Round 1: 官方源, 3 次重试 (30s 超时) — 充分尝试官方源
      Round 2: 国内镜像, 3 次重试 (60s 超时) — 镜像兜底
      Round 3: 跳过

    Args:
        dataset_name: 数据集名称 (与 Provider 的 dataset_name 属性匹配)
        output_dir: 输出目录
        force_update: True=覆盖已有文件

    Returns:
        下载信息字典, 失败返回 None
    """
    out_path = output_dir / f"{dataset_name}.prompt"

    if out_path.exists() and not force_update:
        print(f"  [缓存] {dataset_name}: 已存在, 跳过 (使用 --update 强制刷新)")
        return {"name": dataset_name, "path": str(out_path), "source": "cached", "seeds": 0}

    dataset = None
    source = "unknown"

    # Round 1: 官方源, 充分重试 (3 次, 30s 超时)
    for attempt in range(1, _OFFICIAL_RETRIES + 1):
        print(f"  [尝试] {dataset_name}: 官方源 (第 {attempt}/{_OFFICIAL_RETRIES} 次, 超时 {_OFFICIAL_TIMEOUT}s)...")
        dataset = await _try_fetch_single_dataset(
            dataset_name,
            use_mirror=False,
            timeout=_OFFICIAL_TIMEOUT,
        )
        if dataset is not None:
            source = "official"
            break

    # Round 2: 国内镜像, 充分重试 (3 次, 60s 超时) — 官方源 3 次全部失败后切换
    if dataset is None:
        print(f"  [切换] {dataset_name}: 官方源 {_OFFICIAL_RETRIES} 次均失败, 切换国内镜像 hf-mirror.com...")
        for attempt in range(1, _MIRROR_RETRIES + 1):
            print(
                f"  [尝试] {dataset_name}: 国内镜像 hf-mirror.com "
                f"(第 {attempt}/{_MIRROR_RETRIES} 次, 超时 {_MIRROR_TIMEOUT}s)..."
            )
            dataset = await _try_fetch_single_dataset(
                dataset_name,
                use_mirror=True,
                timeout=_MIRROR_TIMEOUT,
            )
            if dataset is not None:
                source = "mirror"
                break

    # Round 3: 跳过
    if dataset is None:
        print(f"  [失败] {dataset_name}: 官方 {_OFFICIAL_RETRIES} 次 + 镜像 {_MIRROR_RETRIES} 次均失败, 跳过")
        return None

    # 转换为 .prompt 格式
    prompt_data = _dataset_to_prompt(dataset, dataset_name)
    if prompt_data is None:
        print(f"  [失败] {dataset_name}: 无种子数据")
        return None

    # 写入文件
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(prompt_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    seed_count = len(prompt_data["seeds"])
    print(f"  [OK] {dataset_name}: {seed_count} seeds ({source}) -> {out_path.name}")

    return {
        "name": dataset_name,
        "path": str(out_path),
        "source": source,
        "seeds": seed_count,
    }


# ============================================================
# 批量下载
# ============================================================


async def download_datasets(
    dataset_names: list[str],
    output_dir: Path,
    *,
    force_update: bool = False,
) -> dict[str, Any]:
    """批量下载远程数据集到本地。.

    Args:
        dataset_names: 数据集名称列表
        output_dir: 输出目录
        force_update: True=覆盖已有文件 (月度更新)

    Returns:
        下载日志字典
    """
    print(f"{'=' * 70}")
    print("数据集预下载工具")
    print(f"  输出目录: {output_dir}")
    print(f"  目标数据集: {len(dataset_names)} 个")
    print(f"  更新模式: {'是 (覆盖已有)' if force_update else '否 (跳过已有)'}")
    print(
        f"  双源策略: 官方源 ({_OFFICIAL_RETRIES} 次 {_OFFICIAL_TIMEOUT}s)"
        f" -> 镜像 ({_MIRROR_RETRIES} 次 {_MIRROR_TIMEOUT}s)"
    )
    print(f"{'=' * 70}\n")

    # 初始化 PyRIT Memory (Provider 可能需要)
    try:
        from pyrit.memory import CentralMemory

        CentralMemory.set_memory_instance("sqlite", sqlite_db_path=":memory:")
    except Exception:
        pass

    results: list[dict[str, Any]] = []
    success_count = 0
    fail_count = 0
    mirror_count = 0

    for name in dataset_names:
        info = await fetch_dataset_as_prompt(
            name,
            output_dir,
            force_update=force_update,
        )
        if info:
            results.append(info)
            if info["source"] != "cached":
                success_count += 1
            if info.get("source") == "mirror":
                mirror_count += 1
        else:
            fail_count += 1
            results.append({"name": name, "source": "failed", "seeds": 0})

    # 汇总
    total_seeds = sum(r.get("seeds", 0) for r in results)
    print(f"\n{'=' * 70}")
    print("下载完成")
    print(f"  成功: {success_count} (官方: {success_count - mirror_count}, 镜像: {mirror_count})")
    print(f"  缓存: {len(dataset_names) - success_count - fail_count}")
    print(f"  失败: {fail_count}")
    print(f"  总种子数: {total_seeds}")
    print(f"{'=' * 70}")

    # 保存下载日志
    log = {
        "last_update": datetime.now().isoformat(),
        "total_datasets": len(dataset_names),
        "success": success_count,
        "failed": fail_count,
        "mirror_used": mirror_count,
        "total_seeds": total_seeds,
        "downloads": results,
    }
    save_download_log(log)
    print(f"  下载日志: {_DOWNLOAD_LOG}")

    return log


# ============================================================
# CLI 入口
# ============================================================


def main() -> None:
    """Run dataset download main entry point."""
    parser = argparse.ArgumentParser(
        description="远程数据集全量预下载工具 (官方优先 + 镜像兜底 + 月度更新)",
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=_CORE_DATASETS,
        help=f"要下载的数据集名称 (默认核心: {' '.join(_CORE_DATASETS)})",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="下载全部可用数据集 (61+)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="月度更新模式: 覆盖已有文件, 刷新全部数据集",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="列出所有可用远程数据集",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="检查本地缓存状态",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_OUTPUT_DIR),
        help=f"输出目录 (默认: {_OUTPUT_DIR})",
    )
    args = parser.parse_args()

    if args.list:
        datasets = asyncio.run(list_available_datasets())
        print(f"可用远程数据集 ({len(datasets)}):")
        for name in datasets:
            cached = (_OUTPUT_DIR / f"{name}.prompt").exists()
            tag = "[已缓存]" if cached else "[未下载]"
            print(f"  {tag} {name}")
        return

    if args.check:
        cached = list_local_cached_datasets()
        log = load_download_log()
        print(f"本地缓存状态 ({len(cached)} 个数据集):")
        print(f"  目录: {_OUTPUT_DIR}")
        if log.get("last_update"):
            print(f"  上次更新: {log['last_update']}")
            print(f"  上次成功: {log.get('success', 0)}")
            print(f"  上次失败: {log.get('failed', 0)}")
        print()
        for item in cached:
            size_kb = item["size_bytes"] / 1024
            print(f"  {item['name']:<30} {size_kb:>8.1f} KB  {item['modified']}")
        return

    datasets = asyncio.run(list_available_datasets()) if args.all else args.datasets

    output_dir = Path(args.output_dir)
    asyncio.run(download_datasets(datasets, output_dir, force_update=args.update))


if __name__ == "__main__":
    main()
