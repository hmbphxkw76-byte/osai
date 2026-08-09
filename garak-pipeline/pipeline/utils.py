"""Pipeline 公共工具函数

main.py 只做编排，子功能从此模块导入。
"""

import re
import shutil
import time
from pathlib import Path

import yaml

# ------------------------------------------------------------------
# 配置加载
# ------------------------------------------------------------------

def load_config(config_path: str) -> dict:
    """加载 config/target.yaml 配置

    :param config_path: YAML 配置文件路径
    :returns: 解析后的配置字典
    :raises SystemExit: 配置文件不存在或缺少必填字段
    """
    path = Path(config_path)
    if not path.exists():
        print(f"❌ 配置文件不存在: {config_path}")
        print("💡 请先创建 config/target.yaml（参考现有模板）")
        raise SystemExit(1)

    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # 组合感知校验：不依赖单一 kind 决定必填项，而是按「目标画像分组」独立校验。
    # 支持任意组合：
    #   • 仅 openai 填了（web 留空）→ 以 openai 画像运行
    #   • 仅 web 填了（openai 留空）→ 以 web 画像运行
    #   • 两者都填 → 两条画像都可用（运行时按 kind 决定走哪条，或 --target-url 触发 web）
    #   • 两者都留空 → 致命：至少要有一组完整画像
    # 部分填写的分组视为「未启用」，不计入校验；仅当某分组「有填写迹象」却缺
    # 关键字段时才报错，避免用户误填一半。
    target = config.get("target", {})
    from pipeline.env import get_env

    # 每个分组：需要的关键字段 + 对应 .env 回填映射。
    # api_key 对 openai 不强制（本地 Ollama / 无鉴权网关无需 key）。
    groups = {
        "openai": {
            "fields": ["endpoint", "model"],
            "env_map": {
                "endpoint": "OPENAI_TARGET_ENDPOINT",
                "model": "OPENAI_TARGET_MODEL",
            },
        },
        "web": {
            "fields": ["target_url"],
            "env_map": {"target_url": "WEB_TARGET_URL"},
        },
    }

    complete = []   # 已满足的分组
    partial_errors = []  # 有填写迹象但缺字段的分组

    for name, spec in groups.items():
        fields = spec["fields"]
        env_map = spec["env_map"]
        # 该分组是否有「任何填写迹象」（yaml 或 .env 任一非空）
        has_any = any(
            target.get(f) or get_env(env_map.get(f, ""), "")
            for f in fields
        )
        if not has_any:
            continue  # 整组未启用，跳过

        missing = [f for f in fields if not (target.get(f) or get_env(env_map.get(f, ""), ""))]
        if missing:
            partial_errors.append((name, missing))
        else:
            complete.append(name)

    if complete:
        return config

    # 没有任何完整分组
    if partial_errors:
        # 用户动了某组但没填全 → 指出缺哪些
        lines = []
        for name, missing in partial_errors:
            labels = {
                "endpoint": "endpoint(或 .env OPENAI_TARGET_ENDPOINT)",
                "model": "model(或 .env OPENAI_TARGET_MODEL)",
                "target_url": "target_url(或 .env WEB_TARGET_URL)",
            }
            lines.append(f"   • {name}: 缺少 {', '.join(labels.get(f, f) for f in missing)}")
        print("❌ 目标画像不完整（以下分组已填写但未填全）:")
        print("\n".join(lines))
        print("   💡 请补全该分组，或清空该分组字段以使用另一分组")
        raise SystemExit(1)

    # 两组都完全没填
    print("❌ 未配置任何目标画像：需至少填写一组（openai 或 web）")
    print("   💡 openai: endpoint/model（或 .env 的 OPENAI_TARGET_*）")
    print("   💡 web:    target_url（或 .env 的 WEB_TARGET_URL）")
    raise SystemExit(1)


# ------------------------------------------------------------------
# __pycache__ 清理
# ------------------------------------------------------------------

def clean_pycache(project_root: Path) -> int:
    """递归清理项目下所有 __pycache__ 目录、.pyc/.pyo 文件和 .pytest_cache 目录。

    规则 R-008: 三库统一标准 — 每次运行前和运行后自动执行。
    避免 stale bytecode 导致 TypeError（如添加新参数后旧 .pyc 仍被加载）。

    :param project_root: 项目根目录
    :returns: 清理的文件/目录数
    """
    count = 0

    # 清理临时目录: __pycache__ + .pytest_cache
    for pattern in ("__pycache__", ".pytest_cache"):
        for cache_dir in project_root.rglob(pattern):
            if cache_dir.is_dir():
                shutil.rmtree(cache_dir, ignore_errors=True)
                count += 1

    # 清理编译产物: .pyc + .pyo
    for pattern in ("*.pyc", "*.pyo"):
        for temp_file in project_root.rglob(pattern):
            if temp_file.is_file():
                temp_file.unlink(missing_ok=True)
                count += 1

    return count


# ------------------------------------------------------------------
# 历史产物清理（对齐 L5：避免多次运行产物无限累积）
# ------------------------------------------------------------------

# run_id 时间戳正则：YYYYMMDD_HHMM
_RUN_ID_PATTERN = re.compile(r"(\d{8}_\d{4})")


def prune_old_runs(artifacts_dir: Path, keep: int = 5) -> int:
    """保留最近 N 个 run_id 批次，删除更老的产物

    对齐 L5 专家水平：多次运行后产物按 run_id 累积，旧批次不自动清理会
    导致磁盘膨胀 + 分析时混淆批次。本函数扫描各阶段目录，按 run_id 时间戳
    排序，保留最新 keep 个批次，其余删除。

    :param artifacts_dir: 产物根目录（如 outputs/）
    :param keep: 保留的批次数（默认 5）
    :returns: 删除的文件数
    """
    artifacts = Path(artifacts_dir)
    if not artifacts.exists():
        return 0

    # 收集所有 run_id（从文件名提取 YYYYMMDD_HHMM）
    run_ids: set[str] = set()
    for f in artifacts.rglob("*"):
        if f.is_file():
            m = _RUN_ID_PATTERN.search(f.name)
            if m:
                run_ids.add(m.group(1))

    if len(run_ids) <= keep:
        return 0  # 批次数未超阈值，无需清理

    # 保留最新 keep 个 run_id
    keep_ids = set(sorted(run_ids, reverse=True)[:keep])
    remove_ids = run_ids - keep_ids

    removed = 0
    for f in artifacts.rglob("*"):
        if not f.is_file():
            continue
        m = _RUN_ID_PATTERN.search(f.name)
        if m and m.group(1) in remove_ids:
            try:
                f.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass

    # 清理空目录
    for d in sorted(artifacts.rglob("*"), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            try:
                d.rmdir()
            except OSError:
                pass

    return removed


# ------------------------------------------------------------------
# 启动信息打印
# ------------------------------------------------------------------

def print_banner(
    config_path: str,
    target: dict,
    mode: str,
    artifacts_dir: str,
) -> None:
    """打印启动信息横幅"""
    print("=" * 60)
    print("🛡️  garak 目标侦察 — LLM 攻击面枚举")
    print("=" * 60)
    print(f"   📋 配置: {config_path}")
    print(f"   🎯 目标: {target['model']} @ {target['endpoint']}")
    print(f"   📋 模式: {mode}")
    print(f"   📂 产物: {artifacts_dir}")
    print(f"   ⏱️  启动: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()


# ------------------------------------------------------------------
# 结果打印
# ------------------------------------------------------------------

def print_result(
    success: bool,
    elapsed: float,
    run_id: str,
    artifacts_dir: str,
    error: str | None = None,
) -> None:
    """打印最终结果"""
    print(f"\n{'=' * 60}")
    if success:
        print(f"✅ 侦察完成 (耗时 {elapsed:.1f}s)")
        print(f"{'=' * 60}")
        print("\n📊 侦察产物:")
        print(f"   目标画像: {artifacts_dir}/01_recon/target_profile_{run_id}.json")
        print(f"   攻击面:   {artifacts_dir}/01_recon/probe_candidates_{run_id}.json")
        print(f"   连通性:   {artifacts_dir}/01_recon/connectivity_test_{run_id}.json")
    else:
        print(f"❌ 侦察未完成 (耗时 {elapsed:.1f}s)")
        if error:
            print(f"   错误: {error}")
        print(f"{'=' * 60}")


# ------------------------------------------------------------------
# 卡片化展示（阶段间 + 阶段内）
# ------------------------------------------------------------------

def print_stage_card(
    stage_no: str,
    title: str,
    inputs: list[str],
    outputs: list[str],
    metrics: list[tuple[str, str]],
) -> None:
    """打印一张阶段结果卡片（阶段间产物传递一目了然）

    :param stage_no: 阶段编号，如 "1" / "3"
    :param title: 阶段标题
    :param inputs: 本阶段消费的产物路径
    :param outputs: 本阶段产出的产物路径
    :param metrics: (指标名, 指标值) 列表
    """
    width = 62
    print(f"\n╔{'═' * width}╗")
    print(f"║ {'🔹 STAGE ' + stage_no + '  ' + title:<{width - 1}}║")
    print(f"╠{'═' * width}╣")
    if inputs:
        print(f"║ {'📥 输入:':<{width}}║")
        for i in inputs:
            print(f"║   • {i:<{width - 4}}║")
    if metrics:
        print(f"║ {'📊 关键指标:':<{width}}║")
        for k, v in metrics:
            v_str = "—" if v is None else str(v)
            print(f"║   {k}: {v_str:<{width - len(k) - 3}}║")
    if outputs:
        print(f"║ {'📤 输出:':<{width}}║")
        for o in outputs:
            print(f"║   • {o:<{width - 4}}║")
    print(f"╚{'═' * width}╝")


def print_table_card(title: str, header: list[str], rows: list[list[str]]) -> None:
    """打印一张表格卡片（阶段内重要结果）

    :param title: 卡片标题
    :param header: 表头列名
    :param rows: 数据行
    """
    cols = len(header)
    # 计算各列宽度
    widths = [len(h) for h in header]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(str(cell)))

    def fmt(cells: list[str]) -> str:
        return "│ " + " │ ".join(
            str(c).ljust(widths[i]) for i, c in enumerate(cells)
        ) + " │"

    sep = "├─" + "─┼─".join("─" * w for w in widths) + "─┤"
    bot = "└─" + "─┴─".join("─" * w for w in widths) + "─┘"
    line_w = sum(widths) + 3 * (cols - 1) + 2

    print(f"\n╒{'═' * line_w}╕")
    print(f"│ {title:<{line_w}}│")
    print(f"╞{'═' * line_w}╡")
    print(fmt(header))
    print(sep)
    for r in rows:
        print(fmt(r))
    print(bot)
