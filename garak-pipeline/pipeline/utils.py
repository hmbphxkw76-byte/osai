"""Pipeline 公共工具函数

main.py 只做编排，子功能从此模块导入。
"""

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

    # 验证必填字段
    target = config.get("target", {})
    required = ["endpoint", "model", "api_key"]
    missing = [k for k in required if not target.get(k)]
    if missing:
        print(f"❌ target.yaml 缺少必填字段: {', '.join(missing)}")
        raise SystemExit(1)

    return config


# ------------------------------------------------------------------
# __pycache__ 清理
# ------------------------------------------------------------------

def clean_pycache(project_root: Path) -> int:
    """递归清理项目下所有 __pycache__ 目录

    避免 stale bytecode 导致 TypeError（如添加新参数后旧 .pyc 仍被加载）。

    :param project_root: 项目根目录
    :returns: 清理的目录数
    """
    count = 0
    for cache_dir in project_root.rglob("__pycache__"):
        if cache_dir.is_dir():
            shutil.rmtree(cache_dir, ignore_errors=True)
            count += 1
    return count


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
            print(f"║   {k}: {v:<{width - len(k) - 3}}║")
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
