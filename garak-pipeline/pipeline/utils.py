"""Pipeline 公共工具函数

main.py 只做编排，子功能从此模块导入。
"""

import json
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

# ------------------------------------------------------------------
# DEFCON 色彩/emoji 编码（GAP-2: 终端风险视觉即时感知）
# GAP-14: ANSI 色彩降级 — 非 emoji 终端自动降级为纯文本标签
# ------------------------------------------------------------------

DEFCON_EMOJI: dict[int, str] = {
    1: "🔴",  # 严重 — 完全失败
    2: "🟠",  # 高危 — 存在高危攻击面
    3: "🟡",  # 中危 — 可利用攻击面
    4: "🟢",  # 低危 — 攻击面有限
    5: "✅",  # 安全 — 表现良好
}

# GAP-14: 纯文本降级标签（CI/日志收集器/非 Unicode 终端）
DEFCON_TEXT: dict[int, str] = {
    1: "[CRIT]",
    2: "[HIGH]",
    3: "[MED] ",
    4: "[LOW] ",
    5: "[SAFE]",
}


def _supports_emoji() -> bool:
    """检测当前终端是否支持 emoji 字符

    检测逻辑：
    - 环境变量 NO_EMOJI=1 → 强制禁用
    - TERM=dumb → 不支持
    - Windows 终端（非 dumb）→ 支持（现代 Windows Terminal / PowerShell）
    - 其他平台默认支持
    """
    import os
    if os.environ.get("NO_EMOJI", "").strip() in ("1", "true", "yes"):
        return False
    term = os.environ.get("TERM", "").strip().lower()
    if term == "dumb" or term == "":
        # 空 TERM 可能是管道/CI 环境，降级为纯文本
        return os.environ.get("CI", "").strip() not in ("1", "true", "yes")
    return True


_EMOJI_OK: bool | None = None


def defcon_label(defcon: int | str | None) -> str:
    """返回带 emoji 的 DEFCON 标签（终端色彩编码）

    GAP-14: 自动检测终端 emoji 支持能力，非 emoji 终端降级为纯文本。
    环境变量 NO_EMOVI=1 或 TERM=dumb 或 CI=1 时使用纯文本标签。

    >>> defcon_label(1)
    '🔴 DEFCON 1'
    >>> defcon_label(5)
    '✅ DEFCON 5'
    """
    global _EMOJI_OK
    if _EMOJI_OK is None:
        _EMOJI_OK = _supports_emoji()

    if defcon is None:
        return "N/A" if not _EMOJI_OK else "⚪ N/A"
    try:
        d = int(defcon)
    except (ValueError, TypeError):
        return f"⚪ {defcon}" if _EMOJI_OK else str(defcon)

    if _EMOJI_OK:
        return f"{DEFCON_EMOJI.get(d, '⚪')} DEFCON {d}"
    else:
        return f"{DEFCON_TEXT.get(d, '[?]')} DEFCON {d}"


# ------------------------------------------------------------------
# offsec 攻击链映射（Cyber Kill Chain × MITRE ATT&CK for LLM）
# ------------------------------------------------------------------

ATTACK_KILL_CHAIN: list[tuple[str, str, str]] = [
    ("1", "攻击面侦察 (Reconnaissance)", "枚举目标攻击面、连通性、模型模态"),
    ("2", "武器化配置 (Weaponization)", "Tier 排序、Buff 攻击链组装、载荷选择"),
    ("3", "攻击投递与利用 (Delivery & Exploitation)", "逐探针投递 payload、触发漏洞、收集响应"),
    ("4", "战果分析与评估 (Impact Assessment)", "ASR/DEFCON 评分、双框架聚合、命中审查"),
    ("5", "红队交付物 (Red Team Deliverables)", "PyRIT/HTML/SARIF 导出、命中明细、复现哈希"),
]


def print_banner(
    config_path: str,
    target: dict,
    mode: str,
    artifacts_dir: str,
    scope: dict | None = None,
) -> None:
    """打印红队攻击链启动横幅（offsec 视角）

    以攻击者视角框架整个流水线，而非防御扫描器。
    展示攻击链阶段映射，使操作者始终以 offsec 主轴推进。
    """
    W = 62
    print()
    print(f"{'═' * (W + 2)}")
    print(f" ⚔️  garak LLM 红队攻击链 — Red Team Engagement")
    print(f"{'═' * (W + 2)}")
    print(f"   🎯 攻击目标: {target['model']} @ {target['endpoint']}")
    print(f"   📋 交战模式: {mode}")
    print(f"   📂 战果目录: {artifacts_dir}")
    print(f"   ⏱️  发起时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    # Phase 5: 交战范围声明
    if scope:
        in_scope = scope.get("in_scope", [])
        out_scope = scope.get("out_of_scope", [])
        if in_scope:
            print(f"   📋 范围内: {', '.join(in_scope)}")
        if out_scope:
            print(f"   🚫 范围外: {', '.join(out_scope)}")
    print()
    # 攻击链阶段映射
    print(f"   ┌{'─' * (W - 2)}┐")
    print(f"   │ {'🔗 攻击链阶段映射 (Kill Chain)':<{W - 3}}│")
    print(f"   ├{'─' * (W - 2)}┤")
    for stage_no, stage_title, stage_desc in ATTACK_KILL_CHAIN:
        print(f"   │  [{stage_no}] {stage_title}")
        print(f"   │      └─ {stage_desc}")
    print(f"   └{'─' * (W - 2)}┘")
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
    """打印红队交战最终战果（offsec 视角）"""
    W = 62
    print(f"\n{'═' * (W + 2)}")
    if success:
        print(f" 🏁 红队攻击链完成 (耗时 {elapsed:.1f}s | run_id={run_id})")
        print(f"{'═' * (W + 2)}")
        print("\n📦 战果产物索引:")
        print(f"   [侦察]   {artifacts_dir}/01_recon/target_profile_{run_id}.json")
        print(f"   [配置]   {artifacts_dir}/02_config/probe_selection_{run_id}.json")
        print(f"   [攻击]   {artifacts_dir}/03_execution/garak_report_{run_id}.jsonl")
        print(f"   [战果]   {artifacts_dir}/04_analysis/analysis_{run_id}.json")
        print(f"   [交付]   {artifacts_dir}/05_export/")
    else:
        print(f" ⛔ 攻击链中断 (耗时 {elapsed:.1f}s)")
        if error:
            print(f"   错误: {error}")
        print(f"{'═' * (W + 2)}")


# ------------------------------------------------------------------
# 卡片化展示（阶段间 + 阶段内）
# ------------------------------------------------------------------

def print_stage_card(
    stage_no: str,
    title: str,
    inputs: list[str],
    outputs: list[str],
    metrics: list[tuple[str, str]],
    elapsed: float | None = None,
) -> None:
    """打印一张阶段结果卡片（阶段间产物传递一目了然）

    :param stage_no: 阶段编号，如 "1" / "3"
    :param title: 阶段标题
    :param inputs: 本阶段消费的产物路径
    :param outputs: 本阶段产出的产物路径
    :param metrics: (指标名, 指标值) 列表
    :param elapsed: 本阶段耗时（秒），可选。GAP-8: 每阶段耗时统计
    """
    width = 62
    # GAP-8: 将耗时追加到 metrics 末尾
    if elapsed is not None:
        metrics = list(metrics) + [("耗时", f"{elapsed:.1f}s")]
    print(f"\n╔{'═' * width}╗")
    print(f"║ {'⚔️ PHASE ' + stage_no + '  ' + title:<{width - 1}}║")
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


# ------------------------------------------------------------------
# offsec 攻击执行实时进度展示
# ------------------------------------------------------------------

def print_attack_progress(
    idx: int,
    total: int,
    probe_name: str,
    status: str,
    asr: float | None = None,
    atlas_ttp: str | None = None,
    hit_preview: str | None = None,
) -> None:
    """打印单探针攻击执行进度（offsec 实时反馈 + ATLAS 战术标注）

    在 Stage3 逐探针循环中调用，使操作者实时看到攻击投递进度、战术上下文与命中 loot。

    :param idx: 当前探针序号（从 1 开始）
    :param total: 探针总数
    :param probe_name: 探针全名
    :param status: "running" | "ok" | "fail" | "skip"
    :param asr: 该探针的 ASR（百分比），仅 status="ok" 时有意义
    :param atlas_ttp: ATLAS 战术/技术标注（如 "AML.T0051.000 Prompt Injection"）
    :param hit_preview: 命中内容预览（成功越狱的 output 摘要）
    """
    # 截断过长的探针名以保持对齐
    short_name = probe_name.replace("probes.", "")
    if len(short_name) > 40:
        short_name = short_name[:37] + "..."

    # ATLAS 战术标注
    ttp_tag = f" [{atlas_ttp}]" if atlas_ttp else ""

    prefix = f"   [{idx}/{total}]"

    if status == "running":
        # N1: 实时刷新 — 用 \r 覆写单行，避免逐行堆积
        print(f"\r{prefix} ▶ {short_name:<40}{ttp_tag} ...", end="", flush=True)
    elif status == "ok":
        if asr is not None and asr > 0:
            hit_tag = f"ASR={asr:.0f}% 💥"
        else:
            hit_tag = "ASR=0%"
        # N1: 清除 running 行后换行打印最终结果
        print(f"\r{prefix} ✓ {short_name:<40}{ttp_tag} {hit_tag}{'':<20}", flush=True)
        # 命中 loot 预览
        if hit_preview:
            preview = hit_preview[:80] + ("..." if len(hit_preview) > 80 else "")
            print(f"         └─ [LOOT] {preview}", flush=True)
    elif status == "fail":
        print(f"\r{prefix} ✗ {short_name:<40}{ttp_tag} FAILED{'':<20}", flush=True)
    elif status == "skip":
        print(f"\r{prefix} ⏭ {short_name:<40}{ttp_tag} skipped (checkpoint){'':<10}", flush=True)


def print_offsec_engagement_summary(
    probes_total: int,
    probes_succeeded: int,
    probes_failed: int,
    probes_skipped: int,
    analysis: dict | None = None,
) -> None:
    """打印红队交战总结（offsec 战果汇总）

    在 Stage5 结束后调用，以攻击者视角汇总整个攻击链的战果：
    - 投递的攻击载荷数、成功/失败比
    - 命中数（ASR > 0 的探针）
    - 最差 DEFCON 等级
    - 最有效的攻击向量（最高 ASR 探针）

    :param probes_total: 配置的总探针数
    :param probes_succeeded: 成功执行的探针数
    :param probes_failed: 执行失败的探针数
    :param probes_skipped: 跳过的探针数（断点续扫）
    :param analysis: Stage4 分析结果（可选，用于展示命中战果）
    """
    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🏁 红队交战总结 (Engagement Summary)':<{W}}║")
    print(f"╠{'═' * W}╣")

    # 攻击投递统计
    print(f"║ {'📡 攻击投递:':<{W}}║")
    print(f"║   载荷总数: {probes_total:<{W - 10}}║")
    print(f"║   成功投递: {probes_succeeded:<{W - 10}}║")
    if probes_failed:
        print(f"║   投递失败: {probes_failed:<{W - 10}}║")
    if probes_skipped:
        print(f"║   断点跳过: {probes_skipped:<{W - 10}}║")

    # 命中战果（需要 analysis 数据）
    if analysis:
        overall = analysis.get("overall", {})
        worst_asr = overall.get("worst_asr", 0)
        defcon = overall.get("defcon", "-")
        hit_count = analysis.get("hitlog", {}).get("hit_count", 0)
        probes_evaluated = overall.get("probes_evaluated", 0)

        print(f"╠{'═' * W}╣")
        print(f"║ {'💥 命中战果:':<{W}}║")
        print(f"║   命中总数: {hit_count:<{W - 10}}║")
        print(f"║   最差 ASR: {worst_asr}%{'':<{W - 12 - len(str(worst_asr)) - 1}}║")
        print(f"║   整体 DEFCON: {defcon}{'':<{W - 14 - len(str(defcon))}}║")
        print(f"║   评估探针: {probes_evaluated:<{W - 10}}║")

        # 找出最有效的攻击向量（ASR 最高的探针）
        probe_results = analysis.get("probe_results", {})
        if probe_results:
            top_exploits = sorted(
                probe_results.items(),
                key=lambda x: x[1].get("asr", 0),
                reverse=True,
            )[:3]
            effective = [p for p, v in top_exploits if v.get("asr", 0) > 0]
            if effective:
                print(f"╠{'═' * W}╣")
                print(f"║ {'🎯 最有效攻击向量 (Top 3 by ASR):':<{W}}║")
                for probe, v in top_exploits:
                    asr_val = v.get("asr", 0)
                    if asr_val <= 0:
                        continue
                    short = probe.replace("probes.", "")
                    if len(short) > 40:
                        short = short[:37] + "..."
                    line = f"   {short}: ASR={asr_val}%"
                    print(f"║ {line:<{W}}║")

        # GAP-3: 战果预览（Proof of Exploitation）
        print_loot_preview(analysis)

        # GAP-10: 安全态势趋势 Delta
        trend = analysis.get("trend_analysis", {})
        trend_points = trend.get("trend_points", [])
        if len(trend_points) >= 2:
            prev = trend_points[-2]
            curr = trend_points[-1]
            asr_delta = curr.get("worst_asr", 0) - prev.get("worst_asr", 0)
            defcon_delta = (curr.get("defcon") or 5) - (prev.get("defcon") or 5)
            direction = trend.get("trend_direction", "stable")
            dir_icon = (
                "📈 恶化" if direction == "degrading"
                else "📉 改善" if direction == "improving"
                else "➡️ 稳定"
            )
            print(f"╠{'═' * W}╣")
            print(f"║ {'📊 安全态势趋势:':<{W}}║")
            prev_asr = prev.get("worst_asr", 0)
            curr_asr = curr.get("worst_asr", 0)
            prev_dc = prev.get("defcon", "?")
            curr_dc = curr.get("defcon", "?")
            delta_str = f"{asr_delta:+.1f}"
            print(f"║   {dir_icon} ASR: {prev_asr}% → {curr_asr}% (Δ{delta_str}%){'':<{W - 35}}║")
            print(f"║   DEFCON: {prev_dc} → {curr_dc} (Δ{defcon_delta:+d}){'':<{W - 30}}║")

        # 数据可靠性
        dq = analysis.get("data_quality", {})
        rel = dq.get("reliability", "normal")
        if rel != "normal":
            print(f"╠{'═' * W}╣")
            print(f"║ {'⚠️  数据可靠性: {rel}':<{W}}║")
            null_rate = dq.get("overall_null_rate", 0)
            print(f"║   null 输出率: {null_rate:.1f}%{'':<{W - 14 - len(f'{null_rate:.1f}%')}}║")

        # GAP-11: 执行摘要（Executive Summary — 一句话风险评估结论）
        try:
            dc = int(defcon) if defcon != "-" else 5
        except (ValueError, TypeError):
            dc = 5
        if dc <= 2:
            verdict = "🔴 高风险：目标存在严重可利用漏洞，建议立即修复"
        elif dc == 3:
            verdict = "🟡 中风险：目标存在可利用攻击面，建议限期修复"
        elif dc == 4:
            verdict = "🟢 低风险：目标攻击面有限，建议持续监控"
        else:
            verdict = "✅ 低风险：目标表现良好，建议常规巡检"
        print(f"╠{'═' * W}╣")
        print(f"║ {'📋 执行摘要 (Executive Summary):':<{W}}║")
        print(f"║   {verdict:<{W - 3}}║")

    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# GAP-3: Loot 战果预览（Proof of Exploitation）
# ------------------------------------------------------------------

def print_loot_preview(analysis: dict, max_items: int = 3) -> None:
    """打印 Top N 命中战果预览（offsec proof of exploitation）

    从 hitlog JSONL 提取实际攻击命中记录，展示 prompt → output → detector 链路，
    使红队操作者在终端即可看到实际越狱内容，而非仅百分比数字。

    :param analysis: Stage4 分析结果 dict
    :param max_items: 最多展示条数
    """
    hitlog = analysis.get("hitlog", {})
    jsonl_path = hitlog.get("jsonl_path")
    if not jsonl_path:
        return
    p = Path(jsonl_path)
    if not p.exists():
        return
    hits: list[dict] = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not hits:
        return
    W = 62
    print(f"╠{'═' * W}╣")
    print(f"║ {'💎 战果预览 (Proof of Exploitation):':<{W}}║")
    for i, hit in enumerate(hits[:max_items], 1):
        probe = hit.get("probe", "unknown")
        if len(probe) > 35:
            probe = probe[:32] + "..."
        prompt = (hit.get("prompt", "") or "")[:45].replace("\n", " ")
        output = (hit.get("output", "") or "")[:45].replace("\n", " ")
        dets = ", ".join(hit.get("triggered_detectors", []))
        if len(dets) > 25:
            dets = dets[:22] + "..."
        print(f"║   [{i}] {probe:<{W - 37}}║")
        print(f"║       PROMPT: {prompt:<{W - 13}}║")
        print(f"║       OUTPUT: {output:<{W - 13}}║")
        print(f"║       DETECT: {dets:<{W - 13}}║")


# ------------------------------------------------------------------
# GAP-4: Kill Path 攻击链路终端卡片
# ------------------------------------------------------------------

def print_kill_paths(kill_paths: list[dict]) -> None:
    """打印攻击链路分析卡片（offsec kill path narrative）

    展示识别到的多步攻击链（如 注入→数据泄露），使操作者理解攻击者如何
    从初始突破到最终目标，而非仅看孤立探针结果。

    :param kill_paths: stage4 _analyze_kill_paths() 返回的列表
    """
    if not kill_paths:
        return
    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🔗 攻击链路分析 (Kill Path Analysis):':<{W}}║")
    print(f"╠{'═' * W}╣")
    for kp in kill_paths:
        name = kp.get("path_name", "")[:W - 6]
        combined_asr = kp.get("combined_asr", 0)
        narrative = kp.get("narrative", "")[:W - 6]
        print(f"║  ⚔️  {name:<{W - 6}}║")
        print(f"║     组合 ASR: {combined_asr}%{'':<{W - 14 - len(str(combined_asr)) - 1}}║")
        print(f"║     {narrative:<{W - 5}}║")
        for stage in kp.get("stages", []):
            stage_short = str(stage)[:W - 8]
            print(f"║    → {stage_short:<{W - 8}}║")
        print(f"║{' ' * W}║")
    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# GAP-5: 修复建议优先级终端卡片
# ------------------------------------------------------------------

def print_remediation_priority(remediation: list[dict], max_items: int = 3) -> None:
    """打印修复优先级卡片（红队 → 蓝队闭环）

    按优先级排序展示修复建议，使攻击评估闭环到防御行动。
    红队报告的 "so what" 环节同等重要。

    :param remediation: stage4 _generate_remediation_recommendations() 返回的列表
    :param max_items: 最多展示条数
    """
    if not remediation:
        return
    W = 62
    priority_order = {"high": 0, "medium": 1, "low": 2}
    sorted_recs = sorted(
        remediation,
        key=lambda r: priority_order.get(r.get("priority", "low"), 3),
    )[:max_items]
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🛡️  修复优先级 (Remediation Priority):':<{W}}║")
    print(f"╠{'═' * W}╣")
    for rec in sorted_recs:
        cat = rec.get("owasp_category", "")[:W - 10]
        asr = rec.get("asr", 0)
        defcon = rec.get("defcon", 5)
        priority = rec.get("priority", "low")
        icon = "🔴" if priority == "high" else "🟡" if priority == "medium" else "🟢"
        print(f"║  {icon} {cat:<{W - 8}}║")
        print(f"║     ASR={asr}% DEFCON={defcon} 优先级={priority:<{W - 28}}║")
        for r in rec.get("recommendations", [])[:2]:
            r_short = r[:W - 8]
            print(f"║    → {r_short:<{W - 8}}║")
        print(f"║{' ' * W}║")
    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# GAP-15: IOA 检测规则终端预览
# ------------------------------------------------------------------

def print_ioa_preview(ioa_path: str, max_rules: int = 3) -> None:
    """打印 IOA 检测规则预览（offsec 检测工程交付物预览）

    从 ioa_rules_{run_id}.json 读取蓝队可消费的检测规则，展示前 N 条规则
    的 probe、prompt 模式和检测逻辑，使红队操作者在终端即可审查检测规则。

    :param ioa_path: IOA 规则 JSON 文件路径
    :param max_rules: 最多展示规则条数
    """
    if not ioa_path:
        return
    p = Path(ioa_path)
    if not p.exists():
        return
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    rules = data.get("rules", [])
    if not rules:
        return
    W = 62
    total = data.get("total_rules", len(rules))
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🔎 IOA 检测规则预览 (Detection Rules):':<{W}}║")
    print(f"╠{'═' * W}╣")
    print(f"║   规则总数: {total}{'':<{W - 11 - len(str(total))}}║")
    for i, rule in enumerate(rules[:max_rules], 1):
        rule_id = rule.get("rule_id", "?")[:W - 8]
        probe = rule.get("probe", "unknown")
        if len(probe) > 30:
            probe = probe[:27] + "..."
        prompt = (rule.get("prompt_pattern", "") or "")[:40].replace("\n", " ")
        dets = ", ".join(rule.get("detectors", []))
        if len(dets) > 25:
            dets = dets[:22] + "..."
        print(f"║  [{i}] {rule_id:<{W - 8}}║")
        print(f"║      探针: {probe:<{W - 11}}║")
        print(f"║      模式: {prompt:<{W - 11}}║")
        print(f"║      检测: {dets:<{W - 11}}║")
    if total > max_rules:
        print(f"║   ...及另外 {total - max_rules} 条规则{'':<{W - 16 - len(str(total - max_rules))}}║")
    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# E1: MITRE ATLAS 热力图（终端战术×探针覆盖矩阵）
# ------------------------------------------------------------------

def print_atlas_heatmap(
    probe_results: dict,
    probe_ttp_map: dict[str, str] | None = None,
) -> None:
    """打印 ATLAS 战术热力图（offsec 战术覆盖可视化）

    展示每个 ATLAS 战术/技术下有多少探针命中（ASR > 0），使操作者
    一目了然地看到哪些攻击战术被成功验证，而非仅看探针名列表。

    :param probe_results: Stage4 probe_results dict
    :param probe_ttp_map: 探针→ATLAS TTP 映射（可选，从 atlas_map 构建）
    """
    if not probe_results or not probe_ttp_map:
        return

    # 构建战术→探针命中统计
    tactic_stats: dict[str, dict] = {}
    for probe_name, info in probe_results.items():
        short = probe_name.replace("probes.", "")
        ttp_str = probe_ttp_map.get(probe_name) or probe_ttp_map.get(short, "")
        if not ttp_str:
            continue
        asr = info.get("asr", 0)
        for ttp in ttp_str.split(", "):
            ttp = ttp.strip()
            if not ttp:
                continue
            if ttp not in tactic_stats:
                tactic_stats[ttp] = {"total": 0, "hit": 0, "max_asr": 0.0}
            tactic_stats[ttp]["total"] += 1
            if asr > 0:
                tactic_stats[ttp]["hit"] += 1
            tactic_stats[ttp]["max_asr"] = max(tactic_stats[ttp]["max_asr"], asr)

    if not tactic_stats:
        return

    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🎯 ATLAS 战术热力图 (Tactic Heatmap):':<{W}}║")
    print(f"╠{'═' * W}╣")
    print(f"║ {'TTP':<18} {'探针':>4} {'命中':>4} {'最差ASR':>8} {'覆盖度':>7}{'':<{W - 45}}║")
    print(f"╠{'═' * W}╣")

    for ttp in sorted(tactic_stats.keys()):
        s = tactic_stats[ttp]
        coverage = s["hit"] / s["total"] * 100 if s["total"] > 0 else 0
        # 热力图色彩：命中率高→🔴，中→🟡，低→🟢，无命中→⚪
        if s["hit"] == 0:
            bar = "⚪"
        elif coverage >= 75:
            bar = "🔴"
        elif coverage >= 50:
            bar = "🟠"
        elif coverage >= 25:
            bar = "🟡"
        else:
            bar = "🟢"
        asr_str = f'{s["max_asr"]:.0f}%' if s["max_asr"] > 0 else "—"
        cov_str = f'{coverage:.0f}%'
        s_total = s["total"]
        s_hit = s["hit"]
        print(f"║ {bar} {ttp:<15} {s_total:>4} {s_hit:>4} {asr_str:>8} {cov_str:>7}{'':<{W - 47}}║")

    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# E2: Technique-Intent 矩阵终端展示
# ------------------------------------------------------------------

def print_technique_intent_matrix(matrix: dict, max_techniques: int = 5) -> None:
    """打印攻技×意图交叉矩阵（offsec 攻击效果矩阵）

    garak digest.technique_intent_matrix 提供攻击技术维度（demon:* tags）
    的意图级通过率，超越单一 ASR 聚合粒度。

    :param matrix: analysis["technique_intent_matrix"] dict
    :param max_techniques: 最多展示技术条数
    """
    if not matrix:
        return

    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'⚔️  攻技×意图矩阵 (Technique-Intent Matrix):':<{W}}║")
    print(f"╠{'═' * W}╣")

    count = 0
    for tech_tag, tech_data in sorted(matrix.items()):
        if count >= max_techniques:
            break
        count += 1

        summary = tech_data.get("_summary", {})
        tech_name = summary.get("name", tech_tag)[:W - 8]
        n_intents = summary.get("n_intents", 0)
        n_detectors = summary.get("n_detectors", 0)

        print(f"║  🔧 {tech_name:<{W - 8}}║")
        print(f"║     tag={tech_tag}  意图={n_intents}  检测器={n_detectors}{'':<{max(0, W - 30 - len(tech_tag))}}║")

        # 展示每个 intent 的通过率
        intent_count = 0
        for intent_code, intent_data in tech_data.items():
            if intent_code == "_summary":
                continue
            if intent_count >= 3:
                remaining = n_intents - intent_count
                if remaining > 0:
                    print(f"║     ...及另外 {remaining} 个意图{'':<{W - 20 - len(str(remaining))}}║")
                break
            intent_count += 1

            iname = intent_data.get("name", intent_code)[:25]
            score = intent_data.get("score", 0)
            passed = intent_data.get("passed", 0)
            total = intent_data.get("total_evaluated", 0)
            pass_rate = f"{passed}/{total}" if total > 0 else "—"
            # 通过率色彩：高通过=🔴（攻击成功），低=🟢
            if total > 0 and passed / total >= 0.5:
                hit_icon = "🔴"
            elif total > 0 and passed / total >= 0.25:
                hit_icon = "🟡"
            else:
                hit_icon = "🟢"
            print(f"║    {hit_icon} {iname:<25} 通过={pass_rate:<8} score={score}{'':<{W - 48}}║")

        print(f"║{' ' * W}║")

    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# E3: 多目标对比报告（多 run_id 横向对比）
# ------------------------------------------------------------------

def print_multi_run_comparison(
    artifacts_dir: str,
    current_run_id: str,
    max_runs: int = 3,
) -> None:
    """打印多次运行横向对比卡片（offsec 安全态势演进）

    从 04_analysis 目录读取历史 analysis JSON，横向对比 ASR/DEFCON/命中数，
    使操作者看到安全态势的多次运行趋势，而非仅纵向 Delta。

    :param artifacts_dir: 产物根目录
    :param current_run_id: 当前 run_id
    :param max_runs: 最多对比运行次数（含当前）
    """
    analysis_dir = Path(artifacts_dir) / "04_analysis"
    if not analysis_dir.exists():
        return

    # 收集所有 analysis_*.json
    run_pattern = re.compile(r"analysis_(\d{8}_\d{4})\.json$")
    runs: list[tuple[str, dict]] = []
    for f in sorted(analysis_dir.glob("analysis_*.json"), reverse=True):
        m = run_pattern.search(f.name)
        if not m:
            continue
        rid = m.group(1)
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            runs.append((rid, data))
        except (json.JSONDecodeError, OSError):
            continue
        if len(runs) >= max_runs:
            break

    if len(runs) < 2:
        return  # 仅一次运行无需对比

    # 按时间正序排列（最老→最新）
    runs.reverse()

    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'📊 多目标横向对比 (Multi-Run Comparison):':<{W}}║")
    print(f"╠{'═' * W}╣")

    # 表头
    header = f"║ {'run_id':<16} {'最差ASR':>8} {'DEFCON':>7} {'命中':>5} {'探针':>5}{'':<{W - 45}}║"
    print(header)
    print(f"╠{'═' * W}╣")

    for rid, data in runs:
        overall = data.get("overall", {})
        worst_asr = overall.get("worst_asr", 0)
        defcon = overall.get("defcon", "-")
        hit_count = data.get("hitlog", {}).get("hit_count", 0)
        probes = overall.get("probes_evaluated", 0)

        # 标记当前运行
        marker = " ◄" if rid == current_run_id else "  "
        dc_icon = ""
        try:
            d = int(defcon)
            dc_icon = DEFCON_EMOJI.get(d, "")
        except (ValueError, TypeError):
            pass

        asr_str = f"{worst_asr}%"
        print(f"║  {rid:<15} {asr_str:>8} {dc_icon}D{defcon:>3} {hit_count:>5} {probes:>5}{marker:<{W - 43}}║")

    # 趋势方向
    if len(runs) >= 2:
        first_asr = runs[0][1].get("overall", {}).get("worst_asr", 0)
        last_asr = runs[-1][1].get("overall", {}).get("worst_asr", 0)
        delta = last_asr - first_asr
        if delta > 0:
            trend = f"📈 ASR 上升 {delta:+.1f}%（安全态势恶化）"
        elif delta < 0:
            trend = f"📉 ASR 下降 {delta:+.1f}%（安全态势改善）"
        else:
            trend = "➡️ ASR 无变化"
        print(f"╠{'═' * W}╣")
        print(f"║   {trend:<{W - 3}}║")

    print(f"╚{'═' * W}╝")


def print_cross_model_comparison(
    artifacts_dir: str,
    max_models: int = 5,
) -> None:
    """F7: 打印跨模型横向对比矩阵（同一探针 vs 不同模型 ASR）

    从历史 analysis JSON 收集不同 target_model 的结果，
    构建探针 × 模型 ASR 矩阵，使红队可一眼识别哪个模型在哪个攻击面上最脆弱。

    :param artifacts_dir: 产物根目录
    :param max_models: 最多对比模型数
    """
    analysis_dir = Path(artifacts_dir) / "04_analysis"
    if not analysis_dir.exists():
        return

    # 收集所有历史结果，按 model 分组
    model_results: dict[str, dict[str, float]] = {}  # model → {probe → asr}
    model_run_ids: dict[str, str] = {}

    for f in sorted(analysis_dir.glob("analysis_*.json"), reverse=True):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        model = data.get("target_model", "unknown")
        if model in model_results:
            continue  # 已有该模型最新结果
        probe_results = data.get("probe_results", {})
        model_results[model] = {
            pr.replace("probes.", ""): info.get("asr", 0)
            for pr, info in probe_results.items()
        }
        rid = f.stem.replace("analysis_", "")
        model_run_ids[model] = rid
        if len(model_results) >= max_models:
            break

    if len(model_results) < 2:
        return  # 仅一个模型无需跨模型对比

    # 收集所有探针名（并集）
    all_probes = set()
    for probes in model_results.values():
        all_probes.update(probes.keys())
    # 按 ASR 降序排列（取各模型最大 ASR）
    probe_max_asr = {}
    for p in all_probes:
        probe_max_asr[p] = max(model_results[m].get(p, 0) for m in model_results)
    sorted_probes = sorted(all_probes, key=lambda x: probe_max_asr[x], reverse=True)[:15]  # Top 15

    models = list(model_results.keys())
    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🎯 跨模型横向对比矩阵 (Cross-Model ASR Matrix):':<{W}}║")
    print(f"╠{'═' * W}╣")

    # 表头
    model_headers = "  ".join(f"{m[:12]:>12}" for m in models)
    header = f"║ {'Probe':<28}{model_headers}{'':<{W - 28 - len(model_headers)}}║"
    print(header)
    print(f"╠{'═' * W}╣")

    for probe in sorted_probes:
        cells = []
        for m in models:
            asr = model_results[m].get(probe, 0)
            if asr >= 50:
                cells.append(f"{'💥'+f'{asr:.0f}%':>12}")
            elif asr > 0:
                cells.append(f"{f'{asr:.0f}%':>12}")
            else:
                cells.append(f"{'—':>12}")
        row = "  ".join(cells)
        short_p = probe[:26] + ".." if len(probe) > 26 else probe
        print(f"║ {short_p:<28}{row}{'':<{max(0, W - 28 - len(row))}}║")

    print(f"╠{'═' * W}╣")
    # 模型 run_id
    for m in models:
        rid = model_run_ids.get(m, "?")
        print(f"║  {m[:20]:<20} run_id: {rid:<20}{'':<{W - 46}}║")
    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# E4: 对话上下文终端查看器
# ------------------------------------------------------------------

def print_conversation_preview(conv_path: str, max_items: int = 3) -> None:
    """打印攻击对话上下文预览（offsec 攻击链路对话回溯）

    从 pyrit_conversations_{run_id}.json 读取攻击对话记录，
    展示 prompt→response→judge verdict 链路，使操作者在终端
    即可回溯攻击过程。

    :param conv_path: 对话上下文 JSON 文件路径
    :param max_items: 最多展示对话条数
    """
    if not conv_path:
        return
    p = Path(conv_path)
    if not p.exists():
        return
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    conversations = data.get("conversations", [])
    if not conversations:
        return

    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'💬 攻击对话回溯 (Conversation Replay):':<{W}}║")
    print(f"╠{'═' * W}╣")
    print(f"║   对话总数: {len(conversations)}{'':<{W - 11 - len(str(len(conversations)))}}║")

    for i, conv in enumerate(conversations[:max_items], 1):
        probe = conv.get("probe", "unknown")
        if len(probe) > 30:
            probe = probe[:27] + "..."
        messages = conv.get("messages", [])
        user_msg = next((m for m in messages if m.get("role") == "user"), {})
        asst_msg = next((m for m in messages if m.get("role") == "assistant"), {})
        prompt = (user_msg.get("content", "") or "")[:45].replace("\n", " ")
        response = (asst_msg.get("content", "") or "")[:45].replace("\n", " ")
        dets = ", ".join(conv.get("detectors", []))
        if len(dets) > 25:
            dets = dets[:22] + "..."

        print(f"╠{'═' * W}╣")
        print(f"║   [{i}] {probe:<{W - 37}}║")
        print(f"║   👤 PROMPT:  {prompt:<{W - 16}}║")
        print(f"║   🤖 RESPONSE: {response:<{W - 16}}║")
        print(f"║   🔍 DETECT:  {dets:<{W - 16}}║")

        judge = conv.get("judge_verdict")
        if judge:
            jb = judge.get("jailbroken", False)
            conf = judge.get("confidence", 0.0)
            jb_icon = "💥 越狱成功" if jb else "🛡️ 未越狱"
            print(f"║   ⚖️  JUDGE:   {jb_icon} (置信度={conf:.0%}){'':<{W - 30}}║")

    if len(conversations) > max_items:
        remaining = len(conversations) - max_items
        print(f"╠{'═' * W}╣")
        print(f"║   ...及另外 {remaining} 条对话{'':<{W - 16 - len(str(remaining))}}║")

    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# Phase 1: 侦察→攻击自适应桥接（Gap-01/13）
# ------------------------------------------------------------------

def print_recon_to_attack_bridge(
    rationale: list[tuple[str, str]],
) -> None:
    """打印侦察→攻击决策链过渡卡片（offsec 侦察驱动攻击叙事）

    在 Stage 1 和 Stage 2 之间调用，展示侦察情报如何动态驱动攻击计划。

    :param rationale: [(侦察发现, 攻击调整), ...] 列表
    """
    if not rationale:
        return
    W = 62
    print(f"\n╔{'═' * W}╗")
    print(f"║ {'🔍 侦察→攻击决策链 (Recon-to-Attack Bridge)':<{W}}║")
    print(f"╠{'═' * W}╣")
    for finding, adjustment in rationale:
        # 截断过长的文本以保持对齐
        f_short = finding[:W - 6] if len(finding) > W - 6 else finding
        a_short = adjustment[:W - 6] if len(adjustment) > W - 6 else adjustment
        print(f"║  🔍 {f_short:<{W - 6}}║")
        print(f"║  → {a_short:<{W - 5}}║")
        print(f"║{' ' * W}║")
    print(f"╚{'═' * W}╝")


# ------------------------------------------------------------------
# Phase 2: 战术覆盖矩阵展示（Gap-15）
# ------------------------------------------------------------------

def print_tactical_coverage(
    covered: list[str],
    total_atlas_tactics: int = 12,
) -> None:
    """打印 ATLAS 战术覆盖进度（offsec 实时战术态势）

    在 Stage3 执行过程中定期调用，展示已覆盖的 ATLAS 战术数。

    :param covered: 已覆盖的 ATLAS 战术 ID 列表
    :param total_atlas_tactics: ATLAS 战术总数（默认 12）
    """
    n = len(covered)
    tags = ", ".join(covered[:6])
    if len(covered) > 6:
        tags += f", +{len(covered) - 6}"
    print(f"   🎯 战术覆盖: ATLAS {n}/{total_atlas_tactics} ({tags})", flush=True)


# ------------------------------------------------------------------
# F14: 多探针并发 progress bar
# ------------------------------------------------------------------

def print_concurrent_progress(
    probe_status: dict[str, str],
    total: int,
) -> None:
    """F14: 打印多探针并发执行进度（多行覆写）

    在并发执行场景下，同时展示多个探针的执行状态。

    :param probe_status: {probe_name: "running"|"ok"|"fail"} 当前各探针状态
    :param total: 探针总数
    """
    completed = sum(1 for s in probe_status.values() if s in ("ok", "fail"))
    running = sum(1 for s in probe_status.values() if s == "running")
    pct = completed / total * 100 if total > 0 else 0

    # 进度条
    bar_len = 30
    filled = int(pct / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    status_icons = {"running": "▶", "ok": "✓", "fail": "✗"}
    # 显示 running 探针名（最多 3 个）
    running_probes = [p.replace("probes.", "")[:20] for p, s in probe_status.items() if s == "running"][:3]
    running_str = " | ".join(running_probes) if running_probes else ""

    print(
        f"\r  [{completed}/{total}] {bar} {pct:.0f}% "
        f"({running} running) {running_str:<60}",
        end="", flush=True,
    )
    if completed == total:
        print(f"\r  [{completed}/{total}] {bar} {pct:.0f}% — done{'':<60}", flush=True)


# ------------------------------------------------------------------
# F15: 终端输出 i18n
# ------------------------------------------------------------------

TERMINAL_I18N = {
    "zh": {
        "stage_1": "侦察",
        "stage_2": "配置",
        "stage_3": "攻击执行",
        "stage_4": "战果分析",
        "stage_5": "报告导出",
        "probes_total": "探针总数",
        "probes_succeeded": "成功探针",
        "probes_failed": "失败探针",
        "probes_skipped": "跳过探针",
        "worst_asr": "最差 ASR",
        "overall_defcon": "整体 DEFCON",
        "hit_count": "命中! 命中数",
        "coverage": "覆盖率",
        "reliability": "数据可靠性",
        "repro_hash": "可复现哈希",
        "kill_paths": "攻击链路",
        "remediation": "修复建议",
        "pass": "通过",
        "blocked": "阻断",
        "regression": "回归告警",
        "cross_model": "跨模型对比",
    },
    "en": {
        "stage_1": "Recon",
        "stage_2": "Config",
        "stage_3": "Attack Execution",
        "stage_4": "Impact Assessment",
        "stage_5": "Report Export",
        "probes_total": "Probes Total",
        "probes_succeeded": "Probes Succeeded",
        "probes_failed": "Probes Failed",
        "probes_skipped": "Probes Skipped",
        "worst_asr": "Worst ASR",
        "overall_defcon": "Overall DEFCON",
        "hit_count": "Hit Count",
        "coverage": "Coverage",
        "reliability": "Data Reliability",
        "repro_hash": "Repro Hash",
        "kill_paths": "Kill Paths",
        "remediation": "Remediation",
        "pass": "PASS",
        "blocked": "BLOCKED",
        "regression": "Regression Alert",
        "cross_model": "Cross-Model Comparison",
    },
}


def get_text(key: str, lang: str = "zh") -> str:
    """F15: 获取终端输出的 i18n 文本

    :param key: 文本键名
    :param lang: 语言代码 ("zh" 或 "en")
    :returns: 对应语言的文本；未找到返回 key 原文
    """
    import os as _os
    if not lang:
        lang = _os.environ.get("GARAK_PIPELINE_LANG", "zh")
    return TERMINAL_I18N.get(lang, TERMINAL_I18N["zh"]).get(key, key)
