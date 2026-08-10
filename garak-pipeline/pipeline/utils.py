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
        print(f"{prefix} ▶ {short_name:<40}{ttp_tag} ...", flush=True)
    elif status == "ok":
        if asr is not None and asr > 0:
            hit_tag = f"ASR={asr:.0f}% 💥"
        else:
            hit_tag = "ASR=0%"
        print(f"{prefix} ✓ {short_name:<40}{ttp_tag} {hit_tag}", flush=True)
        # 命中 loot 预览
        if hit_preview:
            preview = hit_preview[:80] + ("..." if len(hit_preview) > 80 else "")
            print(f"         └─ [LOOT] {preview}", flush=True)
    elif status == "fail":
        print(f"{prefix} ✗ {short_name:<40}{ttp_tag} FAILED", flush=True)
    elif status == "skip":
        print(f"{prefix} ⏭ {short_name:<40}{ttp_tag} skipped (checkpoint)", flush=True)


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

        # 数据可靠性
        dq = analysis.get("data_quality", {})
        rel = dq.get("reliability", "normal")
        if rel != "normal":
            print(f"╠{'═' * W}╣")
            print(f"║ {'⚠️  数据可靠性: {rel}':<{W}}║")
            null_rate = dq.get("overall_null_rate", 0)
            print(f"║   null 输出率: {null_rate:.1f}%{'':<{W - 14 - len(f'{null_rate:.1f}%')}}║")

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
