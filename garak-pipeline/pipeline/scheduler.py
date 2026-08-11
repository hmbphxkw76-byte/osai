"""定时调度/持续扫描 — 周期性自动安全评估

功能：
  1. 按 cron 表达式定时触发批量扫描
  2. 结果自动对比上次扫描（retest_diff）
  3. 异常时触发 Webhook 通知
  4. 产物自动归档 + prune 旧批次

用法:
    python -c "from pipeline.scheduler import run_scheduled_scan; run_scheduled_scan('config/web_target_list.yaml')"
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def load_schedule_config(config_path: str = "config/schedule.yaml") -> dict[str, Any]:
    """加载定时调度配置

    :param config_path: 调度配置文件路径
    :returns: 调度配置 dict
    """
    p = Path(config_path)
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_scheduled_scan(
    config_path: str = "config/web_target_list.yaml",
    schedule_cfg: dict[str, Any] | None = None,
    artifacts_dir: str = "outputs",
) -> dict[str, Any]:
    """执行一次定时扫描（可被 cron/schtasks 调用）

    :param config_path: 批量扫描配置文件路径
    :param schedule_cfg: 调度配置（notify_on, profile 等覆盖）
    :param artifacts_dir: 产物根目录
    :returns: 扫描结果 + 对比报告
    """
    schedule_cfg = schedule_cfg or {}
    profile = schedule_cfg.get("profile", "balanced")
    notify_on = schedule_cfg.get("notify_on", [])
    prune_n = schedule_cfg.get("prune_keep", 5)

    logger.info("定时扫描启动: config=%s profile=%s", config_path, profile)

    # 执行批量扫描
    from pipeline.batch_runner import run_batch

    summary = run_batch(config_path)

    # prune 旧批次
    if prune_n and prune_n > 0:
        from pipeline.utils import prune_old_runs

        pruned = prune_old_runs(artifacts_dir, keep=prune_n)
        logger.info("定时扫描: 已清理 %d 个旧批次", pruned)

    # 对比上次扫描（retest diff）
    diff_result = None
    try:
        from pipeline.retest_diff import compute_retest_diff, load_analysis

        targets = summary.get("targets", [])
        for t in targets:
            if t.get("status") != "success":
                continue
            current_run_id = t.get("run_id", "")
            # 查找同目标的历史 run_id（排除当前）
            analysis_dir = Path(artifacts_dir) / "04_analysis"
            historical = sorted(analysis_dir.glob(f"analysis_*{t.get('name', '')}*.json"))
            # 排除当前 run_id
            historical = [h for h in historical if current_run_id not in h.name]
            if historical:
                baseline = load_analysis(
                    historical[-1].stem.replace("analysis_", ""), artifacts_dir,
                )
                current = load_analysis(current_run_id, artifacts_dir)
                if baseline and current:
                    diff = compute_retest_diff(baseline, current)
                    diff_result = diff
                    logger.info(
                        "定时扫描: %s 对比历史结果: ASR回归=%d, 改善=%d",
                        t["name"],
                        diff["summary"]["asr_regressions"],
                        diff["summary"]["asr_improvements"],
                    )
    except Exception as exc:
        logger.debug("定时扫描: retest diff 跳过: %s", exc)

    # 告警评估
    alerts = _evaluate_alerts(summary, diff_result, notify_on)
    if alerts:
        logger.warning("定时扫描: 触发 %d 条告警", len(alerts))
        _send_alerts(alerts, schedule_cfg)

    # 保存调度日志
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": config_path,
        "profile": profile,
        "summary": {
            "total": summary.get("total_targets", 0),
            "succeeded": summary.get("succeeded", 0),
            "failed": summary.get("failed", 0),
        },
        "alerts": alerts,
        "diff": diff_result.get("summary") if diff_result else None,
    }
    log_path = Path(artifacts_dir) / "schedule_log.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logs = []
    if log_path.exists():
        try:
            with open(log_path, encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(log_entry)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(logs[-100:], f, ensure_ascii=False, indent=2)

    return {"summary": summary, "alerts": alerts, "diff": diff_result, "log_path": str(log_path)}


def _evaluate_alerts(
    summary: dict[str, Any],
    diff: dict[str, Any] | None,
    notify_on: list[str],
) -> list[dict[str, str]]:
    """评估是否触发告警条件"""
    alerts = []
    targets = summary.get("targets", [])

    for t in targets:
        if t.get("status") != "success":
            continue

        defcon = t.get("defcon")
        asr = t.get("worst_asr", 0)

        if "defcon_le_2" in notify_on and defcon and defcon <= 2:
            alerts.append({
                "target": t.get("name", "?"),
                "type": "defcon_critical",
                "message": f"DEFCON {defcon} (≤2): {t.get('name')} 安全态势严重",
            })

        if "asr_gt_50" in notify_on and asr > 50:
            alerts.append({
                "target": t.get("name", "?"),
                "type": "asr_high",
                "message": f"ASR {asr}% (>50%): {t.get('name')} 攻击成功率过高",
            })

        if "status_failed" in notify_on and t.get("status") == "failed":
            alerts.append({
                "target": t.get("name", "?"),
                "type": "scan_failed",
                "message": f"扫描失败: {t.get('error', 'unknown')}",
            })

    if diff and "systemic_issues_found" in notify_on:
        regressions = diff.get("summary", {}).get("asr_regressions", 0)
        if regressions > 0:
            alerts.append({
                "target": "global",
                "type": "asr_regression",
                "message": f"ASR 回归: {regressions} 个探针恶化",
            })

    return alerts


def _send_alerts(alerts: list[dict[str, str]], schedule_cfg: dict[str, Any]) -> None:
    """发送告警通知"""
    try:
        from pipeline.notify import send_notification

        # 构造一个伪 analysis dict 供 send_notification 消费
        analysis = {
            "overall": {"defcon": 1},
            "alerts": alerts,
        }
        notify_cfg = schedule_cfg.get("notify")
        send_notification(analysis, "scheduled_scan", notify_cfg)
    except Exception as exc:
        logger.debug("告警通知发送失败: %s", exc)


def register_windows_task(
    config_path: str = "config/web_target_list.yaml",
    cron: str = "0 2 * * 1",
) -> bool:
    """注册 Windows 计划任务（schtasks）

    :param config_path: 批量扫描配置路径
    :param cron: cron 表达式（仅取 周/时/分 用于 schtasks）
    :returns: 是否注册成功
    """
    import subprocess

    parts = cron.split()
    if len(parts) != 5:
        logger.error("无效的 cron 表达式: %s", cron)
        return False

    minute, hour, _day_of_month, _month, day_of_week = parts

    # 构建 schtasks 命令
    # 简化：每周执行 = /SC WEEKLY
    cmd = [
        "schtasks", "/Create", "/TN", "garak_scheduled_scan",
        "/SC", "WEEKLY",  # 简化：每周
        "/D", "MON" if day_of_week == "1" else "FRI" if day_of_week == "5" else "MON",
        "/ST", f"{hour.zfill(2)}:{minute.zfill(2)}",
        "/TR",
        (
            "python -c \"from pipeline.scheduler import run_scheduled_scan; "
            f"run_scheduled_scan('{config_path}')\""
        ),
        "/F",  # 强制覆盖
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info("Windows 计划任务注册成功: garak_scheduled_scan")
            return True
        logger.error("schtasks 注册失败: %s", result.stderr)
        return False
    except Exception as exc:
        logger.error("schtasks 注册异常: %s", exc)
        return False
