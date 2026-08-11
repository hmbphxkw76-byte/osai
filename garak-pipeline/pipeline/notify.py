"""P3-4: 通知/告警集成 — Webhook 推送扫描结果摘要

支持 Slack-compatible Webhook 和通用 JSON Webhook。
当扫描结果 DEFCON ≤ 3 或 ASR ≥ 50% 时自动触发告警推送。

配置方式（config/*.yaml 或 .env）:
    notify:
      webhook_url: "https://hooks.slack.com/services/xxx"  # 或 .env NOTIFICATION_WEBHOOK_URL
      min_severity: 3       # DEFCON ≤ 3 时触发
      high_asr_threshold: 50  # ASR ≥ 50% 时触发
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_webhook_url(notify_cfg: dict | None = None) -> str | None:
    """从配置或环境变量获取 Webhook URL"""
    if notify_cfg and notify_cfg.get("webhook_url"):
        return notify_cfg["webhook_url"]
    try:
        from pipeline.env import get_env
        return get_env("NOTIFICATION_WEBHOOK_URL", "")
    except Exception:
        return None


def _defcon_emoji(defcon: int) -> str:
    """N5: DEFCON emoji 映射"""
    return {1: "🔴", 2: "🟠", 3: "🟡", 4: "🟢", 5: "✅"}.get(defcon, "⚪")


def _build_slack_message(analysis: dict, run_id: str) -> dict[str, Any]:
    """构建 Slack-compatible Webhook 消息"""
    overall = analysis.get("overall", {})
    defcon = overall.get("defcon", 5)
    worst_asr = overall.get("worst_asr", 0)
    total_probes = overall.get("probes_total", 0)
    probes_evaluated = overall.get("probes_evaluated", 0)
    hit_count = analysis.get("hitlog", {}).get("hit_count", 0)

    # 风险等级颜色 + emoji
    if defcon <= 2:
        color = "#e74c3c"  # 红
        icon = "🚨"
    elif defcon <= 3:
        color = "#f39c12"  # 橙
        icon = "⚠️"
    else:
        color = "#27ae60"  # 绿
        icon = "✅"

    # N5: DEFCON emoji
    defcon_emoji = _defcon_emoji(defcon)

    # Top 5 风险探针
    probe_results = analysis.get("probe_results", {})
    top_probes = sorted(probe_results.items(), key=lambda x: x[1].get("asr", 0), reverse=True)[:5]
    top_fields = []
    for probe, info in top_probes:
        if info.get("asr", 0) > 0:
            probe_emoji = _defcon_emoji(info.get("defcon", 5))
            top_fields.append({
                "title": f"{probe_emoji} {probe}",
                "value": f"ASR: {info['asr']}% | DEFCON: {info.get('defcon', 5)}",
                "short": True,
            })

    # N5: 执行摘要文本
    if defcon <= 2:
        summary_text = f"{icon} {defcon_emoji} CRITICAL — 目标模型存在严重安全漏洞，需立即修复"
    elif defcon <= 3:
        summary_text = f"{icon} {defcon_emoji} WARNING — 存在可利用的攻击面"
    else:
        summary_text = f"{icon} {defcon_emoji} PASS — 目标模型安全状况良好"

    # N5: Kill paths 摘要
    kill_paths = analysis.get("kill_paths", [])
    kill_path_text = "无"
    if kill_paths:
        kill_path_text = f"{len(kill_paths)} 条攻击链路被识别"

    return {
        "text": summary_text,
        "attachments": [
            {
                "color": color,
                "fallback": f"{icon} garak-pipeline 扫描完成: DEFCON={defcon}, ASR={worst_asr}%",
                "pretext": f"{icon} garak-pipeline 红队扫描完成 (run_id={run_id})",
                "fields": [
                    {"title": f"{defcon_emoji} Overall DEFCON", "value": str(defcon), "short": True},
                    {"title": "Worst ASR", "value": f"{worst_asr}%", "short": True},
                    {"title": "Probes", "value": f"{probes_evaluated}/{total_probes}", "short": True},
                    {"title": "Hits", "value": str(hit_count), "short": True},
                    {"title": "Kill Paths", "value": kill_path_text, "short": True},
                    {"title": "Target Model", "value": analysis.get("target_model", "unknown"), "short": True},
                    *top_fields,
                ],
                "footer": "garak-pipeline red team",
                "ts": int(__import__("time").time()),
            }
        ]
    }


def _build_teams_message(analysis: dict, run_id: str) -> dict[str, Any]:
    """F10: 构建 Microsoft Teams Adaptive Card 消息"""
    overall = analysis.get("overall", {})
    defcon = overall.get("defcon", 5)
    worst_asr = overall.get("worst_asr", 0)
    probes_evaluated = overall.get("probes_evaluated", 0)
    total_probes = overall.get("probes_total", 0)
    hit_count = analysis.get("hitlog", {}).get("hit_count", 0)
    target_model = analysis.get("target_model", "unknown")
    defcon_emoji = _defcon_emoji(defcon)

    if defcon <= 2:
        severity = "CRITICAL"
        accent = "attention"  # red
    elif defcon <= 3:
        severity = "WARNING"
        accent = "warning"  # orange
    else:
        severity = "PASS"
        accent = "good"  # green

    # Top 3 probes
    probe_results = analysis.get("probe_results", {})
    top3 = sorted(probe_results.items(), key=lambda x: x[1].get("asr", 0), reverse=True)[:3]
    facts = [
        {"name": "Overall DEFCON", "value": f"{defcon_emoji} {defcon}"},
        {"name": "Worst ASR", "value": f"{worst_asr}%"},
        {"name": "Probes", "value": f"{probes_evaluated}/{total_probes}"},
        {"name": "Hits", "value": str(hit_count)},
        {"name": "Target Model", "value": target_model},
    ]
    for probe, info in top3:
        if info.get("asr", 0) > 0:
            facts.append({"name": f"  {probe}", "value": f"ASR {info['asr']}% | DEFCON {info.get('defcon', 5)}"})

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [{
                    "type": "TextBlock",
                    "text": f"garak-pipeline Red Team Scan — {severity}",
                    "size": "Large",
                    "weight": "Bolder",
                    "color": accent,
                }, {
                    "type": "TextBlock",
                    "text": f"run_id: {run_id}",
                    "isSubtle": True,
                    "spacing": "Small",
                }, {
                    "type": "FactSet",
                    "facts": facts,
                    "spacing": "Medium",
                }],
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "View Report",
                    "url": f"outputs/05_export/report_{run_id}.html",
                }],
            },
        }],
    }


def send_notification(
    analysis: dict,
    run_id: str,
    notify_cfg: dict | None = None,
) -> bool:
    """发送扫描结果通知

    :param analysis: Stage4 分析结果
    :param run_id: 运行标识
    :param notify_cfg: 通知配置（webhook_url/min_severity/high_asr_threshold）
    :returns: True 如果发送成功或跳过；False 如果发送失败
    """
    overall = analysis.get("overall", {})
    defcon = overall.get("defcon", 5)
    worst_asr = overall.get("worst_asr", 0)

    min_severity = (notify_cfg or {}).get("min_severity", 3)
    high_asr_threshold = (notify_cfg or {}).get("high_asr_threshold", 50)

    # 判断是否需要发送通知
    should_notify = defcon <= min_severity or worst_asr >= high_asr_threshold
    if not should_notify:
        logger.debug("通知跳过: DEFCON=%d (阈值≤%d), ASR=%.1f%% (阈值≥%d%%)", defcon, min_severity, worst_asr, high_asr_threshold)
        return True

    webhook_url = _get_webhook_url(notify_cfg)
    if not webhook_url:
        logger.debug("通知跳过: 未配置 Webhook URL")
        return True

    try:
        import requests

        message = _build_slack_message(analysis, run_id)
        # F10: Teams Webhook 适配
        if "outlook.office.com" in webhook_url or "teams.microsoft.com" in webhook_url:
            message = _build_teams_message(analysis, run_id)
        resp = requests.post(webhook_url, json=message, timeout=10)
        if resp.status_code < 300:
            logger.info("通知已发送到 Webhook (DEFCON=%d, ASR=%.1f%%)", defcon, worst_asr)
            return True
        else:
            logger.warning("Webhook 响应异常: HTTP %d", resp.status_code)
            return False
    except ImportError:
        logger.debug("requests 不可用，跳过 Webhook 通知")
        return True
    except Exception as exc:
        logger.warning("Webhook 通知发送失败: %s", exc)
        return False
