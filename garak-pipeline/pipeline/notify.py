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


def _build_slack_message(analysis: dict, run_id: str) -> dict[str, Any]:
    """构建 Slack-compatible Webhook 消息"""
    overall = analysis.get("overall", {})
    defcon = overall.get("defcon", 5)
    worst_asr = overall.get("worst_asr", 0)
    total_probes = overall.get("total_probes", 0)

    # 风险等级颜色
    if defcon <= 2:
        color = "#e74c3c"  # 红
        icon = "🚨"
    elif defcon <= 3:
        color = "#f39c12"  # 橙
        icon = "⚠️"
    else:
        color = "#27ae60"  # 绿
        icon = "✅"

    # Top 5 风险探针
    probe_results = analysis.get("probe_results", {})
    top_probes = sorted(probe_results.items(), key=lambda x: x[1].get("asr", 0), reverse=True)[:5]
    top_fields = []
    for probe, info in top_probes:
        if info.get("asr", 0) > 0:
            top_fields.append({
                "title": probe,
                "value": f"ASR: {info['asr']}% | DEFCON: {info.get('defcon', 5)}",
                "short": True,
            })

    return {
        "attachments": [
            {
                "color": color,
                "fallback": f"{icon} garak-pipeline 扫描完成: DEFCON={defcon}, ASR={worst_asr}%",
                "pretext": f"{icon} garak-pipeline 扫描完成 (run_id={run_id})",
                "fields": [
                    {"title": "Overall DEFCON", "value": str(defcon), "short": True},
                    {"title": "Worst ASR", "value": f"{worst_asr}%", "short": True},
                    {"title": "Total Probes", "value": str(total_probes), "short": True},
                    {"title": "Target Model", "value": analysis.get("target_model", "unknown"), "short": True},
                    *top_fields,
                ],
                "footer": "garak-pipeline",
                "ts": int(__import__("time").time()),
            }
        ]
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
