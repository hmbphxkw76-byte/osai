#!/bin/bash
# ============================================================================
# 数据集月度自动更新脚本
# ============================================================================
# 功能:
#   1. 调用 download_datasets.py --update --all 刷新全部远程数据集
#   2. 记录更新日志到 logs/dataset_update.log
#   3. 更新失败时发送通知 (邮件/企业微信, 可选)
#
# 使用方式:
#   手动执行: bash scripts/schedule_monthly_update.sh
#   定时执行 (crontab -e):
#     # 每月1日凌晨3点自动更新
#     0 3 1 * * /path/to/pyrit-pipeline/scripts/schedule_monthly_update.sh
#
# 依赖:
#   - Python 3.10+
#   - PyRIT (pip install pyrit)
#   - 网络连接 (官方源 → 国内镜像兜底)
#
# > 日期: 2026-8-1
# ============================================================================

set -euo pipefail

# 项目根目录 (脚本所在目录的上级)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/dataset_update_$(date +%Y%m%d).log"

mkdir -p "$LOG_DIR"

echo "============================================" | tee -a "$LOG_FILE"
echo "数据集月度更新" | tee -a "$LOG_FILE"
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "  项目: $PROJECT_ROOT" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

cd "$PROJECT_ROOT"

# 执行全量更新 (覆盖已有, 官方源 → 镜像兜底)
echo "" | tee -a "$LOG_FILE"
echo "[1/2] 下载远程数据集 (官方源 → 国内镜像)..." | tee -a "$LOG_FILE"
python scripts/download_datasets.py --update --all 2>&1 | tee -a "$LOG_FILE"

# 检查结果
DOWNLOAD_LOG="data/datasets/_download_log.yaml"
if [ -f "$DOWNLOAD_LOG" ]; then
    echo "" | tee -a "$LOG_FILE"
    echo "[2/2] 更新结果:" | tee -a "$LOG_FILE"
    python -c "
import yaml, sys
with open('$DOWNLOAD_LOG') as f:
    log = yaml.safe_load(f)
print(f'  上次更新: {log.get(\"last_update\", \"N/A\")}')
print(f'  成功: {log.get(\"success\", 0)} 个')
print(f'  失败: {log.get(\"failed\", 0)} 个')
print(f'  镜像使用: {log.get(\"mirror_used\", 0)} 个')
print(f'  总种子: {log.get(\"total_seeds\", 0)}')
if log.get('failed', 0) > 0:
    failed = [d['name'] for d in log.get('downloads', []) if d.get('source') == 'failed']
    if failed:
        print(f'  失败列表: {\", \".join(failed)}')
" 2>&1 | tee -a "$LOG_FILE"
fi

echo "" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
echo "月度更新完成: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "日志: $LOG_FILE" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
