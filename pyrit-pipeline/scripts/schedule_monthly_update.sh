#!/bin/bash
# ============================================================================
# 数据集月度自动更新脚本 v2 — 下载 → 精简 → 模型感知种子选择
# ============================================================================
# 功能:
#   1. 调用 download_datasets.py --update --all 刷新全部远程数据集
#   2. 调用 curate_seeds.py 执行 6 步精简管线 (去重→均衡→聚类→ASR→模态→Tier)
#   3. 为已知的常用模型生成模型感知种子集
#   4. 记录更新日志
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
#   - scikit-learn, numpy (pip install scikit-learn numpy)
#   - 网络连接 (官方源 → 国内镜像兜底)
#
# > 日期: 2026-8-2
# > 版本: v2 — 新增种子精简 + 模型感知选择
# ============================================================================

set -euo pipefail

# 项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/dataset_update_$(date +%Y%m%d).log"

mkdir -p "$LOG_DIR"

echo "============================================" | tee -a "$LOG_FILE"
echo "数据集月度更新 v2 (下载 + 精简 + 模型感知)" | tee -a "$LOG_FILE"
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "  项目: $PROJECT_ROOT" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

cd "$PROJECT_ROOT"
export PYTHONIOENCODING=utf-8

# ============================================================
# Phase 1: 下载远程数据集 (官方源 → 国内镜像兜底)
# ============================================================
echo "" | tee -a "$LOG_FILE"
echo "[1/3] 下载远程数据集 (官方源 → 国内镜像)..." | tee -a "$LOG_FILE"
python scripts/download_datasets.py --update --all 2>&1 | tee -a "$LOG_FILE"

DOWNLOAD_LOG="data/seed_datasets/benchmarks/_download_log.yaml"
if [ -f "$DOWNLOAD_LOG" ]; then
    echo "" | tee -a "$LOG_FILE"
    echo "  下载结果:" | tee -a "$LOG_FILE"
    python -c "
import yaml
with open('$DOWNLOAD_LOG') as f:
    log = yaml.safe_load(f)
print(f'  成功: {log.get(\"success\", 0)} 个')
print(f'  失败: {log.get(\"failed\", 0)} 个')
print(f'  镜像使用: {log.get(\"mirror_used\", 0)} 个')
print(f'  总种子: {log.get(\"total_seeds\", 0)}')
" 2>&1 | tee -a "$LOG_FILE"
fi

# ============================================================
# Phase 2: 通用种子精简 (6 步管线)
# ============================================================
echo "" | tee -a "$LOG_FILE"
echo "[2/3] 通用种子精简 (去重→均衡→聚类→ASR→模态→Tier)..." | tee -a "$LOG_FILE"
python scripts/curate_seeds.py --target-count 50 2>&1 | tee -a "$LOG_FILE"

# ============================================================
# Phase 3: 模型感知种子选择 (为常用模型生成专属种子集)
# ============================================================
echo "" | tee -a "$LOG_FILE"
echo "[3/3] 模型感知种子选择..." | tee -a "$LOG_FILE"

# 为每个模型生成专属种子集
# 模型列表: (模型名, 模态)
MODELS=(
    "gpt-4o|text"
    "gpt-4|text"
    "gpt-3.5-turbo|text"
    "claude-3-5-sonnet|text"
    "llama-3-8b|text"
    "llama-3.1-405b|text"
    "gpt-4o|multimodal"
    "claude-3-5-sonnet|multimodal"
)

for entry in "${MODELS[@]}"; do
    IFS='|' read -r model modality <<< "$entry"
    echo "  → $model ($modality)" | tee -a "$LOG_FILE"
    python scripts/curate_seeds.py --model "$model" --modality "$modality" --target-count 50 2>&1 | tail -5 | tee -a "$LOG_FILE"
done

# ============================================================
# Phase 4: Probe 运行 (用精简种子跑一轮快速评估, 收集实测 ASR)
# ============================================================
echo "" | tee -a "$LOG_FILE"
echo "[4/5] Probe 运行 (收集种子级实测 ASR)..." | tee -a "$LOG_FILE"
echo "  运行: python main.py --datasets curated_seeds --max-dataset-size 50 --max-attempts 1" | tee -a "$LOG_FILE"
python main.py --datasets curated_seeds --max-dataset-size 50 --max-attempts 1 2>&1 | tail -20 | tee -a "$LOG_FILE"
echo "  Probe 完成, 种子级 ASR 已写入 outputs/empirical_asr/" | tee -a "$LOG_FILE"

# ============================================================
# Phase 5: 二次精简 (用实测 ASR 重新排序种子)
# ============================================================
echo "" | tee -a "$LOG_FILE"
echo "[5/5] 二次精简 (用种子级实测 ASR 重新排序)..." | tee -a "$LOG_FILE"

# 重新为每个模型精简 (此时 curate_seeds.py 会自动加载种子级实测 ASR)
for entry in "${MODELS[@]}"; do
    IFS='|' read -r model modality <<< "$entry"
    echo "  → $model (二次精简)" | tee -a "$LOG_FILE"
    python scripts/curate_seeds.py --model "$model" --modality "$modality" --target-count 50 2>&1 | tail -5 | tee -a "$LOG_FILE"
done

echo "" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
echo "月度更新完成 v3 (下载→精简→模型感知→Probe→二次精简): $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "  下载: data/seed_datasets/benchmarks/"
echo "  通用精简: data/seed_datasets/benchmarks/curated_seeds.prompt"
echo "  模型专属: data/seed_datasets/benchmarks/curated_seeds_*.prompt"
echo "  实测 ASR: outputs/empirical_asr/seed_level_*.json"
echo "  日志: $LOG_FILE" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"
