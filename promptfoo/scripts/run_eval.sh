#!/bin/bash
# ============================================================
# 一键评估脚本
# 用途: 快速运行 promptfoo 评估
# 使用: ./scripts/run_eval.sh [配置文件]
# ============================================================

CONFIG_FILE="${1:-promptfooconfig.yaml}"

echo "========================================="
echo " Promptfoo 评估启动"
echo " 配置文件: $CONFIG_FILE"
echo "========================================="

# 检查 .env 文件
if [ ! -f .env ]; then
    echo "⚠️  未找到 .env 文件，正在从 .env.example 创建..."
    cp .env.example .env
    echo "⚠️  请编辑 .env 文件填入正确的配置"
    exit 1
fi

# 检查 promptfoo 是否安装
if ! command -v promptfoo &> /dev/null; then
    echo "❌ 未找到 promptfoo 命令"
    echo "请运行: npm install -g promptfoo"
    exit 1
fi

# 运行评估
echo ""
echo "🚀 开始评估..."
promptfoo eval -c "$CONFIG_FILE" --output output/results.json

echo ""
echo "📊 生成报告..."
promptfoo view -y output/results.json

echo ""
echo "✅ 评估完成！"
echo "报告路径: output/results.json"
