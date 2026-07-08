#!/bin/bash
# ============================================================
# 一键红队测试脚本
# 用途: 快速运行 promptfoo 红队测试
# 使用: ./scripts/run_redteam.sh [配置文件]
# ============================================================

CONFIG_FILE="${1:-promptfooconfig.redteam.yaml}"

echo "========================================="
echo " Promptfoo 红队测试启动"
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

# 运行红队测试
echo ""
echo "🔴 开始红队测试..."
promptfoo redteam run -c "$CONFIG_FILE"

echo ""
echo "📊 生成红队报告..."
promptfoo redteam report

echo ""
echo "✅ 红队测试完成！"
echo "查看报告: promptfoo redteam report"
