# R7: Dockerfile — garak-pipeline 容器化
# 多阶段构建：基础镜像 → 依赖安装 → 应用代码
#
# 构建: docker build -t garak-pipeline:latest .
# 运行 CLI: docker run --rm --env-file .env garak-pipeline:latest --mode standard
# 运行 API: docker run --rm -p 8765:8765 --env-file .env garak-pipeline:latest api

FROM python:3.11-slim AS base

# 系统依赖：Playwright 需要 libglib, libnss3 等；weasyprint 需要 GTK/Pango
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxcb1 \
    libxkbcommon0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 依赖安装（利用 Docker 层缓存：requirements.txt 单独一层）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium --with-deps \
    && playwright install-deps

# 应用代码
COPY . .

# 创建输出目录
RUN mkdir -p /app/outputs /app/config /app/data /app/sessions

# 环境变量默认值
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GARAK_PIPELINE_ARTIFACTS_DIR=/app/outputs

# 入口：支持 CLI 和 API 两种模式
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
