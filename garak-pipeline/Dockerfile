# R7: Dockerfile — garak-pipeline 容器化
# 多阶段构建：基础镜像 → 依赖安装 → 应用代码
#
# F13: 版本锁定 — 所有依赖版本固化，确保可复现构建
#
# 构建: docker build -t garak-pipeline:latest .
# 运行 CLI: docker run --rm --env-file .env garak-pipeline:latest --mode standard
# 运行 API: docker run --rm -p 8765:8765 --env-file .env garak-pipeline:latest api

FROM python:3.11-slim-bookworm AS base

# F13: 固定基础镜像 digest（可复现构建）
# python:3.11-slim-bookworm@sha256:... (uncomment and pin for production)

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
# F13: 锁定 pip 版本并使用 --no-cache-dir 确保可复现
RUN python -m pip install --no-cache-dir --upgrade pip==24.2 \
    && pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium --with-deps \
    && playwright install-deps

# F13: 锁定 garak 源码 commit（如果从源码安装）
# 如果使用 submodule，这里会读取子模块的固定 commit
ARG GARAK_SOURCE=package
COPY . .
RUN if [ "$GARAK_SOURCE" = "submodule" ] && [ -d "src/garak-0.15.1" ]; then \
        pip install --no-cache-dir -e src/garak-0.15.1/; \
    elif [ "$GARAK_SOURCE" = "package" ]; then \
        pip install --no-cache-dir garak==0.15.1; \
    fi

# 创建输出目录
RUN mkdir -p /app/outputs /app/config /app/data /app/sessions

# 环境变量默认值
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GARAK_PIPELINE_ARTIFACTS_DIR=/app/outputs

# 入口：支持 CLI 和 API 两种模式
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
