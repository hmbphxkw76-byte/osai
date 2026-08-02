# ============================================================================
# PyRIT-Pipeline Dockerfile — L5 生产级容器化标准 (G-10)
# ============================================================================
# 基于 Python 3.12 slim, 非特权用户, 安全运行
# 构建: docker build -t pyrit-pipeline .
# 运行: docker run --rm --env-file .env pyrit-pipeline
# ============================================================================

FROM python:3.12-slim

# ── 系统依赖 ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl && \
    rm -rf /var/lib/apt/lists/*

# ── 工作目录 ──
WORKDIR /app

# ── 复制 PyRIT 源码 (editable 安装) ──
# 要求构建上下文中有 ../src/PyRIT-1.0.1/ 目录
# 或通过 build-arg 指定路径
COPY ../src/PyRIT-1.0.1 /src/pyrit

# ── 安装 PyRIT ──
RUN cd /src/pyrit && \
    pip install --no-cache-dir --editable ".[all]"

# ── 复制项目文件 ──
COPY pyproject.toml /app/
COPY pipeline/ /app/pipeline/
COPY web_redteam/ /app/web_redteam/
COPY main.py /app/
COPY conftest.py /app/
COPY data/ /app/data/

# ── 安装项目依赖 ──
RUN pip install --no-cache-dir -e ".[dev,reports]"

# ── 非特权用户 ──
RUN useradd -m -u 1000 -s /bin/bash pyrit && \
    mkdir -p /app/outputs/empirical_asr /app/outputs/reports /app/outputs/logs && \
    chown -R pyrit:pyrit /app

USER pyrit

# ── 环境变量 ──
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MALLOC_ARENA_MAX=2 \
    PYRIT_TELEMETRY_IMPLEMENTED=0

# ── 健康检查 ──
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s \
    CMD python -c "import pyrit; print('OK')"

# ── Volume ──
VOLUME ["/app/data", "/app/outputs"]

# ── 默认命令 ──
CMD ["python", "main.py", "--help"]

# ── Labels ──
LABEL org.opencontainers.image.title="PyRIT-Pipeline" \
      org.opencontainers.image.version="5.0.0" \
      org.opencontainers.image.description="ASR-driven AI Red Team pipeline built on PyRIT" \
      org.opencontainers.image.licenses="MIT"
