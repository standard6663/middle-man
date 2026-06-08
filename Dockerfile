# =============================================================================
# Stage 1: Builder - 安装依赖
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /app

# 安装编译依赖（部分 Python 包需要编译 C 扩展）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    libpcap-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# 克隆项目（如果使用容器镜像构建，需提前 COPY）
# COPY . .

# 初始化 cmdman 子模块（如果项目是通过 git clone 拉取的）
RUN git submodule update --init --recursive || true

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Runtime - 最终镜像
# =============================================================================
FROM python:3.12-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    libpcap0.8 \
    tshark \
    wireshark-common \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash midman

# 从 builder 复制已安装的 Python 包
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 复制项目文件
COPY --chown=midman:midman . .

# 设置 PYTHONPATH，确保能找到 midman / mitmproxy / cmdman
ENV PYTHONPATH="/app:${PYTHONPATH}"

# 环境变量默认值
ENV PIPE_PATH="/tmp/.midman.pipe"
ENV MIDMAN_CONF="/app/.midman"
ENV MIDMAN_SECRET="midman_secret"
ENV MIDMAN_LOG_PATH="/tmp/midman.log"
ENV MIDMAN_PORT="12039"

# 以非 root 用户运行
USER midman

# 默认启动 start.py（会启动 Reporter + Manager，Manager 再启动 mitmdump 子进程）
ENTRYPOINT ["python", "./start.py"]
