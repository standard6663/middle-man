# ---------- builder ----------
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

# 安装编译时依赖（根据需要可以补充）
# 安装系统依赖（确保包含 venv/ensurepip 所需包）
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential gcc g++ git curl patchelf pkg-config libssl-dev libbz2-dev liblzma-dev \
    && rm -rf /var/lib/apt/lists/*



# 复制项目和 requirements
WORKDIR /app
COPY ./requirements.txt /tmp/requirements.txt
COPY . /app
COPY midman /app/midman

# 创建 venv 到稳定路径，然后使用 venv 的 python 来初始化 pip 并安装依赖
RUN python3 -m venv /app/venv && \
    # 确保 venv 自带 pip（如果没有，try ensurepip）
    /app/venv/bin/python -m ensurepip --upgrade || true && \
    /app/venv/bin/python -m pip install --upgrade pip setuptools wheel && \
    /app/venv/bin/pip install -r /tmp/requirements.txt

# 确保 Nuitka 可用（如果你在 requirements 里没有包含 nuitka）
RUN /app/venv/bin/pip install nuitka

# 使用 venv 的 python 来运行 Nuitka（输出到 ./build）
RUN /app/venv/bin/python -m nuitka \
        --standalone \
        --follow-imports \
        --include-module=mitmproxy_linux \
        --jobs=$(nproc) \
        --output-dir=./build \
        ./man.py

# ---------- runtime ----------
FROM ubuntu:24.04

COPY requirements.txt /app/requirements.txt

# 运行时必要依赖
RUN apt-get update && \
    apt-get install -y python3 python3-venv libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /app/venv
RUN /app/venv/bin/python -m pip install --upgrade pip setuptools wheel
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
WORKDIR /app

# 把编译产物复制过来
COPY --from=builder /app/build/man.dist/ /app/

# 拷贝 midman 文件夹
COPY --from=builder /app/midman /app/midman
COPY --from=builder /app/cmdman /app/cmdman
COPY --from=builder /app/mitmproxy /app/mitmproxy
COPY --from=builder /app/scripts /app/scripts
# 创建 .midman 目录以便程序写证书（避免 FileNotFoundError）
RUN mkdir -p /app/.midman && chown root:root /app/.midman

# 如果你想在容器里也提供一个 python venv（可选）
COPY start.py /app/start.py
# 如果复制 venv，请确保二进制兼容（通常构建阶段和运行阶段的 base image 相同就能兼容）

# 默认执行编译好的二进制
CMD ["/app/venv/bin/python", "./start.py"]

