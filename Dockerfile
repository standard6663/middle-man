# 第一阶段：编译环境
FROM ubuntu:24.04 AS builder

# 设置非交互式安装
ENV DEBIAN_FRONTEND=noninteractive

# 安装基础编译依赖
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    gcc \
    g++ \
    curl \
    git \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# 创建Python虚拟环境
COPY ./requirements.txt /tmp/
RUN python3 -m venv /tmp/venv && \
    bash -c "source /tmp/venv/bin/activate && \
    pip install -r /tmp//requirements.txt"

# 复制项目文件到容器
WORKDIR /app
COPY . .

# 执行Nuitka编译（根据CPU核心数调整--jobs参数）
RUN bash -c "source /tmp/venv/bin/activate && \
    python3 -m nuitka \
        --standalone \
        --follow-imports \
        --include-module=mitmproxy_linux \
        --jobs=$(nproc) \
        --output-dir=./build \
        ./start.py"

# 第二阶段：运行时环境
FROM ubuntu:24.04

# 安装运行时依赖
RUN apt-get update && \
    apt-get install -y \
    python3 \
    # 如果包含二进制组件可能需要额外依赖
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 从编译阶段复制生成的可执行文件
COPY --from=builder /app/build/start.dist/ .

# 设置容器启动命令
CMD ["./start.bin"]
