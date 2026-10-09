# Multi-Stage Production Dockerfile for Sentinels
# Stage 1: Build & Dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# Stage 2: Runtime Image
FROM python:3.11-slim AS runtime

WORKDIR /workspace

# Install Git (required for repo cloning) and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from builder
COPY --from=builder /install /usr/local

# Copy source code and scripts
COPY src/ /workspace/src/
COPY pyproject.toml /workspace/

# Install editable package link
RUN pip install --no-cache-dir -e .

# Create reports volume directory
RUN mkdir -p /workspace/reports

ENV PYTHONUNBUFFERED=1
ENV LLM_PROVIDER=ollama
ENV OLLAMA_HOST=http://host.docker.internal:11434

ENTRYPOINT ["sentinels"]
CMD ["--help"]
