# ── Stage 1: build shhgit ─────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS go-builder
RUN go install github.com/eth0izzle/shhgit@latest

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

# system tools for trufflehog download and git scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# trufflehog binary (multi-arch)
ARG TRUFFLEHOG_VERSION=3.78.0
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) TAG="linux_amd64" ;; \
      arm64) TAG="linux_arm64" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL \
      "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${TAG}.tar.gz" \
      | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# shhgit binary from build stage
COPY --from=go-builder /go/bin/shhgit /usr/local/bin/shhgit

# Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application files
COPY . .

# shhgit signature config
RUN mkdir -p /root/.shhgit && cp config.yaml /root/.shhgit/config.yaml

# Railway injects $PORT; default to 8000 for local Docker runs
ENV PORT=8000
EXPOSE 8000

CMD ["python", "api.py"]
