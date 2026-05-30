# ── Builder ───────────────────────────────────
FROM rust:1-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates pkg-config git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# cache deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs \
    && cargo build --release || true \
    && rm -rf src

# real build
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── Runtime ───────────────────────────────────
# Must match the builder's glibc (rust:1-slim is Debian trixie, glibc 2.39).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-pip \
    && pip install --no-cache-dir --break-system-packages opentimestamps-client \
    && rm -rf /var/lib/apt/lists/* \
    && ots --version
WORKDIR /app
COPY --from=builder /build/target/release/akashi /app/akashi
COPY frontend /app/frontend
ENV STATIC_DIR=/app/frontend DATA_DIR=/data DATABASE_PATH=/data/akashi.db PORT=8080
EXPOSE 8080
CMD ["/app/akashi"]
