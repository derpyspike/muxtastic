FROM rust:1-slim-bookworm AS builder

# rustls' aws-lc-rs backend builds native code.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        gcc \
        libc6-dev \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p muxtastic

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        netcat-openbsd \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r mux && useradd -r -g mux -d /app -s /usr/sbin/nologin mux

WORKDIR /app
COPY --from=builder /build/target/release/muxtastic /usr/local/bin/muxtastic
COPY configs ./configs
# The tracked example is the fallback when no config is mounted.
RUN cp configs/config.example.yaml configs/config.yaml \
    && mkdir -p logs data \
    && chown -R mux:mux /app

USER mux

EXPOSE 4404 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD sh -c 'nc -z 127.0.0.1 "${MUXTASHTIC_HEALTH_PORT:-4404}" \
        || nc -z 127.0.0.1 "${MUXTASHTIC_WEB_PORT:-8080}"'

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["muxtastic", "--config", "configs/config.yaml"]
