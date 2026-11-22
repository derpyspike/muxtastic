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
        tini \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user. UID/GID 1000 matches the usual first host user, so the
# bind-mounted ./data and ./logs are writable without extra setup; override
# with --build-arg MUX_UID=... / MUX_GID=... (or `user:` in compose).
# `dialout` grants access to USB serial nodes such as /dev/ttyUSB0.
ARG MUX_UID=1000
ARG MUX_GID=1000
RUN groupadd -g "${MUX_GID}" mux \
    && useradd -u "${MUX_UID}" -g mux -G dialout -d /app -s /usr/sbin/nologin mux

WORKDIR /app
COPY --from=builder /build/target/release/muxtastic /usr/local/bin/muxtastic
COPY configs ./configs
# The tracked example is the fallback when no config is mounted.
RUN cp configs/config.example.yaml configs/config.yaml \
    && mkdir -p logs data \
    && chown -R mux:mux /app

USER mux

EXPOSE 4404 8080

# Healthy while something is listening on the mux port. This reads the kernel's
# socket table instead of connecting, so it never shows up as a mux client.
# Set MUXTASHTIC_HEALTH_PORT when server.port is not 4404.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD grep -qE ":$(printf '%04X' "${MUXTASHTIC_HEALTH_PORT:-4404}") [0-9A-F]+:0000 0A " \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["muxtastic", "--config", "configs/config.yaml"]
