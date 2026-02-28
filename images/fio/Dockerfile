# syntax=docker/dockerfile:1
# ============================================================================
# FIO — Flexible I/O Tester (scratch-based, static binary)
# ============================================================================
#
# Two-stage build:
#   Stage 1 (builder) — Compiles FIO as a fully static binary (musl)
#   Stage 2 (final)   — Scratch-based, single binary, no deps
#
# Supported architectures: linux/amd64, linux/arm64
#
# Build:
#   docker build -t ghcr.io/evariops/fio:v3.41.0 .
#
# Usage:
#   fio /etc/fio/job.fio --output-format=json+
#
# ============================================================================

# ============================================================================
# Stage 1: Build FIO as a static binary
# ============================================================================
FROM docker.io/library/alpine:3.21 AS builder

ARG FIO_VERSION=fio-3.41

WORKDIR /build

# hadolint ignore=DL3018
RUN apk add --no-cache \
      gcc \
      make \
      musl-dev \
      linux-headers \
      libaio-dev \
      zlib-dev \
      zlib-static \
      git

RUN git clone --branch "${FIO_VERSION}" --depth 1 \
        https://github.com/axboe/fio.git /build/fio

WORKDIR /build/fio

RUN ./configure --prefix=/usr/local --disable-native \
    && make -j"$(nproc)" LDFLAGS="-static -laio" CFLAGS="-include linux/falloc.h" \
    && strip --strip-all fio \
    && ./fio --version \
    && printf 'fio:x:1000:1000::/:\n' > /tmp/passwd


# ============================================================================
# Stage 2: Production image (scratch — single static binary)
# ============================================================================
FROM scratch

LABEL org.opencontainers.image.title="FIO — Flexible I/O Tester" \
      org.opencontainers.image.description="Minimal FIO — Flexible I/O Tester, built from source" \
      org.opencontainers.image.vendor="Evariops" \
      org.opencontainers.image.source="https://github.com/Evariops/containers" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /build/fio/fio /usr/local/bin/fio

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/fio"]
