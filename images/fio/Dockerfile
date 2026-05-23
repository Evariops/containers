# syntax=docker/dockerfile:1
# ============================================================================
# FIO — Flexible I/O Tester with HTTP Controller (scratch-based, static binaries)
# ============================================================================
#
# Three-stage build:
#   Stage 1 (fio-builder)  — Compiles FIO as a fully static binary (musl)
#   Stage 2 (go-builder)   — Compiles fio-controller as a static Go binary
#   Stage 3 (final)        — Scratch-based, two static binaries, no deps
#
# Supported architectures: linux/amd64, linux/arm64
#
# Build:
#   docker build -t ghcr.io/evariops/fio:v3.42.0 .
#
# Usage (with HTTP controller for graceful stop):
#   docker run --rm -p 8080:8080 ghcr.io/evariops/fio:v3.42.0 \
#     -- /etc/fio/job.fio --output-format=json+
#
#   Then: curl -X POST http://localhost:8080/stop   # graceful stop with results
#         curl http://localhost:8080/status          # check status
#         curl http://localhost:8080/output          # get fio output
#
# ============================================================================

# ============================================================================
# Stage 1: Build FIO as a static binary
# ============================================================================
FROM docker.io/library/alpine:3.23 AS fio-builder

ARG FIO_VERSION=fio-3.42

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
# Stage 2: Build fio-controller (Go static binary)
# ============================================================================
FROM docker.io/library/golang:1.26-alpine AS go-builder

WORKDIR /src

COPY go.mod ./
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /fio-controller ./cmd/fio-controller/

# ============================================================================
# Stage 3: Production image (scratch — static binaries only)
# ============================================================================
FROM scratch

LABEL org.opencontainers.image.title="FIO — Flexible I/O Tester" \
      org.opencontainers.image.description="Minimal FIO with HTTP controller for graceful stop" \
      org.opencontainers.image.vendor="Evariops" \
      org.opencontainers.image.source="https://github.com/Evariops/containers" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=fio-builder /tmp/passwd /etc/passwd
COPY --from=fio-builder /build/fio/fio /usr/local/bin/fio
COPY --from=go-builder /fio-controller /usr/local/bin/fio-controller

EXPOSE 8080

# /tmp is needed for inline job files — use emptyDir or tmpfs in k8s
VOLUME /tmp

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/fio-controller"]
