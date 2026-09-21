ARG BUILDER=golang:1.26.2-bookworm
# Pinned to the runner platform: the binary is cross-compiled with an
# installed arm64 toolchain instead of emulating the whole build with QEMU.
FROM --platform=$BUILDPLATFORM ${BUILDER} AS builder
WORKDIR /app
# Instruct BuildKit's Syft scanner to also generate an SBOM attestation for
# this intermediate stage (in addition to the default final-stage scan).
ARG BUILDKIT_SBOM_SCAN_STAGE=true
ARG TARGETARCH

# go.work/go.work.sum rarely change — keep as an early cache layer.
COPY go.work go.work
COPY go.work.sum go.work.sum

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors

RUN GONOSUMDB=github.com/lamassuiot/lamassuiot GOPROXY=direct go work vendor

# Build args are declared after vendoring so that a version-only change does
# not bust the vendor cache layer.
ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

# Install the arm64 cross toolchain only when targeting arm64; CGO_ENABLED is
# required so miekg/pkcs11 and crypto11 compile and link correctly.
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      apt-get update && \
      apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross; \
      rm -rf /var/lib/apt/lists/*; \
    fi

RUN if [ "$TARGETARCH" = "arm64" ]; then \
      export CC=aarch64-linux-gnu-gcc; \
    fi && \
    now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=1 GOOS=linux GOARCH=$TARGETARCH \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o kms \
      backend/cmd/kms/main.go

FROM debian:bookworm-slim AS pkcs11-client-proxy
# Instruct BuildKit's Syft scanner to also generate an SBOM attestation for
# this intermediate stage (in addition to the default final-stage scan).
ARG BUILDKIT_SBOM_SCAN_STAGE=true
# This stage is NOT pinned to $BUILDPLATFORM: it must run for the target
# architecture so that apt installs matching p11-kit libraries.
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends p11-kit && \
    case "$TARGETARCH" in \
      amd64) TRIPLET=x86_64-linux-gnu ;; \
      arm64) TRIPLET=aarch64-linux-gnu ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    mkdir -p /out/pkcs11 && \
    cp -L /usr/lib/${TRIPLET}/libffi.so.8 /out/ && \
    cp -L /usr/lib/${TRIPLET}/pkcs11/p11-kit-client.so /out/pkcs11/

# gcr.io/distroless/cc-debian13:nonroot provides glibc + libgcc (required for
# the CGO-linked binary), CA certificates, and a non-root user (UID 65532).
# p11-kit-client.so and libffi are copied from the pkcs11-client-proxy stage
# since they are not included in the distroless image.
# libffi.so.8 lives in /usr/lib: the plain lib dir is part of the default
# loader search path on every architecture. p11-kit-client.so keeps the
# /usr/lib/x86_64-linux-gnu/pkcs11 path on all architectures because it is
# loaded by explicit module_path (documented default), never via the loader.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=pkcs11-client-proxy /out/libffi.so.8 /usr/lib/libffi.so.8
COPY --from=pkcs11-client-proxy /out/pkcs11/p11-kit-client.so /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
COPY --from=builder /app/kms /kms
CMD ["/kms"]

