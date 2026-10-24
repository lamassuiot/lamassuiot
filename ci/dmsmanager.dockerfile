ARG BUILDER=ghcr.io/lamassuiot/golang-pqc:latest

# Optional pre-vendored dependencies. CI runs `go mod vendor` once and passes
# the result with `--build-context vendor=./vendor`, which replaces this empty
# stage; plain `docker build` falls back to downloading modules.
FROM scratch AS vendor

# Pinned to the runner platform: Go cross-compiles the target architecture
# natively instead of emulating the whole toolchain with QEMU.
FROM --platform=$BUILDPLATFORM ${BUILDER} AS builder
WORKDIR /app
# Instruct BuildKit's Syft scanner to also generate an SBOM attestation for
# this intermediate stage (in addition to the default final-stage scan).
ARG BUILDKIT_SBOM_SCAN_STAGE=true

# Dependencies are resolved before the sources are copied, so this layer is
# reused across code changes, version bumps and target architectures. A
# provided vendor tree is used as is (go build picks vendor/ up automatically);
# otherwise the empty vendor stage is copied and modules are downloaded.
COPY go.mod go.sum ./
COPY --from=vendor / vendor/
RUN if [ -f vendor/modules.txt ]; then \
      echo "Using provided vendor directory"; \
    else \
      rm -rf vendor && go mod download; \
    fi

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors

# Declared after the dependency layer so they do not bust its cache.
ARG TARGETARCH
ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

RUN --mount=type=cache,target=/root/.cache/go-build \
    now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build \
      -tags nopkcs11 \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -o dms-manager \
      backend/cmd/dms-manager/main.go

# gcr.io/distroless/static-debian13:nonroot provides:
#   - a minimal (~2 MB) static-binary runtime with CA certificates included
#     (covers TLS for EST enrollment and outbound calls to CA/Device Manager)
#   - a pre-configured non-root user (UID/GID 65532) with no shell or package manager
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /app/dms-manager /dms-manager
CMD ["/dms-manager"]
