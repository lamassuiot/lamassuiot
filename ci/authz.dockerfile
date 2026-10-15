ARG BUILDER=golang:1.26.8-bookworm

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
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o authz connectors/authz/cmd/main.go

FROM ubuntu:26.04

RUN groupadd --system --gid 65532 lamassu && \
    useradd --system --uid 65532 --gid lamassu --no-create-home --shell /usr/sbin/nologin lamassu

COPY --from=builder /app/authz /
COPY --from=builder /app/connectors/authz/cmd/preload /etc/lamassuiot/authz/preload
COPY --from=builder /app/connectors/authz/authz.json /etc/lamassuiot/authz/schemas/authz.json
COPY --from=builder /app/connectors/authz/pki.json /etc/lamassuiot/authz/schemas/pki.json
COPY --from=builder /app/connectors/authz/wfx.json /etc/lamassuiot/authz/schemas/http-wfx.json
USER lamassu
CMD ["/authz"]
