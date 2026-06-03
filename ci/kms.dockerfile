FROM golang:1.26.2-bookworm AS builder
WORKDIR /app

# Copy workspace manifests first so the vendor step is cached independently
# from version-only rebuilds (ARG SHA1VER/VERSION come later).
COPY go.work go.work
COPY go.work.sum go.work.sum

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors
COPY vendor vendor

# Build args are declared after vendoring so that a version-only change does
# not bust the vendor cache layer.
ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

RUN GONOSUMDB=github.com/lamassuiot/lamassuiot GOPROXY=direct go work vendor

# CGO must remain enabled: miekg/pkcs11 uses dlopen via CGO to load the PKCS11
# module at runtime, so a purely static CGO_ENABLED=0 build is not possible.
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o kms \
      backend/cmd/kms/main.go

# Build pkcs11-proxy from source in a disposable stage so that no build
# toolchain (~64 MB) leaks into the final runtime image.
# -DCMAKE_POLICY_VERSION_MINIMUM=3.5 lets CMake 4.x configure pkcs11-proxy's
# old CMakeLists.txt, and -Wno-error=incompatible-pointer-types keeps GCC 15
# pointer type diagnostics as warnings instead of build-stopping errors.
FROM ubuntu:24.04 AS pkcs11-proxy-builder
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get --no-install-recommends install -y \
      ca-certificates git-core libc6-dev gcc make cmake libssl-dev libseccomp-dev && \
    rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_C_FLAGS="-Wno-error=incompatible-pointer-types" . && \
    make && make install

# Runtime stage: ubuntu is required because the KMS binary is CGO-linked against
# glibc (miekg/pkcs11 → dlopen). distroless/static (no glibc) and Alpine (musl)
# are ABI-incompatible with a glibc-compiled binary.
# libssl3 and libseccomp2 are already present in the ubuntu:24.04 base image.
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get --no-install-recommends install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy only the pkcs11-proxy runtime artifacts from the disposable build stage.
COPY --from=pkcs11-proxy-builder /usr/local/lib/libpkcs11-proxy.so* /usr/local/lib/
COPY --from=pkcs11-proxy-builder /usr/local/bin/pkcs11-daemon /usr/local/bin/pkcs11-daemon
RUN ldconfig

RUN groupadd --system --gid 65532 lamassu && \
    useradd --system --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin lamassu

COPY --from=builder /app/kms /kms
USER 65532:65532
CMD ["/kms"]
