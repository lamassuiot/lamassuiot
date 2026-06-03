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

# CGO must remain enabled: the monolithic binary imports the PKCS11 crypto
# engine (miekg/pkcs11 uses dlopen via CGO), so a static build is not possible.
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o monolithic \
      monolithic/cmd/development/main.go

# ubuntu:24.04 is required because the binary is glibc-linked (CGO/PKCS11).
# distroless/static or Alpine would fail at runtime when dlopen is invoked.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get --no-install-recommends install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 65532 lamassu && \
    useradd --system --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin lamassu

COPY --from=builder /app/monolithic /monolithic
USER 65532:65532
CMD ["/monolithic"]
