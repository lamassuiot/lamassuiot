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

# CGO must remain enabled: miekg/pkcs11 uses dlopen via CGO to load the PKCS11
# module at runtime, so a purely static CGO_ENABLED=0 build is not possible.
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o kms \
      backend/cmd/kms/main.go

# Runtime stage: distroless/cc provides glibc (required by the CGO-linked
# binary) and ca-certificates, without including pkcs11-proxy.
# Users who need pkcs11-proxy should deploy it as a sidecar and mount
# libpkcs11-proxy.so via a shared volume, or use the kms.dockerfile variant.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/kms /kms
CMD ["/kms"]
