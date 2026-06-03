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

RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    GOOS=linux \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o ca \
      backend/cmd/ca/main.go

# gcr.io/distroless/static-debian12:nonroot provides:
#   - a minimal (~2 MB) static-binary runtime with CA certificates included
#   - a pre-configured non-root user (UID/GID 65532) with no shell or package manager
# gcr.io/distroless/cc-debian12:nonroot provides glibc (required because the
# binary is CGO-linked through the assemblers/kms.go → crypto11 dependency),
# ca-certificates, and a non-root user (UID 65532), with no shell or package
# manager. ~7 MB image.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/ca /ca
CMD ["/ca"]
