FROM golang:1.26.2-bookworm AS builder
WORKDIR /app

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

RUN GONOSUMDB=github.com/lamassuiot/lamassuiot GOPROXY=direct go work vendor

RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=0 GOOS=linux \
    go build \
      -tags nopkcs11 \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o dms-manager \
      backend/cmd/dms-manager/main.go

# gcr.io/distroless/static-debian12:nonroot provides:
#   - a minimal (~2 MB) static-binary runtime with CA certificates included
#     (covers TLS for EST enrollment and outbound calls to CA/Device Manager)
#   - a pre-configured non-root user (UID/GID 65532) with no shell or package manager
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/dms-manager /dms-manager
CMD ["/dms-manager"]
