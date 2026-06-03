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


RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=0 GOOS=linux \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o goose-lamassu \
      engines/storage/postgres/cmd/goose-lamassu/main.go

# gcr.io/distroless/static-debian12:nonroot provides:
#   - a minimal (~2 MB) static-binary runtime with CA certificates and tzdata included
#     (covers TLS connections to PostgreSQL and time zone handling)
#   - a pre-configured non-root user (UID/GID 65532) with no shell or package manager
# Usage: docker run <image> "<pg-conn-string>" <command> [args...]
#   e.g. docker run <image> "host=localhost user=postgres dbname=ca sslmode=disable" up
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/goose-lamassu /goose-lamassu
ENTRYPOINT ["/goose-lamassu"]
