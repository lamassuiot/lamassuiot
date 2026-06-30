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

RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=1 GOOS=linux \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o kms \
      backend/cmd/kms/main.go

FROM debian:bookworm-slim AS pkcs11-client-proxy
RUN apt-get update && apt-get install -y --no-install-recommends p11-kit

# gcr.io/distroless/cc-debian13:nonroot provides glibc + libgcc (required for
# the CGO-linked binary), CA certificates, and a non-root user (UID 65532).
# p11-kit-client.so and libffi are copied from the pkcs11-client-proxy stage
# since they are not included in the distroless image.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=pkcs11-client-proxy /usr/lib/x86_64-linux-gnu/libffi.so.8 /usr/lib/x86_64-linux-gnu/
COPY --from=pkcs11-client-proxy /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
COPY --from=builder /app/kms /kms
CMD ["/kms"]

