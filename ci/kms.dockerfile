FROM golang:1.26.2-bookworm AS builder
WORKDIR /app

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors

COPY go.work go.work
COPY go.work.sum go.work.sum

ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

RUN GONOSUMDB=github.com/lamassuiot/lamassuiot GOPROXY=direct go work vendor

ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ")&& \
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -mod vendor -o kms backend/cmd/kms/main.go


FROM debian:bookworm-slim AS certs
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

FROM debian:bookworm-slim AS pkcs11-client-proxy
RUN apt-get update && apt-get install -y --no-install-recommends p11-kit

FROM scratch
USER 65532:65532
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/kms /
COPY --from=pkcs11-client-proxy /lib64/ld-linux-x86-64.so.2 /lib64/
COPY --from=pkcs11-client-proxy /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/
COPY --from=pkcs11-client-proxy /usr/lib/x86_64-linux-gnu/libffi.so.8 /usr/lib/x86_64-linux-gnu/
COPY --from=pkcs11-client-proxy /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
CMD ["/kms"]