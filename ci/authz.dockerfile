ARG BUILDER=golang:1.26.2-bookworm
FROM ${BUILDER} AS builder
WORKDIR /app
# Instruct BuildKit's Syft scanner to also generate an SBOM attestation for
# this intermediate stage (in addition to the default final-stage scan).
ARG BUILDKIT_SBOM_SCAN_STAGE=true

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

RUN go work vendor

ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -mod vendor -o authz connectors/authz/cmd/main.go

FROM ubuntu:26.04

RUN groupadd --system lamassu && \
    useradd --system --gid lamassu --no-create-home --shell /usr/sbin/nologin lamassu

COPY --from=builder /app/authz /
COPY --from=builder /app/connectors/authz/cmd/preload /etc/lamassuiot/authz/preload
COPY --from=builder /app/connectors/authz/authz.json /etc/lamassuiot/authz/schemas/authz.json
COPY --from=builder /app/connectors/authz/pki.json /etc/lamassuiot/authz/schemas/pki.json
COPY --from=builder /app/connectors/authz/wfx.json /etc/lamassuiot/authz/schemas/http-wfx.json
USER lamassu
CMD ["/authz"]
