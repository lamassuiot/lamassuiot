FROM ghcr.io/lamassuiot/golang-pqc:latest
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

RUN go build -mod vendor -o monolithic monolithic/cmd/development/main.go 

FROM ubuntu:26.04

RUN groupadd --system lamassu && \
    useradd --system --gid lamassu --no-create-home --shell /usr/sbin/nologin lamassu


COPY --from=0 /app/monolithic /
USER lamassu
CMD ["/monolithic"]
