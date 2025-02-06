FROM golang:1.22.1-bullseye
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

RUN go work vendor

RUN go build -mod vendor -o monolithic monolithic/cmd/development/main.go 

FROM ubuntu:20.04
COPY --from=0 /app/monolithic /
CMD ["/monolithic"]
