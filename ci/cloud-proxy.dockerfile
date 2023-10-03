ARG BASE_IMAGE=scratch

FROM golang:1.21-bullseye
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off

RUN now=$(date +'%Y-%m-%d_%T') && \
    CGO_ENABLED=0 go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o cloud-proxy cmd/cloud-proxy/main.go 

FROM ubuntu:20.04
COPY --from=0 /app/cloud-proxy /
CMD ["/cloud-proxy"]
