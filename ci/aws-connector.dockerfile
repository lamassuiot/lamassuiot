ARG BASE_IMAGE=scratch

FROM golang:1.21-bullseye
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o aws cmd/aws/main.go 

# cannot use scratch becaue of the ca-certificates & hosntame -i command used by the service
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y ca-certificates

COPY --from=0 /app/aws /
CMD ["/aws"]
