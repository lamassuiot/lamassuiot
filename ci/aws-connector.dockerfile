ARG BASE_IMAGE=scratch

FROM golang:1.21-bullseye
WORKDIR /app

COPY .git .git
COPY cmd cmd
COPY pkg pkg
COPY vendor vendor
COPY go.mod go.mod
COPY go.sum go.sum

ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o aws cmd/aws/main.go 

# cannot use scratch becaue of the ca-certificates & hosntame -i command used by the service
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y ca-certificates --no-install-recommends \
    && apt-get clean

ARG USERNAME=lamassu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

USER $USERNAME

COPY --from=0 /app/aws /
CMD ["/aws"]
