ARG BASE_IMAGE=scratch

FROM golang:1.21-bullseye
WORKDIR /app

COPY .git .git
COPY cmd cmd
COPY pkg pkg
COPY go.mod go.mod
COPY go.sum go.sum

# Since no vendoring, donwload dependencies
RUN go mod tidy

ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -o dms-manager cmd/ra/main.go 

FROM ubuntu:20.04

ARG USERNAME=lamassu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid "$USER_GID" "$USERNAME" \
    && useradd --uid "$USER_UID" --gid "$USER_GID" -m "$USERNAME" 

USER $USERNAME

COPY --from=0 /app/dms-manager /
CMD ["/dms-manager"]
