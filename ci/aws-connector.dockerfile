FROM golang:1.22-bullseye
WORKDIR /app

COPY cmd cmd
COPY pkg pkg
COPY go.mod go.mod
COPY go.sum go.sum

ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

# Since no vendoring, donwload dependencies
RUN go mod tidy

ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ")&& \
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o aws cmd/aws/main.go 

# cannot use scratch becaue of the ca-certificates & hosntame -i command used by the service
FROM ubuntu:20.04
RUN apt-get update && apt-get --no-install-recommends install -y ca-certificates \
    && apt-get clean

ARG USERNAME=lamassu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid "$USER_GID" "$USERNAME" \
    && useradd --uid "$USER_UID" --gid "$USER_GID" -m "$USERNAME" 

USER $USERNAME

COPY --from=0 /app/aws /
CMD ["/aws"]
