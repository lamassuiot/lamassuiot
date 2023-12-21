FROM golang:1.21-bullseye
WORKDIR /app

COPY .git .git
COPY cmd cmd
COPY pkg pkg
COPY go.mod go.mod
COPY go.sum go.sum

ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

# Since no vendoring, donwload dependencies
RUN go mod tidy

ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \ 
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o ca cmd/ca/main.go 

# Alpine and scartch dont work for this image due to non corss compileable HSM library
FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

# Dependencies for pkcs11-proxy and opensc for pkcs11-tool
RUN apt-get update && \
    apt-get --no-install-recommends install -y git-core libc6-dev gcc make cmake libssl-dev libseccomp-dev opensc ca-certificates && \
    apt-get clean

RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake . && make && make install

# Clean build artifacts
RUN rm -rf /pkcs11-proxy
# Clean compilation dependencies
RUN apt-get remove -y git-core libc6-dev gcc make cmake libssl-dev libseccomp-dev && \
    apt-get autoremove -y && \
    apt-get clean

ARG USERNAME=lamassu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid "$USER_GID" "$USERNAME" \
    && useradd --uid "$USER_UID" --gid "$USER_GID" -m "$USERNAME" 

USER $USERNAME

COPY --from=0 /app/ca /
CMD ["/ca"]
