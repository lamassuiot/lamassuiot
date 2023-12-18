FROM golang:1.21-bullseye
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
ENV GOWORK=off 

RUN now=$(date +'%Y-%m-%d_%T') && \ 
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o ca cmd/ca/main.go 

# Alpine and scartch dont work for this image due to non corss compileable HSM library
FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

# Dependencies for pkcs11-proxy and opensc for pkcs11-tool
RUN apt-get update && \
    apt-get install -y  git-core make cmake libssl-dev libseccomp-dev opensc && \
    apt-get clean

RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake . && make && make install

# Clean build artifacts
RUN rm -rf /pkcs11-proxy

COPY --from=0 /app/ca /
CMD ["/ca"]
