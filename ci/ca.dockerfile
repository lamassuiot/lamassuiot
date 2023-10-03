FROM golang:1.21-bullseye
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off

RUN now=$(date +'%Y-%m-%d_%T') && \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o ca cmd/ca/v3/main.go 

# Alpine and scartch dont work for this image due to non corss compileable HSM library
FROM ubuntu:18.04
# Dependencies for pkcs11-proxy and opensc for pkcs11-tool
RUN apt-get update && \
    apt-get install -y  git-core make cmake libssl-dev libseccomp-dev opensc

RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake . && make && make install

COPY --from=0 /app/ca /
CMD ["/ca"]
