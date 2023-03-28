ARG API_VERSION="v0.x"
FROM golang:1.19
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
#Cannot run a crosscompile build due to the GO HSM library
RUN now=$(date +'%Y-%m-%d_%T') && vers=$API_VERSION \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.version=$vers -X main.buildTime=$now" -mod=vendor -o ca cmd/ca/main.go 

# Alpine and scartch dont work for this image due to non corss compileable HSM library
FROM ubuntu:22.04
COPY --from=0 /app/ca /
CMD ["/ca"]
