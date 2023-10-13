ARG BASE_IMAGE=scratch

FROM golang:1.21-bullseye
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o alerts cmd/alerts/v3/main.go 

FROM ubuntu:20.04
# COPY pkg/alerts/server/resources/email.html /app/templates/email.html
# COPY pkg/alerts/server/resources/config.json /app/templates/config.json
COPY --from=0 /app/alerts /
CMD ["/alerts"]
