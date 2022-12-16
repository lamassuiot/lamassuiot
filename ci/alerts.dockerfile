ARG BASE_IMAGE=scratch

FROM golang:1.19
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \
    CGO_ENABLED=0 go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o alerts cmd/alerts/main.go 

FROM $BASE_IMAGE
COPY pkg/alerts/server/resources/email.html /app/templates/email.html
COPY pkg/alerts/server/resources/config.json /app/templates/config.json
COPY --from=0 /app/alerts /
CMD ["/alerts"]
