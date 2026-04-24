FROM golang:1.26.2-bookworm
WORKDIR /app

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors

COPY go.work go.work
COPY go.work.sum go.work.sum

ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

RUN go work vendor

##############

ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ")&& \
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -mod vendor -o aws connectors/awsiot/cmd/main.go 

# cannot use scratch becaue of the ca-certificates & hosntame -i command used by the service
FROM ubuntu:26.04
RUN apt-get update && apt-get --no-install-recommends install -y ca-certificates \
    && apt-get clean



COPY --from=0 /app/aws /
CMD ["/aws"]
