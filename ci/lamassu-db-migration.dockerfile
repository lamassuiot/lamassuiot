FROM golang:1.24.3-bullseye AS builder
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
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=0 go build \
    -ldflags "-X main.version=$VERSION \
    -X main.sha1ver=$SHA1VER \
    -X main.buildTime=$now" \
    -mod vendor \
    -o goose-lamassu \
    engines/storage/postgres/cmd/goose-lamassu/main.go

# Use Alpine for minimal image
FROM alpine:3.19

# Add ca-certificates for HTTPS connections
RUN apk --no-cache add ca-certificates tzdata

ARG USERNAME=migrate
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN addgroup -g "$USER_GID" "$USERNAME" && \
    adduser -D -u "$USER_UID" -G "$USERNAME" "$USERNAME"

USER $USERNAME

WORKDIR /home/$USERNAME

COPY --from=builder /app/goose-lamassu ./goose-lamassu

ENTRYPOINT ["./goose-lamassu"]
