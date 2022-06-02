ARG BASE_IMAGE=scratch

FROM golang:1.18
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN CGO_ENABLED=0 go build -mod=vendor -o devices cmd/device-manager/main.go

FROM $BASE_IMAGE
COPY --from=0 /app/devices /
COPY ./db/migrations/device-manager /app/db/migrations
CMD ["/devices"]