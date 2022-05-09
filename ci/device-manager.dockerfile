FROM golang:1.16
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN CGO_ENABLED=0 go build -mod=vendor -o devices cmd/main.go

FROM alpine:3.14
COPY --from=0 /app/devices /
COPY ./db/migrations /app/db/migrations
CMD ["/devices"]