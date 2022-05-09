FROM golang:1.16
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN CGO_ENABLED=0 go build -mod=vendor -o ca cmd/main.go

FROM alpine:3.14
COPY --from=0 /app/ca /
COPY ./db/migrations /app/db/migrations
CMD ["/ca"]
