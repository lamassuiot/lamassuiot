ARG BASE_IMAGE=scratch

FROM golang:1.18
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN CGO_ENABLED=0 go build -mod=vendor -o ca cmd/ca/main.go

FROM $BASE_IMAGE
COPY --from=0 /app/ca /
COPY ./db/migrations/ca /app/db/migrations
CMD ["/ca"]
