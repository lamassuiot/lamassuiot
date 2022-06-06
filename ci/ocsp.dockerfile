ARG BASE_IMAGE=scratch

FROM golang:1.18
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN CGO_ENABLED=0 go build -mod=vendor -o ocsp cmd/ocsp/main.go

FROM $BASE_IMAGE
COPY --from=0 /app/ocsp /
CMD ["/ocsp"]
