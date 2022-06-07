ARG BASE_IMAGE=scratch

FROM golang:1.18
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN CGO_ENABLED=0 go build -mod=vendor -o enroller cmd/dms-enroller/main.go

FROM $BASE_IMAGE
COPY --from=0 /app/enroller /
CMD ["/enroller"]
