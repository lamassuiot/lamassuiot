ARG BASE_IMAGE=scratch

FROM golang:1.18
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN now=$(date +'%Y-%m-%d_%T') && \
    go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o ca cmd/ca/main.go 

#FROM $BASE_IMAGE
#COPY --from=0 /app/ca /
#CMD ["/ca"]