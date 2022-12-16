.PHONY: all build test lint

gopath=$(shell go env GOPATH)

all: build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: bin/golangci-lint-1.23.8
	./bin/golangci-lint-1.23.8 run ./...

bin/golangci-lint-1.23.8:
	./hack/fetch-golangci-lint.sh
