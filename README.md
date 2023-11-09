Lamassu IoT
===================
[![Coverage](https://img.shields.io/badge/Coverage-57%25-6d9100)](https://img.shields.io/badge/coverage-57%25-6d9100) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

<img src="https://www.lamassu.io/assets/brand/lamassu-brand.png" alt="Lamassu App" title="Lamassu" />

Lamassu is an IoT first PKI designed for industrial scenarios. This is the main code repository for Lamassu IoT where the product logic is being implemented. If you are looking for deployment instructions, please check the [docs](https://www.lamassu.io/docs/) or the project's [Docker Compose repository](https://github.com/lamassuiot/lamassu-compose).

## Running Unit tests

Each service has its own set of unit tests. To run them, you can use the following commands:
 > **Note:** In order to speed up the process, the tests are run in parallel by default.
 
#For pretty printing
go install github.com/haveyoudebuggedit/gotestfmt/v2/cmd/gotestfmt@v2.3.1

```bash
START=$(date +%s)
go test -coverprofile cover.out -coverpkg=./... ./pkg/v3/... | awk '{if ($1 != "?") print $5; else print "0.0";}' | sed 's/\%//g' | awk '{s+=$1} END {printf "%.2f\n", s}' | bash .github/coverage-badge.sh
END=$(date +%s)
DIFF=$(( $END - $START ))
echo "It took $DIFF seconds"

go-cover-treemap -coverprofile cover.out > out.svg
go tool cover -html=cover.out -o cover-report.html
go tool cover -func cover.out  | grep total
```

```bash
go test -json -v  -coverprofile cover.out -coverpkg=./... ./pkg/v3/...
go tool cover -func=cover.out
```

## ARM

CGO_ENABLED=1 GOARCH=arm64 go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -mod=vendor -o ca cmd/ca/v3/main.go 