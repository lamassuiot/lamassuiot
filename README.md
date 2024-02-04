Lamassu IoT
===================
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/haritzsaiz/a1936540297c6e96589da704a71419be/raw/coverage.json)](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/haritzsaiz/a1936540297c6e96589da704a71419be/raw/coverage.json) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

<img src="https://www.lamassu.io/assets/brand/lamassu-brand.png" alt="Lamassu App" title="Lamassu" />

Lamassu is an IoT first PKI designed for industrial scenarios. This is the main code repository for Lamassu IoT where the product logic is being implemented. If you are looking for deployment instructions, please check the [docs](https://www.lamassu.io/docs/) or the project's [Docker Compose repository](https://github.com/lamassuiot/lamassu-compose).

## Running Unit tests

Each service has its own set of unit tests. To run them, you can use the following commands:
 > **Note:** In order to speed up the process, the tests are run in parallel by default.
 
### Run Test

```bash
START=$(date +%s)
go run gotest.tools/gotestsum@latest --format github-actions ./pkg/... -coverpkg=./... -timeout 600s -coverprofile cover.out
END=$(date +%s)
DIFF=$(( $END - $START ))
echo "It took $DIFF seconds"
```

### Get Coverage Badge
```bash
go tool cover -func cover.out | grep total | awk '{print substr($3, 1, length($3)-1)}' | .github/coverage-badge.sh
```

### Get Coverage HTML Report
```bash
go tool cover -html=cover.out -o cover-report.html
```

### Get Coverage SVG
```bash
go-cover-treemap -coverprofile cover.out > out.svg
```

```bash
go test -json -v  -coverprofile cover.out -coverpkg=./... ./pkg/v3/...
go tool cover -func=cover.out
```

## ARM

CGO_ENABLED=1 GOARCH=arm64 go build -ldflags "-X main.sha1ver=`git rev-parse HEAD` -X main.buildTime=$now" -o ca cmd/ca/main.go 