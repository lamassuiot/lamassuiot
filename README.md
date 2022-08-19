Lamassu IoT
===================
[![Coverage](https://img.shields.io/badge/Coverage-57%25-6d9100)](https://img.shields.io/badge/coverage-57%25-6d9100) [![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

<img src="https://www.lamassu.io/assets/brand/lamassu-brand.png" alt="Lamassu App" title="Lamassu" />

Lamassu is an IoT first PKI designed for industrial scenarios. This is the main code repository for Lamassu IoT where the product logic is being implemented. If you are looking for deployment instructions, please check the [docs](https://www.lamassu.io/docs/) or the project's [Docker Compose repository](https://github.com/lamassuiot/lamassu-compose).

## Running Unit tests

Each service has its own set of unit tests. To run them, you can use the following command:

```bash
#For pretty printing
go install github.com/haveyoudebuggedit/gotestfmt/v2/cmd/gotestfmt@v2.3.1

go test -json -v ./pkg/ca/server/api/ | gotestfmt
go test -json -v ./pkg/dms-manager/server/api/ | gotestfmt
go test -json -v ./pkg/device-manager/server/api/ | gotestfmt
go test -json -v ./pkg/ocsp/server/api/ | gotestfmt
```

Also, it is also posible to run all the test at once and obtain the overall coverage:

```bash	
go test -json -v ./pkg/... -cover -coverprofile=coverage.out -coverpkg=./...
go tool cover -func coverage.out | grep total
```