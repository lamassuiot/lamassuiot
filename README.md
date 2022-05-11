<a href="https://www.lamassu.io/">
    <img src="assets/logo.png" alt="Lamassu logo" title="Lamassu" align="right" height="80" />
</a>

Lamassu IoT
===================
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

<img src="assets/lamassu-app.png" alt="Lamassu App" title="Lamassu" />


## Running Unit tests

```
#For pretty printing
go install github.com/haveyoudebuggedit/gotestfmt/v2/cmd/gotestfmt@v2.3.1


go test -json -v ./pkg/ca/server/api/service/ | gotestfmt
go test -json -v ./pkg/dms-enroller/server/api/service/ | gotestfmt
go test -json -v ./pkg/device-manager/server/api/service/ | gotestfmt
```