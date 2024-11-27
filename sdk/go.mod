module github.com/lamassuiot/lamassuiot/sdk/v3

go 1.22.0

replace (
	github.com/lamassuiot/lamassuiot/core/v3 => ../core
	github.com/lamassuiot/lamassuiot/shared/http/v3 => ../shared/http
)

require (
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/crypto v0.28.0
	golang.org/x/oauth2 v0.23.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/ugorji/go v1.2.12 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/sys v0.26.0 // indirect
)
