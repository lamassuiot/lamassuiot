module github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3

go 1.22.0

replace (
	github.com/lamassuiot/lamassuiot/core/v3 => ../../../core
	github.com/lamassuiot/lamassuiot/shared/aws/v3 => ../../../shared/aws

	github.com/lamassuiot/lamassuiot/shared/http/v3 => ../../../shared/http

	github.com/lamassuiot/lamassuiot/shared/subsystems/v3 => ../../../shared/subsystems
)

require (
	github.com/aws/aws-sdk-go-v2 v1.32.4
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.34.2
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.23 // indirect
	github.com/aws/smithy-go v1.22.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/ugorji/go v1.2.12 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/sys v0.26.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
