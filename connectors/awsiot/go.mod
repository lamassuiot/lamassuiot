module github.com/lamassuiot/lamassuiot/connectors/awsiot/v3

go 1.22.0

replace (
	github.com/lamassuiot/lamassuiot/backend/v3 => ../../backend
	github.com/lamassuiot/lamassuiot/core/v3 => ../../core
	github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3 => ../../engines/crypto/aws
	github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3 => ../../engines/crypto/filesystem
	github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3 => ../../engines/crypto/pkcs11
	github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3 => ../../engines/crypto/vaultkv2
	github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3 => ../../engines/eventbus/amqp
	github.com/lamassuiot/lamassuiot/engines/eventbus/aws/v3 => ../../engines/eventbus/aws
	github.com/lamassuiot/lamassuiot/engines/eventbus/channel/v3 => ../../engines/eventbus/channel
	github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3 => ../../engines/storage/couchdb
	github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3 => ../../engines/storage/postgres
	github.com/lamassuiot/lamassuiot/engines/storage/sqlite/v3 => ../../engines/storage/sqlite
	github.com/lamassuiot/lamassuiot/sdk/v3 => ../../sdk
	github.com/lamassuiot/lamassuiot/shared/aws/v3 => ../../shared/aws
	github.com/lamassuiot/lamassuiot/shared/http/v3 => ../../shared/http
	github.com/lamassuiot/lamassuiot/shared/subsystems/v3 => ../../shared/subsystems
)

require (
	github.com/ThreeDotsLabs/watermill v1.4.1
	github.com/aws/aws-sdk-go-v2 v1.32.4
	github.com/aws/aws-sdk-go-v2/service/iot v1.59.5
	github.com/aws/aws-sdk-go-v2/service/iotdataplane v1.26.5
	github.com/aws/aws-sdk-go-v2/service/sqs v1.37.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.32.4
	github.com/cloudevents/sdk-go/v2 v2.15.2
	github.com/eclipse/paho.mqtt.golang v1.5.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.28.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.4 // indirect
	github.com/aws/smithy-go v1.22.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/lithammer/shortuuid/v3 v3.0.7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/ugorji/go v1.2.12 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
