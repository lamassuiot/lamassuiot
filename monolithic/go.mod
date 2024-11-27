module github.com/lamassuiot/lamassuiot/monolithic/v3

go 1.22.0

replace (
	github.com/lamassuiot/lamassuiot/backend/v3 => ../backend
	github.com/lamassuiot/lamassuiot/connectors/awsiot/v3 => ../connectors/awsiot
	github.com/lamassuiot/lamassuiot/core/v3 => ../core
	github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3 => ../engines/crypto/aws
	github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3 => ../engines/crypto/filesystem
	github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3 => ../engines/crypto/pkcs11
	github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3 => ../engines/crypto/vaultkv2
	github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3 => ../engines/eventbus/amqp
	github.com/lamassuiot/lamassuiot/engines/eventbus/aws/v3 => ../engines/eventbus/aws
	github.com/lamassuiot/lamassuiot/engines/eventbus/channel/v3 => ../engines/eventbus/channel
	github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3 => ../engines/storage/couchdb
	github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3 => ../engines/storage/postgres
	github.com/lamassuiot/lamassuiot/engines/storage/sqlite/v3 => ../engines/storage/sqlite
	github.com/lamassuiot/lamassuiot/sdk/v3 => ../sdk
	github.com/lamassuiot/lamassuiot/shared/aws/v3 => ../shared/aws
	github.com/lamassuiot/lamassuiot/shared/http/v3 => ../shared/http
	github.com/lamassuiot/lamassuiot/shared/subsystems/v3 => ../shared/subsystems
)

require (
	github.com/fatih/color v1.16.0
	github.com/gin-gonic/gin v1.10.0
	github.com/google/uuid v1.6.0
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/bytedance/sonic v1.12.3 // indirect
	github.com/bytedance/sonic/loader v0.2.1 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/gabriel-vasile/mimetype v1.4.6 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.22.1 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/arch v0.11.0 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
