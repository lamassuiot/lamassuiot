module github.com/lamassuiot/lamassuiot/backend/v3

go 1.22.0

replace github.com/lamassuiot/lamassuiot/core/v3 => ../core

replace github.com/lamassuiot/lamassuiot/sdk/v3 => ../sdk

replace github.com/lamassuiot/lamassuiot/engines/crypto/software/v3 => ../engines/crypto/software

replace github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3 => ../engines/crypto/aws

replace github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3 => ../engines/crypto/filesystem

replace github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3 => ../engines/crypto/pkcs11

replace github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3 => ../engines/crypto/vaultkv2

replace github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3 => ../engines/eventbus/amqp

replace github.com/lamassuiot/lamassuiot/engines/eventbus/aws/v3 => ../engines/eventbus/aws

replace github.com/lamassuiot/lamassuiot/engines/fs-storage/localfs/v3 => ../engines/fs-storage/localfs

replace github.com/lamassuiot/lamassuiot/engines/fs-storage/s3/v3 => ../engines/fs-storage/s3

replace github.com/lamassuiot/lamassuiot/shared/http/v3 => ../shared/http

replace github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3 => ../engines/storage

replace github.com/lamassuiot/lamassuiot/shared/subsystems/v3 => ../shared/subsystems

require (
	github.com/ThreeDotsLabs/watermill v1.4.6
	github.com/cloudevents/sdk-go/v2 v2.14.0
	github.com/eclipse/paho.mqtt.golang v1.5.0
	github.com/gin-contrib/cors v1.6.0
	github.com/gin-gonic/gin v1.10.1
	github.com/globalsign/est v1.0.6
	github.com/go-playground/validator/v10 v10.26.0
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/jakehl/goid v1.1.0
	github.com/kaptinlin/jsonschema v0.2.5
	github.com/mocktools/go-smtp-mock/v2 v2.4.0
	github.com/robertkrimen/otto v0.5.1
	github.com/robfig/cron/v3 v3.0.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	go.mozilla.org/pkcs7 v0.9.0
	golang.org/x/crypto v0.33.0
	golang.org/x/text v0.22.0
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aws/aws-sdk-go-v2/service/s3 v1.80.0 // indirect
	github.com/bytedance/sonic v1.13.2 // indirect
	github.com/bytedance/sonic/loader v0.2.4 // indirect
	github.com/cloudwego/base64x v0.1.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/gin-contrib/sse v1.0.0 // indirect
	github.com/go-chi/chi v4.1.2+incompatible // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.17.1 // indirect
	github.com/google/go-tpm v0.3.2 // indirect
	github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976 // indirect
	github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092 // indirect
	github.com/kaptinlin/go-i18n v0.1.3 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lithammer/shortuuid/v3 v3.0.7 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/arch v0.14.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
)

require (
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/uuid v1.6.0
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
)

require (
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/googleapis/gax-go/v2 v2.12 // indirect
	github.com/spyzhov/ajson v0.9.6
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	gocloud.dev v0.39.0
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/time v0.10.0 // indirect
	google.golang.org/api v0.220.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231212172506-995d672761c0 // indirect
	google.golang.org/grpc v1.71.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
