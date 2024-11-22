module github.com/lamassuiot/lamassuiot/v3/connectors/awsiot

go 1.22.0

replace (
	github.com/lamassuiot/lamassuiot/v3/aws => ../../shared/aws
	github.com/lamassuiot/lamassuiot/v3/backend => ../../backend
	github.com/lamassuiot/lamassuiot/v3/core => ../../shared/core
	github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws => ../../engines/crypto/aws
	github.com/lamassuiot/lamassuiot/v3/engines/crypto/filesystem => ../../engines/crypto/filesystem
	github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11 => ../../engines/crypto/pkcs11
	github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2 => ../../engines/crypto/vaultkv2
	github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp => ../../engines/eventbus/amqp
	github.com/lamassuiot/lamassuiot/v3/engines/eventbus/aws => ../../engines/eventbus/aws
	github.com/lamassuiot/lamassuiot/v3/engines/eventbus/channel => ../../engines/eventbus/channel
	github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb => ../../engines/storage/couchdb
	github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres => ../../engines/storage/postgres
	github.com/lamassuiot/lamassuiot/v3/engines/storage/sqlite => ../../engines/storage/sqlite
	github.com/lamassuiot/lamassuiot/v3/http => ../../shared/http
	github.com/lamassuiot/lamassuiot/v3/sdk => ../../shared/sdk
	github.com/lamassuiot/lamassuiot/v3/subsystems => ../../shared/subsystems
)

require (
	github.com/lamassuiot/lamassuiot/v3/core v0.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp v0.0.0-00010101000000-000000000000 // indirect
	github.com/lamassuiot/lamassuiot/v3/engines/eventbus/aws v0.0.0-00010101000000-000000000000 // indirect
	github.com/lamassuiot/lamassuiot/v3/engines/eventbus/channel v0.0.0-00010101000000-000000000000 // indirect
	github.com/lamassuiot/lamassuiot/v3/http v0.0.0-00010101000000-000000000000
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
	github.com/lamassuiot/lamassuiot/v3/aws v0.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/v3/backend v0.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/v3/sdk v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.28.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/ThreeDotsLabs/watermill-amqp/v2 v2.1.3 // indirect
	github.com/ThreeDotsLabs/watermill-aws v1.0.0 // indirect
	github.com/antonfisher/nested-logrus-formatter v1.3.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.28.3 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.44 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sns v1.31.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.4 // indirect
	github.com/aws/smithy-go v1.22.0 // indirect
	github.com/bytedance/sonic v1.12.3 // indirect
	github.com/bytedance/sonic/loader v0.2.1 // indirect
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/containerd/continuity v0.4.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/cli v26.1.4+incompatible // indirect
	github.com/docker/docker v27.1.1+incompatible // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.6 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.10.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.22.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/jakehl/goid v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/lamassuiot/lamassuiot/v3/subsystems v0.0.0-00010101000000-000000000000 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lithammer/shortuuid/v3 v3.0.7 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runc v1.1.13 // indirect
	github.com/ory/dockertest/v3 v3.11.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rabbitmq/amqp091-go v1.10.0 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sony/gobreaker v1.0.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go v1.2.12 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/arch v0.11.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
