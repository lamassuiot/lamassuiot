module github.com/lamassuiot/lamassuiot/backend/v3

go 1.22.0

replace (
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
	github.com/lamassuiot/lamassuiot/core/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/eventbus/aws/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/eventbus/channel/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/engines/storage/sqlite/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/shared/subsystems/v3 v3.0.0-00010101000000-000000000000
)

require (
	github.com/ThreeDotsLabs/watermill v1.4.1
	github.com/cloudevents/sdk-go/v2 v2.15.2
	github.com/eclipse/paho.mqtt.golang v1.5.0
	github.com/gin-contrib/cors v1.6.0
	github.com/gin-gonic/gin v1.10.0
	github.com/globalsign/est v1.0.6
	github.com/go-playground/validator/v10 v10.22.1
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/jakehl/goid v1.1.0
	github.com/lamassuiot/lamassuiot/sdk/v3 v3.0.0-00010101000000-000000000000
	github.com/lamassuiot/lamassuiot/shared/http/v3 v3.0.0-00010101000000-000000000000
	github.com/robfig/cron/v3 v3.0.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	golang.org/x/crypto v0.28.0
	golang.org/x/text v0.19.0
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.4.0
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/ThreeDotsLabs/watermill-aws v1.0.0 // indirect
	github.com/antonfisher/nested-logrus-formatter v1.3.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.32.4 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.28.3 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.44 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.34.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sns v1.31.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.37.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.4 // indirect
	github.com/aws/smithy-go v1.22.0 // indirect
	github.com/bytedance/sonic v1.12.3 // indirect
	github.com/bytedance/sonic/loader v0.2.1 // indirect
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
	github.com/go-chi/chi v4.1.2+incompatible // indirect
	github.com/go-gormigrate/gormigrate/v2 v2.1.3 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/go-kivik/kivik/v4 v4.3.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-tpm v0.3.2 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/vault/api v1.15.0 // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/lithammer/shortuuid/v3 v3.0.7 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runc v1.1.13 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
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
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	golang.org/x/arch v0.11.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gorm.io/driver/postgres v1.5.9 // indirect
	gorm.io/driver/sqlite v1.5.6 // indirect
	gorm.io/gorm v1.25.12 // indirect
)

require (
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/uuid v1.6.0
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
)

require (
	github.com/ThreeDotsLabs/watermill-amqp/v2 v2.1.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.32.4 // indirect
	github.com/lamassuiot/lamassuiot/shared/aws/v3 v3.0.0-00010101000000-000000000000 // indirect
	github.com/ory/dockertest/v3 v3.11.0 // indirect
	github.com/ugorji/go v1.2.12 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
