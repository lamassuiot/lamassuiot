package config

type LogLevel string

const (
	Info  LogLevel = "info"
	Debug LogLevel = "debug"
	Trace LogLevel = "trace"
	None  LogLevel = "none"
)

type HTTPProtocol string

const (
	HTTPS HTTPProtocol = "https"
	HTTP  HTTPProtocol = "http"
)

type HTTPClientAuthMethod string

const (
	JWT    HTTPClientAuthMethod = "jwt"
	MTLS   HTTPClientAuthMethod = "mtls"
	NoAuth HTTPClientAuthMethod = "noauth"
)

type AMQPProtocol string

const (
	AMQP  AMQPProtocol = "amqp"
	AMQPS AMQPProtocol = "amqps"
)

type EventBusProvider string

const (
	Amqp      EventBusProvider = "amqp"
	AWSSqsSns EventBusProvider = "aws_sqs_sns"
)

type StorageProvider string

const (
	Postgres StorageProvider = "postgres"
	CouchDB  StorageProvider = "couch_db"
	DynamoDB StorageProvider = "dynamo_db"
	SQLite   StorageProvider = "sqlite"
)

type AWSAuthenticationMethod string

const (
	Static     AWSAuthenticationMethod = "static"
	Default    AWSAuthenticationMethod = "default"
	AssumeRole AWSAuthenticationMethod = "role"
)

type CryptoEngineProvider string

const (
	HashicorpVaultProvider    CryptoEngineProvider = "hashicorp_vault"
	AWSKMSProvider            CryptoEngineProvider = "aws_kms"
	AWSSecretsManagerProvider CryptoEngineProvider = "aws_secrets_manager"
	FilesystemProvider        CryptoEngineProvider = "filesystem"
	PKCS11Provider            CryptoEngineProvider = "pkcs11"
)
