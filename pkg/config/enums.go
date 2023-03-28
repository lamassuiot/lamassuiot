package config

type LogLevel string

const (
	Info  LogLevel = "info"
	Debug LogLevel = "debug"
	Trace LogLevel = "trace"
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
	NoAuth HTTPClientAuthMethod = "no-auth"
)

type AMQPProtocol string

const (
	AMQP  AMQPProtocol = "amqp"
	AMQPS AMQPProtocol = "amqps"
)

type StorageProvider string

const (
	CouchDB StorageProvider = "couch_db"
)
