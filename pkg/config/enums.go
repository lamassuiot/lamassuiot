package config

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
