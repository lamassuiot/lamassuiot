package config

type HTTPClientAuthMethod string

const (
	JWT    HTTPClientAuthMethod = "jwt"
	MTLS   HTTPClientAuthMethod = "mtls"
	NoAuth HTTPClientAuthMethod = "noauth"
)

type EventBusProvider string

const (
	Amqp      EventBusProvider = "amqp"
	AWSSqsSns EventBusProvider = "aws_sqs_sns"
)
