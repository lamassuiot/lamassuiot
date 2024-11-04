package config

type EventBusProvider string

const (
	Amqp      EventBusProvider = "amqp"
	AWSSqsSns EventBusProvider = "aws_sqs_sns"
)
