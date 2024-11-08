package config

type EventBusEngine struct {
	LogLevel LogLevel               `mapstructure:"log_level"`
	Enabled  bool                   `mapstructure:"enabled"`
	Provider EventBusProvider       `mapstructure:"provider"`
	Config   map[string]interface{} `mapstructure:",remain"`
}

type EventBusProvider string

const (
	Amqp      EventBusProvider = "amqp"
	AWSSqsSns EventBusProvider = "aws_sqs_sns"
)
