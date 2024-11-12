package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
)

type AMQPConnection struct {
	cconfig.BasicConnection `mapstructure:",squash"`
	Exchange                string                  `mapstructure:"exchange"`
	Protocol                AMQPProtocol            `mapstructure:"protocol"`
	BasicAuth               AMQPConnectionBasicAuth `mapstructure:"basic_auth"`
	ClientTLSAuth           struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
	} `mapstructure:"client_tls_auth"`
}
type AMQPConnectionBasicAuth struct {
	Enabled  bool             `mapstructure:"enabled"`
	Username string           `mapstructure:"username"`
	Password cconfig.Password `mapstructure:"password"`
}

type AMQPProtocol string

const (
	AMQP  AMQPProtocol = "amqp"
	AMQPS AMQPProtocol = "amqps"
)
