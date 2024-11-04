package config

import cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"

type VAconfig struct {
	Logs   BaseConfigLogging `mapstructure:"logs"`
	Server HttpServer        `mapstructure:"server"`

	CAClient CAClient `mapstructure:"ca_client"`
}

type CAClient struct {
	cconfig.HTTPClient `mapstructure:",squash"`
}
